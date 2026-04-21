#!/usr/bin/env python3
"""Session and pending-approval state for mcpd."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List

try:
    from schema_utils import ensure_int, ensure_non_empty_str
except ModuleNotFoundError:  # pragma: no cover - package import fallback
    from .schema_utils import ensure_int, ensure_non_empty_str

DEFAULT_SESSION_TTL_MS = 30 * 60 * 1000
MAX_SESSION_TTL_MS = 24 * 60 * 60 * 1000


@dataclass(frozen=True)
class PeerIdentity:
    pid: int
    uid: int
    gid: int


@dataclass(frozen=True)
class AgentBinding:
    peer: PeerIdentity
    binding_hash: int
    binding_epoch: int
    catalog_epoch: int = 0


_approval_lock = threading.Lock()
_pending_approvals: Dict[int, Dict[str, Any]] = {}
_session_lock = threading.Lock()
_sessions: Dict[str, Dict[str, Any]] = {}
_next_session_epoch = 0


def compute_binding_hash(peer: PeerIdentity, session_id: str) -> int:
    digest = hashlib.blake2b(
        f"{peer.uid}:{peer.gid}:{peer.pid}:{session_id}".encode("utf-8"),
        digest_size=8,
    ).digest()
    return int.from_bytes(digest, byteorder="big", signed=False)


def _next_binding_epoch() -> int:
    global _next_session_epoch
    with _session_lock:
        _next_session_epoch += 1
        return _next_session_epoch


def cleanup_expired_sessions() -> None:
    now_ms = int(time.time() * 1000)
    expired_ids: List[str] = []
    with _session_lock:
        for session_id, session in list(_sessions.items()):
            expires_at_ms = session.get("expires_at_ms", 0)
            if isinstance(expires_at_ms, int) and expires_at_ms > now_ms:
                continue
            expired_ids.append(session_id)
            _sessions.pop(session_id, None)
    if not expired_ids:
        return
    expired_set = set(expired_ids)
    with _approval_lock:
        for ticket_id, pending in list(_pending_approvals.items()):
            if pending.get("session_id") in expired_set:
                _pending_approvals.pop(ticket_id, None)


def normalize_session_ttl_ms(raw: Any) -> int:
    ttl_ms = ensure_int("ttl_ms", raw if raw not in ("", None) else DEFAULT_SESSION_TTL_MS)
    if ttl_ms <= 0:
        raise ValueError("ttl_ms must be positive")
    return min(ttl_ms, MAX_SESSION_TTL_MS)


def _new_agent_id(peer: PeerIdentity) -> str:
    return f"ag_{peer.uid:x}_{peer.pid:x}_{secrets.token_hex(4)}"


def open_session(
    peer: PeerIdentity,
    client_name: str,
    ttl_ms: int,
    catalog_epoch: int = 0,
) -> Dict[str, Any]:
    cleanup_expired_sessions()
    session_id = secrets.token_hex(16)
    agent_id = _new_agent_id(peer)
    binding_epoch = _next_binding_epoch()
    binding_hash = compute_binding_hash(peer, session_id)
    expires_at_ms = int(time.time() * 1000) + ttl_ms
    session = {
        "session_id": session_id,
        "agent_id": agent_id,
        "client_name": client_name,
        "peer": peer,
        "binding_hash": binding_hash,
        "binding_epoch": binding_epoch,
        "catalog_epoch": catalog_epoch,
        "expires_at_ms": expires_at_ms,
        "created_at_ms": int(time.time() * 1000),
        "ttl_ms": ttl_ms,
    }
    with _session_lock:
        _sessions[session_id] = session
    return {
        "status": "ok",
        "session_id": session_id,
        "agent_id": agent_id,
        "client_name": client_name,
        "expires_at_ms": expires_at_ms,
        "ttl_ms": ttl_ms,
        "catalog_epoch": catalog_epoch,
    }


def resolve_session(session_id: str, peer: PeerIdentity) -> Dict[str, Any]:
    cleanup_expired_sessions()
    with _session_lock:
        session = _sessions.get(session_id)
    if session is None:
        raise ValueError("session not found or expired")
    session_peer = session.get("peer")
    if session_peer != peer:
        raise ValueError("session is bound to a different peer identity")
    return session


def session_binding(session: Dict[str, Any]) -> AgentBinding:
    peer = session.get("peer")
    if not isinstance(peer, PeerIdentity):
        raise ValueError("session is missing peer identity")
    binding_hash = ensure_int("binding_hash", session.get("binding_hash", 0))
    binding_epoch = ensure_int("binding_epoch", session.get("binding_epoch", 0))
    if binding_hash <= 0 or binding_epoch <= 0:
        raise ValueError("session is missing binding metadata")
    catalog_epoch = ensure_int("catalog_epoch", session.get("catalog_epoch", 0))
    return AgentBinding(
        peer=peer,
        binding_hash=binding_hash,
        binding_epoch=binding_epoch,
        catalog_epoch=catalog_epoch,
    )


def remember_pending_approval(
    *,
    ticket_id: int,
    session_id: str,
    req_id: int,
    agent_id: str,
    binding_hash: int,
    binding_epoch: int,
    app_id: str,
    tool_id: int,
    payload: Any,
    tool_hash: str,
) -> None:
    with _approval_lock:
        _pending_approvals[ticket_id] = {
            "session_id": session_id,
            "req": {
                "req_id": req_id,
                "agent_id": agent_id,
                "binding_hash": binding_hash,
                "binding_epoch": binding_epoch,
                "app_id": app_id,
                "tool_id": tool_id,
                "payload": payload,
                "tool_hash": tool_hash,
            },
        }


def take_pending_approval(ticket_id: int) -> Dict[str, Any]:
    with _approval_lock:
        pending = _pending_approvals.pop(ticket_id, None)
    if pending is None:
        raise ValueError(f"pending approval not found: {ticket_id}")
    return pending


def peek_pending_approval(ticket_id: int) -> Dict[str, Any]:
    with _approval_lock:
        pending = _pending_approvals.get(ticket_id)
    if pending is None:
        raise ValueError(f"pending approval not found: {ticket_id}")
    return pending


def put_pending_approval(ticket_id: int, pending: Dict[str, Any]) -> None:
    with _approval_lock:
        _pending_approvals[ticket_id] = pending


def validate_pending_approval_req(pending: Dict[str, Any]) -> Dict[str, Any]:
    req = pending.get("req", {})
    if not isinstance(req, dict):
        raise ValueError("pending approval request is invalid")
    return {
        "req_id": ensure_int("req_id", req.get("req_id", 0)),
        "agent_id": ensure_non_empty_str("agent_id", req.get("agent_id", "")),
        "binding_hash": ensure_int("binding_hash", req.get("binding_hash", 0)),
        "binding_epoch": ensure_int("binding_epoch", req.get("binding_epoch", 0)),
        "app_id": ensure_non_empty_str("app_id", req.get("app_id", "")),
        "tool_id": ensure_int("tool_id", req.get("tool_id", 0)),
        "payload": req.get("payload", {}),
        "tool_hash": req.get("tool_hash", ""),
    }
