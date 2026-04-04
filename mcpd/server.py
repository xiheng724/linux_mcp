#!/usr/bin/env python3
"""Kernel MCP data-plane daemon over Unix Domain Socket."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import signal
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from manifest_loader import DEFAULT_MANIFEST_DIR, AppManifest, ToolManifest, load_all_manifests
    from netlink_client import KernelMcpNetlinkClient
    from public_catalog import list_apps_public, list_tools_public
    from risk import RISK_TAG_TO_FLAG
    from rpc_framing import recv_frame, send_frame
    from schema_utils import ensure_int, ensure_non_empty_str, validate_payload
    from session_store import (
        AgentBinding,
        PeerIdentity,
        normalize_session_ttl_ms,
        open_session,
        peek_pending_approval,
        put_pending_approval,
        remember_pending_approval,
        resolve_session,
        session_binding,
        take_pending_approval,
        validate_pending_approval_req,
    )
except ModuleNotFoundError:  # pragma: no cover - package import fallback
    from .manifest_loader import DEFAULT_MANIFEST_DIR, AppManifest, ToolManifest, load_all_manifests
    from .netlink_client import KernelMcpNetlinkClient
    from .public_catalog import list_apps_public, list_tools_public
    from .risk import RISK_TAG_TO_FLAG
    from .rpc_framing import recv_frame, send_frame
    from .schema_utils import ensure_int, ensure_non_empty_str, validate_payload
    from .session_store import (
        AgentBinding,
        PeerIdentity,
        normalize_session_ttl_ms,
        open_session,
        peek_pending_approval,
        put_pending_approval,
        remember_pending_approval,
        resolve_session,
        session_binding,
        take_pending_approval,
        validate_pending_approval_req,
    )

SOCK_PATH = "/tmp/mcpd.sock"
MAX_MSG_SIZE = 16 * 1024 * 1024
DEFAULT_APPROVAL_TTL_MS = 5 * 60 * 1000
DEFAULT_SESSION_TTL_MS = 30 * 60 * 1000
APPROVAL_DECISION_MAP = {
    "approve": 1,
    "deny": 2,
    "revoke": 3,
}
LOGGER = logging.getLogger("mcpd")
HASH_RE = re.compile(r"^[0-9a-fA-F]{8}$")
APPROVAL_REQUIRED_FLAGS = (
    RISK_TAG_TO_FLAG["filesystem_delete"]
    | RISK_TAG_TO_FLAG["device_control"]
    | RISK_TAG_TO_FLAG["external_network"]
    | RISK_TAG_TO_FLAG["privileged"]
    | RISK_TAG_TO_FLAG["irreversible"]
)

_stop_event = threading.Event()
_agents_lock = threading.Lock()
_registry_lock = threading.RLock()
_userspace_state_lock = threading.Lock()
_registered_agents: Dict[str, "AgentBinding"] = {}
_agent_bindings: Dict[str, "AgentBinding"] = {}
_app_registry: Dict[str, AppManifest] = {}
_tool_registry: Dict[int, ToolManifest] = {}
_kernel_client: KernelMcpNetlinkClient | None = None
_manifest_reload_lock = threading.Lock()
_manifest_signature = ""
_userspace_next_ticket_id = 0
_userspace_approval_tickets: Dict[int, Dict[str, Any]] = {}
_userspace_agent_stats: Dict[str, Dict[str, Any]] = {}


def _sock_path() -> str:
    return os.getenv("MCPD_SOCK_PATH", SOCK_PATH)


def _experiment_mode() -> str:
    return os.getenv("MCPD_EXPERIMENT_MODE", "normal").strip().lower() or "normal"


def _normalized_experiment_mode() -> str:
    mode = _experiment_mode()
    if mode == "kernel_control_plane":
        return "normal"
    if mode == "no_kernel":
        return "forwarder_only"
    return mode


def _attack_profiles() -> set[str]:
    raw = os.getenv("MCPD_ATTACK_PROFILE", "").strip().lower()
    if not raw:
        return set()
    return {part.strip() for part in raw.split(",") if part.strip()}


def _kernel_mode_enabled() -> bool:
    return _normalized_experiment_mode() in {"normal", "no_complete_report"}


def _uses_userspace_semantic_plane() -> bool:
    return _normalized_experiment_mode() == "userspace_semantic_plane"


def _uses_forwarder_only() -> bool:
    return _normalized_experiment_mode() == "forwarder_only"


def _userspace_attack_enabled(*profiles: str) -> bool:
    if not _uses_userspace_semantic_plane():
        return False
    active = _attack_profiles()
    if not active:
        return False
    return "compromised_userspace" in active or any(profile in active for profile in profiles)


def _compromised_binding_for_peer(peer: PeerIdentity) -> AgentBinding:
    return AgentBinding(
        peer=peer,
        binding_hash=0xD1CE000000000000 | (peer.pid & 0xFFFF),
        binding_epoch=0xC0DE0000 | (peer.uid & 0xFFFF),
    )


def _tool_complete_enabled() -> bool:
    return _normalized_experiment_mode() == "normal"


def _timing_enabled() -> bool:
    raw = os.getenv("MCPD_TRACE_TIMING", "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _get_kernel_client() -> KernelMcpNetlinkClient:
    if _kernel_client is None:
        raise RuntimeError("kernel netlink client is not initialized")
    return _kernel_client


def _userspace_purge_expired_tickets(now_ms: int | None = None) -> None:
    current_ms = int(time.time() * 1000) if now_ms is None else now_ms
    with _userspace_state_lock:
        expired = [
            ticket_id
            for ticket_id, ticket in _userspace_approval_tickets.items()
            if int(ticket.get("expires_at_ms", 0)) <= current_ms
        ]
        for ticket_id in expired:
            _userspace_approval_tickets.pop(ticket_id, None)


def _userspace_agent_record(agent_id: str) -> Dict[str, Any]:
    with _userspace_state_lock:
        record = _userspace_agent_stats.get(agent_id)
        if record is None:
            record = {
                "allow_count": 0,
                "deny_count": 0,
                "defer_count": 0,
                "completed_ok_count": 0,
                "completed_err_count": 0,
                "last_exec_ms": 0,
                "last_status": 0,
                "last_reason": "",
            }
            _userspace_agent_stats[agent_id] = record
        return record


def _userspace_issue_approval_ticket(
    *,
    agent_id: str,
    binding_hash: int,
    binding_epoch: int,
    tool_id: int,
    req_id: int,
    tool_hash: str,
    reason: str,
    ttl_ms: int = DEFAULT_APPROVAL_TTL_MS,
) -> int:
    global _userspace_next_ticket_id
    now_ms = int(time.time() * 1000)
    _userspace_purge_expired_tickets(now_ms)
    with _userspace_state_lock:
        _userspace_next_ticket_id += 1
        ticket_id = _userspace_next_ticket_id
        _userspace_approval_tickets[ticket_id] = {
            "ticket_id": ticket_id,
            "agent_id": agent_id,
            "binding_hash": binding_hash,
            "binding_epoch": binding_epoch,
            "tool_id": tool_id,
            "req_id": req_id,
            "tool_hash": tool_hash,
            "decided": False,
            "approved": False,
            "consumed": False,
            "reason": reason,
            "expires_at_ms": now_ms + ttl_ms,
            "approver": "",
        }
    return ticket_id


def _userspace_approval_decide(
    *,
    ticket_id: int,
    decision: str,
    agent_id: str,
    binding_hash: int,
    binding_epoch: int,
    approver: str,
    reason: str,
    ttl_ms: int,
) -> None:
    now_ms = int(time.time() * 1000)
    _userspace_purge_expired_tickets(now_ms)
    normalized = decision.strip().lower()
    with _userspace_state_lock:
        ticket = _userspace_approval_tickets.get(ticket_id)
        if ticket is None:
            raise ValueError(f"pending approval not found: {ticket_id}")
        if bool(ticket.get("consumed", False)):
            raise ValueError("approval ticket already consumed")
        if (
            str(ticket.get("agent_id", "")) != agent_id
            or int(ticket.get("binding_hash", 0)) != binding_hash
            or int(ticket.get("binding_epoch", 0)) != binding_epoch
        ):
            raise ValueError("approval ticket binding mismatch")
        if normalized == "approve":
            approved = True
        elif normalized in {"deny", "revoke"}:
            approved = False
        else:
            raise ValueError("decision must be one of: approve, deny, revoke")
        ticket["decided"] = True
        ticket["approved"] = approved
        ticket["reason"] = reason
        ticket["approver"] = approver
        ticket["expires_at_ms"] = now_ms + ttl_ms


def _userspace_consume_approval_ticket(
    *,
    ticket_id: int,
    agent_id: str,
    binding_hash: int,
    binding_epoch: int,
    tool_id: int,
    req_id: int,
    tool_hash: str,
) -> Tuple[bool, str]:
    if _userspace_attack_enabled("tamper_approval", "tamper_policy"):
        return (True, "approval_bypassed_by_userspace_attack")
    now_ms = int(time.time() * 1000)
    _userspace_purge_expired_tickets(now_ms)
    with _userspace_state_lock:
        ticket = _userspace_approval_tickets.get(ticket_id)
        if ticket is None:
            return (False, "approval_ticket_unknown")
        if bool(ticket.get("consumed", False)):
            return (False, "approval_ticket_consumed")
        if (
            str(ticket.get("agent_id", "")) != agent_id
            or int(ticket.get("tool_id", 0)) != tool_id
            or int(ticket.get("req_id", 0)) != req_id
        ):
            return (False, "approval_ticket_scope_mismatch")
        if (
            int(ticket.get("binding_hash", 0)) != binding_hash
            or int(ticket.get("binding_epoch", 0)) != binding_epoch
        ):
            return (False, "approval_ticket_binding_mismatch")
        expected_hash = str(ticket.get("tool_hash", ""))
        if expected_hash and expected_hash != tool_hash:
            return (False, "approval_ticket_hash_mismatch")
        if not bool(ticket.get("decided", False)):
            return (False, "approval_pending")
        if not bool(ticket.get("approved", False)):
            ticket["consumed"] = True
            return (False, "approval_denied")
        ticket["consumed"] = True
        return (True, "allow_approved")


def _userspace_record_decision(agent_id: str, decision: str, reason: str) -> None:
    record = _userspace_agent_record(agent_id)
    with _userspace_state_lock:
        if decision == "ALLOW":
            record["allow_count"] += 1
        elif decision == "DENY":
            record["deny_count"] += 1
        else:
            record["defer_count"] += 1
        record["last_reason"] = reason


def _userspace_record_complete(agent_id: str, status_code: int, exec_ms: int) -> None:
    record = _userspace_agent_record(agent_id)
    with _userspace_state_lock:
        if status_code == 0:
            record["completed_ok_count"] += 1
        else:
            record["completed_err_count"] += 1
        record["last_exec_ms"] = exec_ms
        record["last_status"] = status_code


def _register_tool_with_kernel(tool: ToolManifest) -> None:
    if not _kernel_mode_enabled():
        return
    client = _get_kernel_client()
    client.register_tool(
        tool_id=tool.tool_id,
        name=tool.name,
        risk_flags=tool.risk_flags,
        tool_hash=tool.manifest_hash,
    )


def _compute_manifest_signature() -> str:
    digest = hashlib.sha256()
    paths = sorted(DEFAULT_MANIFEST_DIR.glob("*.json"))
    if not paths:
        raise ValueError(f"no manifests found in {DEFAULT_MANIFEST_DIR}")
    for path in paths:
        digest.update(str(path.relative_to(DEFAULT_MANIFEST_DIR)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _load_runtime_registry() -> str:
    apps = load_all_manifests()
    app_registry: Dict[str, AppManifest] = {}
    tool_registry: Dict[int, ToolManifest] = {}
    client = _get_kernel_client() if _kernel_mode_enabled() else None

    if client is not None:
        client.reset_tools()
    if not _kernel_mode_enabled():
        with _userspace_state_lock:
            _userspace_approval_tickets.clear()
            _userspace_agent_stats.clear()

    for app in apps:
        app_registry[app.app_id] = app
        for tool in app.tools:
            _register_tool_with_kernel(tool)
            tool_registry[tool.tool_id] = tool

    with _registry_lock:
        _app_registry.clear()
        _app_registry.update(app_registry)
        _tool_registry.clear()
        _tool_registry.update(tool_registry)

    LOGGER.info(
        "loaded manifests apps=%d tools=%d app_ids=%s",
        len(app_registry),
        len(tool_registry),
        sorted(app_registry.keys()),
    )
    return _compute_manifest_signature()


def _ensure_runtime_registry_current(*, force: bool = False) -> None:
    global _manifest_signature

    with _manifest_reload_lock:
        current_signature = _compute_manifest_signature()
        if not force and current_signature == _manifest_signature:
            return
        loaded_signature = _load_runtime_registry()
        _manifest_signature = loaded_signature
        LOGGER.info("manifest catalog refreshed signature=%s", loaded_signature[:12])


def _read_peer_identity(conn: socket.socket) -> PeerIdentity:
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("SO_PEERCRED not available on this platform")
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return PeerIdentity(pid=pid, uid=uid, gid=gid)


def _bind_agent_identity(agent_id: str, binding: AgentBinding) -> None:
    with _agents_lock:
        bound = _agent_bindings.get(agent_id)
        if bound is not None and bound != binding:
            raise ValueError("agent_id is bound to a different peer identity")
        _agent_bindings[agent_id] = binding


def _ensure_agent_registered(agent_id: str, binding: AgentBinding) -> None:
    _bind_agent_identity(agent_id, binding)
    if not _kernel_mode_enabled():
        with _agents_lock:
            _registered_agents[agent_id] = binding
        return
    with _agents_lock:
        registered_peer = _registered_agents.get(agent_id)
        if registered_peer is not None:
            if registered_peer != binding:
                raise ValueError("agent_id is registered to a different peer identity")
            return

    client = _get_kernel_client()
    try:
        client.register_agent(
            agent_id,
            pid=binding.peer.pid,
            uid=binding.peer.uid,
            binding_hash=binding.binding_hash,
            binding_epoch=binding.binding_epoch,
        )
    except RuntimeError as exc:
        if "Invalid argument" in str(exc):
            raise RuntimeError(
                "kernel agent ABI mismatch: rebuild and reload kernel_mcp from this repo"
            ) from exc
        raise
    LOGGER.info(
        "agent registered via netlink: %s pid=%d uid=%d binding_hash=%016x epoch=%d",
        agent_id,
        binding.peer.pid,
        binding.peer.uid,
        binding.binding_hash,
        binding.binding_epoch,
    )

    with _agents_lock:
        _registered_agents[agent_id] = binding


def _kernel_arbitrate(
    req_id: int,
    agent_id: str,
    binding_hash: int,
    binding_epoch: int,
    tool_id: int,
    tool_hash: str,
    ticket_id: int = 0,
) -> Tuple[str, str, int]:
    if _uses_forwarder_only():
        return ("ALLOW", "allow_forwarder_only", 0)
    if _uses_userspace_semantic_plane():
        if _userspace_attack_enabled("tamper_policy"):
            decision = ("ALLOW", "allow_compromised_userspace_policy", ticket_id)
            _userspace_record_decision(agent_id, decision[0], decision[1])
            return decision
        with _registry_lock:
            tool = _tool_registry.get(tool_id)
        if tool is None:
            raise ValueError(f"unsupported tool_id: {tool_id}")
        with _agents_lock:
            registered_peer = _registered_agents.get(agent_id)
        if registered_peer is None and _userspace_attack_enabled("tamper_session"):
            decision = ("ALLOW", "allow_tampered_unknown_agent", ticket_id)
        elif registered_peer is None:
            decision = ("DENY", "deny_unknown_agent", 0)
        elif (
            registered_peer.binding_hash != binding_hash
            or registered_peer.binding_epoch != binding_epoch
        ) and not _userspace_attack_enabled("tamper_session"):
            decision = ("DENY", "binding_mismatch", 0)
        elif (
            tool.manifest_hash
            and tool_hash
            and tool.manifest_hash != tool_hash
            and not _userspace_attack_enabled("tamper_metadata")
        ):
            decision = ("DENY", "hash_mismatch", 0)
        elif tool.risk_flags & APPROVAL_REQUIRED_FLAGS:
            if ticket_id > 0:
                approved, reason = _userspace_consume_approval_ticket(
                    ticket_id=ticket_id,
                    agent_id=agent_id,
                    binding_hash=binding_hash,
                    binding_epoch=binding_epoch,
                    tool_id=tool_id,
                    req_id=req_id,
                    tool_hash=tool_hash,
                )
                decision = ("ALLOW", reason, ticket_id) if approved else ("DEFER", reason, ticket_id)
            else:
                issued_ticket_id = _userspace_issue_approval_ticket(
                    agent_id=agent_id,
                    binding_hash=binding_hash,
                    binding_epoch=binding_epoch,
                    tool_id=tool_id,
                    req_id=req_id,
                    tool_hash=tool_hash,
                    reason="require_approval",
                )
                decision = ("DEFER", "require_approval", issued_ticket_id)
        else:
            decision = ("ALLOW", "allow", 0)
        _userspace_record_decision(agent_id, decision[0], decision[1])
        return decision
    client = _get_kernel_client()
    try:
        decision_reply = client.tool_request(
            req_id=req_id,
            agent_id=agent_id,
            binding_hash=binding_hash,
            binding_epoch=binding_epoch,
            tool_id=tool_id,
            tool_hash=tool_hash,
            ticket_id=ticket_id,
        )
    except RuntimeError as exc:
        if "Invalid argument" in str(exc):
            raise RuntimeError(
                "kernel request ABI mismatch: rebuild and reload kernel_mcp from this repo"
            ) from exc
        raise
    LOGGER.info(
        "arb req_id=%d agent=%s tool=%d decision=%s reason=%s ticket_id=%d",
        req_id,
        agent_id,
        tool_id,
        decision_reply.decision,
        decision_reply.reason,
        decision_reply.ticket_id,
    )
    return (
        decision_reply.decision,
        decision_reply.reason,
        decision_reply.ticket_id,
    )


def _kernel_report_complete(
    agent_id: str,
    tool_id: int,
    req_id: int,
    status_code: int,
    exec_ms: int,
) -> None:
    if _uses_userspace_semantic_plane():
        _userspace_record_complete(agent_id, status_code, exec_ms)
        return
    if not _tool_complete_enabled():
        return
    client = _get_kernel_client()
    client.tool_complete(
        req_id=req_id,
        agent_id=agent_id,
        tool_id=tool_id,
        status_code=status_code,
        exec_ms=exec_ms,
    )


def _call_uds_tool(tool: ToolManifest, req_id: int, agent_id: str, payload: Any) -> Dict[str, Any]:
    req = {
        "req_id": req_id,
        "agent_id": agent_id,
        "tool_id": tool.tool_id,
        "operation": tool.operation,
        "payload": payload,
    }
    encoded = json.dumps(req, ensure_ascii=True).encode("utf-8")
    timeout_s = max(tool.timeout_ms / 1000.0, 1.0)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout_s)
            conn.connect(tool.endpoint)
            send_frame(conn, encoded, max_msg_size=MAX_MSG_SIZE)
            raw = recv_frame(conn, max_msg_size=MAX_MSG_SIZE)
    except (FileNotFoundError, ConnectionRefusedError, TimeoutError, OSError) as exc:
        raise ValueError(f"tool service offline: {tool.endpoint}") from exc

    try:
        resp = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"tool service returned invalid JSON ({tool.name})") from exc
    if not isinstance(resp, dict):
        raise ValueError(f"tool service returned non-object response ({tool.name})")
    status = resp.get("status", "")
    if status not in ("ok", "error"):
        raise ValueError(f"tool service returned invalid status ({tool.name})")
    return resp


def _call_tool_service(tool: ToolManifest, req_id: int, agent_id: str, payload: Any) -> Dict[str, Any]:
    if tool.transport != "uds_rpc":
        raise ValueError(f"unsupported tool transport: {tool.transport}")
    return _call_uds_tool(tool, req_id=req_id, agent_id=agent_id, payload=payload)


def _list_apps_public() -> List[Dict[str, Any]]:
    with _registry_lock:
        return list_apps_public(list(_app_registry.values()))


def _list_tools_public(app_id: str = "") -> List[Dict[str, Any]]:
    with _registry_lock:
        if app_id:
            app = _app_registry.get(app_id)
            if app is None:
                raise ValueError(f"unknown app_id: {app_id}")
            tools = app.tools
        else:
            tools = _tool_registry.values()
    return list_tools_public(list(tools))


def _build_error(req_id: int, err: str, t_ms: int) -> Dict[str, Any]:
    return {
        "req_id": req_id,
        "status": "error",
        "result": {},
        "error": err,
        "t_ms": t_ms,
    }


def _send_json(conn: socket.socket, payload: Dict[str, Any]) -> None:
    send_frame(
        conn,
        json.dumps(payload, ensure_ascii=True).encode("utf-8"),
        max_msg_size=MAX_MSG_SIZE,
    )


def _approval_decide(
    ticket_id: int,
    decision: str,
    agent_id: str,
    approver: str,
    reason: str,
    ttl_ms: int,
    *,
    binding_hash: int = 0,
    binding_epoch: int = 0,
) -> None:
    normalized = decision.strip().lower()
    if ttl_ms <= 0:
        raise ValueError("ttl_ms must be positive")
    if _uses_userspace_semantic_plane():
        _userspace_approval_decide(
            ticket_id=ticket_id,
            decision=normalized,
            agent_id=agent_id,
            binding_hash=binding_hash,
            binding_epoch=binding_epoch,
            approver=approver,
            reason=reason,
            ttl_ms=ttl_ms,
        )
        return
    decision_code = APPROVAL_DECISION_MAP.get(normalized)
    if decision_code is None:
        raise ValueError("decision must be one of: approve, deny, revoke")
    client = _get_kernel_client()
    client.approval_decide(
        ticket_id=ticket_id,
        agent_id=agent_id,
        decision=decision_code,
        binding_hash=binding_hash,
        binding_epoch=binding_epoch,
        approver=approver,
        reason=reason,
        ttl_ms=ttl_ms,
    )


def _resolve_tool_hash(req: Dict[str, Any], tool: ToolManifest) -> str:
    raw = req.get("tool_hash", "")
    if raw in (None, ""):
        return tool.manifest_hash
    if not isinstance(raw, str) or not HASH_RE.fullmatch(raw):
        raise ValueError("tool_hash must be 8 hex chars")
    return raw.lower()


def _handle_tool_exec(req: Dict[str, Any]) -> Dict[str, Any]:
    total_start = time.perf_counter()
    _ensure_runtime_registry_current()
    req_id = ensure_int("req_id", req.get("req_id", 0))
    peer = req.get("_peer")
    if not isinstance(peer, PeerIdentity):
        raise ValueError("missing peer identity")
    session_id = ensure_non_empty_str("session_id", req.get("session_id", ""))
    binding: AgentBinding | None = None
    session_lookup_start = time.perf_counter()
    if _uses_forwarder_only():
        try:
            session = resolve_session(session_id, peer)
            agent_id = ensure_non_empty_str("agent_id", session.get("agent_id", ""))
        except Exception:  # noqa: BLE001
            agent_id = "forwarder"
    else:
        try:
            session = resolve_session(session_id, peer)
            binding = session_binding(session)
            agent_id = ensure_non_empty_str("agent_id", session.get("agent_id", ""))
        except Exception:
            if not _userspace_attack_enabled("tamper_session", "tamper_policy"):
                raise
            session = {
                "session_id": session_id,
                "agent_id": "compromised-agent",
                "peer": peer,
            }
            binding = _compromised_binding_for_peer(peer)
            agent_id = "compromised-agent"
    session_lookup_ms = (time.perf_counter() - session_lookup_start) * 1000.0
    app_id = ensure_non_empty_str("app_id", req.get("app_id", ""))
    tool_id = ensure_int("tool_id", req.get("tool_id", 0))

    with _registry_lock:
        tool = _tool_registry.get(tool_id)
    if tool is None:
        raise ValueError(f"unsupported tool_id: {tool_id}")
    if tool.app_id != app_id and not _userspace_attack_enabled("tamper_metadata", "tamper_policy"):
        raise ValueError(
            f"tool_id={tool_id} does not belong to app_id={app_id} (expected {tool.app_id})"
        )

    payload = req.get("payload", {})
    validate_payload(tool.input_schema, payload)

    tool_hash = tool.manifest_hash if _uses_forwarder_only() else _resolve_tool_hash(req, tool)
    decision = "ALLOW"
    reason = "allow_forwarder_only" if _uses_forwarder_only() else "allow"
    ticket_id = 0
    if not _uses_forwarder_only():
        if binding is None:
            raise ValueError("missing session binding")
        _ensure_agent_registered(agent_id, binding)
        approval_ticket_id = ensure_int("approval_ticket_id", req.get("approval_ticket_id", 0))
        arbitration_start = time.perf_counter()
        decision, reason, ticket_id = _kernel_arbitrate(
            req_id=req_id,
            agent_id=agent_id,
            binding_hash=binding.binding_hash,
            binding_epoch=binding.binding_epoch,
            tool_id=tool_id,
            tool_hash=tool_hash,
            ticket_id=approval_ticket_id,
        )
        arbitration_ms = (time.perf_counter() - arbitration_start) * 1000.0
        if decision == "DENY":
            resp = {
                "req_id": req_id,
                "status": "error",
                "result": {},
                "error": f"kernel arbitration denied: {reason}",
                "t_ms": 0,
                "decision": decision,
                "reason": reason,
                "ticket_id": ticket_id,
            }
            if _timing_enabled():
                resp["timing_ms"] = {
                    "session_lookup": round(session_lookup_ms, 3),
                    "arbitration": round(arbitration_ms, 3),
                    "tool_exec": 0.0,
                    "total": round((time.perf_counter() - total_start) * 1000.0, 3),
                }
            return resp
        if decision == "DEFER":
            if ticket_id > 0:
                remember_pending_approval(
                    ticket_id=ticket_id,
                    session_id=session_id,
                    req_id=req_id,
                    agent_id=agent_id,
                    binding_hash=binding.binding_hash,
                    binding_epoch=binding.binding_epoch,
                    app_id=app_id,
                    tool_id=tool_id,
                    payload=payload,
                    tool_hash=tool_hash,
                )
            resp = {
                "req_id": req_id,
                "status": "error",
                "result": {},
                "error": f"kernel arbitration deferred: {reason}",
                "t_ms": 0,
                "decision": decision,
                "reason": reason,
                "ticket_id": ticket_id,
            }
            if _timing_enabled():
                resp["timing_ms"] = {
                    "session_lookup": round(session_lookup_ms, 3),
                    "arbitration": round(arbitration_ms, 3),
                    "tool_exec": 0.0,
                    "total": round((time.perf_counter() - total_start) * 1000.0, 3),
                }
            return resp
    else:
        arbitration_ms = 0.0

    exec_start = time.perf_counter()
    status_code = 1
    try:
        tool_resp = _call_tool_service(tool, req_id=req_id, agent_id=agent_id, payload=payload)
        status = tool_resp.get("status")
        result = tool_resp.get("result", {})
        err = tool_resp.get("error", "")
        tool_t_ms = tool_resp.get("t_ms")
        if not isinstance(result, dict):
            result = {"value": result}
        if not isinstance(err, str):
            err = str(err)
        if not isinstance(tool_t_ms, int) or isinstance(tool_t_ms, bool) or tool_t_ms < 0:
            tool_t_ms = int((time.perf_counter() - exec_start) * 1000)
        if status == "ok":
            status_code = 0
        resp = {
            "req_id": req_id,
            "status": status,
            "result": result if status == "ok" else {},
            "error": "" if status == "ok" else err,
            "t_ms": tool_t_ms,
            "tool_name": tool.name,
            "decision": decision,
            "reason": reason,
            "ticket_id": ticket_id,
        }
        if _timing_enabled():
            resp["timing_ms"] = {
                "session_lookup": round(session_lookup_ms, 3),
                "arbitration": round(arbitration_ms, 3),
                "tool_exec": round((time.perf_counter() - exec_start) * 1000.0, 3),
                "total": round((time.perf_counter() - total_start) * 1000.0, 3),
            }
        return resp
    finally:
        exec_ms = int((time.perf_counter() - exec_start) * 1000)
        try:
            _kernel_report_complete(
                agent_id=agent_id,
                tool_id=tool_id,
                req_id=req_id,
                status_code=status_code,
                exec_ms=exec_ms,
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.error(
                "tool_complete report failed req_id=%d agent=%s tool=%d err=%s",
                req_id,
                agent_id,
                tool_id,
                exc,
            )


def _handle_sys_list_apps(conn: socket.socket, t0: float) -> None:
    _ensure_runtime_registry_current()
    apps_public = _list_apps_public()
    resp = {"status": "ok", "apps": apps_public}
    _send_json(conn, resp)
    t_ms = int((time.perf_counter() - t0) * 1000)
    LOGGER.info("kind=%s status=ok apps=%d t_ms=%d", "sys:list_apps", len(apps_public), t_ms)


def _handle_sys_list_tools(conn: socket.socket, req: Dict[str, Any], t0: float) -> None:
    _ensure_runtime_registry_current()
    app_id_req = req.get("app_id", "")
    if app_id_req not in ("", None) and not isinstance(app_id_req, str):
        raise ValueError("app_id must be string when provided")
    app_id_str = "" if app_id_req in ("", None) else app_id_req
    resp = {"status": "ok", "app_id": app_id_str, "tools": _list_tools_public(app_id=app_id_str)}
    _send_json(conn, resp)
    t_ms = int((time.perf_counter() - t0) * 1000)
    LOGGER.info(
        "kind=%s status=ok app_id=%s tools=%d t_ms=%d",
        "sys:list_tools",
        app_id_str or "all",
        len(resp["tools"]),
        t_ms,
    )


def _handle_sys_open_session(conn: socket.socket, req: Dict[str, Any], peer: PeerIdentity, t0: float) -> None:
    client_name = ensure_non_empty_str("client_name", req.get("client_name", "llm-app"))
    ttl_ms = normalize_session_ttl_ms(req.get("ttl_ms", DEFAULT_SESSION_TTL_MS))
    resp = open_session(peer, client_name, ttl_ms)
    _bind_agent_identity(resp["agent_id"], session_binding(resolve_session(resp["session_id"], peer)))
    _send_json(conn, resp)
    t_ms = int((time.perf_counter() - t0) * 1000)
    LOGGER.info(
        "kind=%s status=ok client=%s session=%s agent=%s uid=%d pid=%d t_ms=%d",
        "sys:open_session",
        client_name,
        resp["session_id"][:12],
        resp["agent_id"],
        peer.uid,
        peer.pid,
        t_ms,
    )


def _handle_sys_approval_decide(conn: socket.socket, req: Dict[str, Any], t0: float) -> None:
    ticket_id_raw = req.get("ticket_id", 0)
    decision_raw = req.get("decision", "")
    operator_raw = req.get("operator", "")
    agent_id_raw = req.get("agent_id", "")
    reason_raw = req.get("reason", "")
    ttl_ms_raw = req.get("ttl_ms", DEFAULT_APPROVAL_TTL_MS)
    binding_hash_raw = req.get("binding_hash", 0)
    binding_epoch_raw = req.get("binding_epoch", 0)
    ticket_id = ensure_int("ticket_id", ticket_id_raw)
    decision_text = ensure_non_empty_str("decision", decision_raw)
    operator_text = ensure_non_empty_str("operator", operator_raw)
    reason_text = ensure_non_empty_str("reason", reason_raw)
    ttl_ms = ensure_int("ttl_ms", ttl_ms_raw)
    binding_hash = ensure_int("binding_hash", binding_hash_raw)
    binding_epoch = ensure_int("binding_epoch", binding_epoch_raw)
    agent_id_text = agent_id_raw if isinstance(agent_id_raw, str) else ""
    try:
        pending = peek_pending_approval(ticket_id)
        replay_req = validate_pending_approval_req(pending)
        if not agent_id_text:
            agent_id_text = replay_req["agent_id"]
        binding_hash = replay_req["binding_hash"]
        binding_epoch = replay_req["binding_epoch"]
    except ValueError:
        if not agent_id_text:
            agent_id_text = operator_text
    agent_id_text = ensure_non_empty_str("agent_id", agent_id_text)
    _approval_decide(
        ticket_id,
        decision_text,
        agent_id_text,
        operator_text,
        reason_text,
        ttl_ms,
        binding_hash=binding_hash,
        binding_epoch=binding_epoch,
    )
    resp = {
        "status": "ok",
        "ticket_id": ticket_id,
        "decision": decision_text.lower(),
        "operator": operator_text,
        "agent_id": agent_id_text,
        "ttl_ms": ttl_ms,
    }
    _send_json(conn, resp)
    t_ms = int((time.perf_counter() - t0) * 1000)
    LOGGER.info(
        "kind=%s status=ok ticket_id=%d decision=%s t_ms=%d",
        "sys:approval_decide",
        ticket_id,
        decision_text.lower(),
        t_ms,
    )


def _handle_connection(conn: socket.socket) -> None:
    with conn:
        peer = _read_peer_identity(conn)
        while True:
            req_id = 0
            agent_id = "unknown"
            app_id = ""
            tool_id = 0
            req_kind = "tool:exec"
            t0 = time.perf_counter()
            try:
                raw = recv_frame(conn, max_msg_size=MAX_MSG_SIZE)
                req = json.loads(raw.decode("utf-8"))
                if not isinstance(req, dict):
                    raise ValueError("request must be JSON object")

                if req.get("sys") == "list_apps":
                    req_kind = "sys:list_apps"
                    _handle_sys_list_apps(conn, t0)
                    continue

                if req.get("sys") == "list_tools":
                    req_kind = "sys:list_tools"
                    _handle_sys_list_tools(conn, req, t0)
                    continue

                if req.get("sys") == "open_session":
                    req_kind = "sys:open_session"
                    _handle_sys_open_session(conn, req, peer, t0)
                    continue

                if req.get("sys") == "approval_decide":
                    req_kind = "sys:approval_decide"
                    _handle_sys_approval_decide(conn, req, t0)
                    continue

                if req.get("sys") == "approval_reply":
                    req_kind = "sys:approval_reply"
                    session_id = ensure_non_empty_str("session_id", req.get("session_id", ""))
                    ticket_id = ensure_int("ticket_id", req.get("ticket_id", 0))
                    decision_text = ensure_non_empty_str("decision", req.get("decision", ""))
                    reason_text = ensure_non_empty_str("reason", req.get("reason", ""))
                    ttl_ms = ensure_int("ttl_ms", req.get("ttl_ms", DEFAULT_APPROVAL_TTL_MS))
                    normalized = decision_text.strip().lower()
                    if normalized not in ("approve", "deny"):
                        raise ValueError("decision must be approve or deny")
                    session = resolve_session(session_id, peer)
                    pending = peek_pending_approval(ticket_id)
                    if pending.get("session_id") != session_id:
                        raise ValueError("approval ticket is bound to a different session")
                    pending = take_pending_approval(ticket_id)
                    try:
                        replay_req = validate_pending_approval_req(pending)
                        operator_text = ensure_non_empty_str("agent_id", session.get("agent_id", ""))
                        binding = session_binding(session)
                        _approval_decide(
                            ticket_id=ticket_id,
                            decision=normalized,
                            agent_id=operator_text,
                            approver=operator_text,
                            reason=reason_text,
                            ttl_ms=ttl_ms,
                            binding_hash=binding.binding_hash,
                            binding_epoch=binding.binding_epoch,
                        )
                        if normalized == "deny":
                            resp = {
                                "status": "error",
                                "error": "approval declined by user",
                                "ticket_id": ticket_id,
                                "decision": "DENY",
                                "reason": "user_declined",
                                "t_ms": 0,
                            }
                        else:
                            replay_req["approval_ticket_id"] = ticket_id
                            replay_req["_peer"] = peer
                            replay_req["session_id"] = session_id
                            resp = _handle_tool_exec(replay_req)
                    except Exception:
                        if normalized == "approve":
                            put_pending_approval(ticket_id, pending)
                        raise
                    _send_json(conn, resp)
                    t_ms = int((time.perf_counter() - t0) * 1000)
                    LOGGER.info(
                        "kind=%s status=%s ticket_id=%d decision=%s t_ms=%d",
                        req_kind,
                        resp.get("status"),
                        ticket_id,
                        normalized,
                        t_ms,
                    )
                    continue

                if "kind" in req and req.get("kind") != "tool:exec":
                    raise ValueError(f"unsupported request kind: {req.get('kind')}")

                req_id = ensure_int("req_id", req.get("req_id", 0))
                session_id = ensure_non_empty_str("session_id", req.get("session_id", ""))
                try:
                    session = resolve_session(session_id, peer)
                    agent_id = ensure_non_empty_str("agent_id", session.get("agent_id", ""))
                except Exception:
                    if not _userspace_attack_enabled("tamper_session", "tamper_policy"):
                        raise
                    agent_id = "compromised-agent"
                app_id = ensure_non_empty_str("app_id", req.get("app_id", ""))
                tool_id = ensure_int("tool_id", req.get("tool_id", 0))
                req["_peer"] = peer
                resp = _handle_tool_exec(req)
                _send_json(conn, resp)
                t_ms = int((time.perf_counter() - t0) * 1000)
                LOGGER.info(
                    "req_id=%d session=%s agent=%s app=%s tool=%d kind=%s status=%s t_ms=%d",
                    req_id,
                    session_id[:12],
                    agent_id,
                    app_id,
                    tool_id,
                    req_kind,
                    resp.get("status"),
                    t_ms,
                )
            except ConnectionError:
                return
            except Exception as exc:  # noqa: BLE001
                t_ms = int((time.perf_counter() - t0) * 1000)
                if req_kind.startswith("sys:"):
                    resp = {"status": "error", "error": str(exc)}
                else:
                    resp = _build_error(req_id=req_id, err=str(exc), t_ms=t_ms)
                try:
                    _send_json(conn, resp)
                except Exception:  # noqa: BLE001
                    return
                LOGGER.error(
                    "req_id=%d agent=%s app=%s tool=%d kind=%s status=error err=%s",
                    req_id,
                    agent_id,
                    app_id,
                    tool_id,
                    req_kind,
                    exc,
                )


def _accept_loop(server: socket.socket) -> None:
    while not _stop_event.is_set():
        try:
            conn, _addr = server.accept()
        except OSError:
            if _stop_event.is_set():
                return
            continue
        th = threading.Thread(target=_handle_connection, args=(conn,), daemon=True)
        th.start()


def _cleanup_socket(path: str) -> None:
    p = Path(path)
    if p.exists():
        p.unlink()


def _signal_handler(_sig: int, _frame: Any) -> None:
    _stop_event.set()


def main() -> int:
    global _kernel_client

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    try:
        if _kernel_mode_enabled():
            _kernel_client = KernelMcpNetlinkClient()
        _ensure_runtime_registry_current(force=True)
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("failed to initialize mcpd runtime: %s", exc)
        if _kernel_client is not None:
            _kernel_client.close()
            _kernel_client = None
        return 1

    sock_path = _sock_path()
    _cleanup_socket(sock_path)

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(sock_path)
            os.chmod(sock_path, 0o666)
            server.listen(128)
            server.settimeout(0.5)
            LOGGER.info("mcpd listening on %s mode=%s", sock_path, _normalized_experiment_mode())

            accept_thread = threading.Thread(target=_accept_loop, args=(server,), daemon=True)
            accept_thread.start()

            while not _stop_event.is_set():
                time.sleep(0.2)
        return 0
    finally:
        _cleanup_socket(sock_path)
        if _kernel_client is not None:
            _kernel_client.close()
            _kernel_client = None
        LOGGER.info("mcpd stopped")


if __name__ == "__main__":
    raise SystemExit(main())
