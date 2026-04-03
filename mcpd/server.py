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

_stop_event = threading.Event()
_agents_lock = threading.Lock()
_registry_lock = threading.RLock()
_registered_agents: Dict[str, "AgentBinding"] = {}
_agent_bindings: Dict[str, "AgentBinding"] = {}
_app_registry: Dict[str, AppManifest] = {}
_tool_registry: Dict[int, ToolManifest] = {}
_kernel_client: KernelMcpNetlinkClient | None = None
_manifest_reload_lock = threading.Lock()
_manifest_signature = ""


def _get_kernel_client() -> KernelMcpNetlinkClient:
    if _kernel_client is None:
        raise RuntimeError("kernel netlink client is not initialized")
    return _kernel_client


def _register_tool_with_kernel(tool: ToolManifest) -> None:
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
    client = _get_kernel_client()

    client.reset_tools()

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
    decision_code = APPROVAL_DECISION_MAP.get(normalized)
    if decision_code is None:
        raise ValueError("decision must be one of: approve, deny, revoke")
    if ttl_ms <= 0:
        raise ValueError("ttl_ms must be positive")
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
    _ensure_runtime_registry_current()
    req_id = ensure_int("req_id", req.get("req_id", 0))
    session_id = ensure_non_empty_str("session_id", req.get("session_id", ""))
    peer = req.get("_peer")
    if not isinstance(peer, PeerIdentity):
        raise ValueError("missing peer identity")
    session = resolve_session(session_id, peer)
    binding = session_binding(session)
    agent_id = ensure_non_empty_str("agent_id", session.get("agent_id", ""))
    app_id = ensure_non_empty_str("app_id", req.get("app_id", ""))
    tool_id = ensure_int("tool_id", req.get("tool_id", 0))

    with _registry_lock:
        tool = _tool_registry.get(tool_id)
    if tool is None:
        raise ValueError(f"unsupported tool_id: {tool_id}")
    if tool.app_id != app_id:
        raise ValueError(
            f"tool_id={tool_id} does not belong to app_id={app_id} (expected {tool.app_id})"
        )

    payload = req.get("payload", {})
    validate_payload(tool.input_schema, payload)

    tool_hash = _resolve_tool_hash(req, tool)
    _ensure_agent_registered(agent_id, binding)
    approval_ticket_id = ensure_int("approval_ticket_id", req.get("approval_ticket_id", 0))
    decision, reason, ticket_id = _kernel_arbitrate(
        req_id=req_id,
        agent_id=agent_id,
        binding_hash=binding.binding_hash,
        binding_epoch=binding.binding_epoch,
        tool_id=tool_id,
        tool_hash=tool_hash,
        ticket_id=approval_ticket_id,
    )
    if decision == "DENY":
        return {
            "req_id": req_id,
            "status": "error",
            "result": {},
            "error": f"kernel arbitration denied: {reason}",
            "t_ms": 0,
            "decision": decision,
            "reason": reason,
            "ticket_id": ticket_id,
        }
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
        return {
            "req_id": req_id,
            "status": "error",
            "result": {},
            "error": f"kernel arbitration deferred: {reason}",
            "t_ms": 0,
            "decision": decision,
            "reason": reason,
            "ticket_id": ticket_id,
        }

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
        return {
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
                    _ensure_runtime_registry_current()
                    apps_public = _list_apps_public()
                    resp = {"status": "ok", "apps": apps_public}
                    send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
                    t_ms = int((time.perf_counter() - t0) * 1000)
                    LOGGER.info("kind=%s status=ok apps=%d t_ms=%d", req_kind, len(apps_public), t_ms)
                    continue

                if req.get("sys") == "list_tools":
                    req_kind = "sys:list_tools"
                    _ensure_runtime_registry_current()
                    app_id_req = req.get("app_id", "")
                    if app_id_req not in ("", None) and not isinstance(app_id_req, str):
                        raise ValueError("app_id must be string when provided")
                    app_id_str = "" if app_id_req in ("", None) else app_id_req
                    resp = {"status": "ok", "app_id": app_id_str, "tools": _list_tools_public(app_id=app_id_str)}
                    send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
                    t_ms = int((time.perf_counter() - t0) * 1000)
                    LOGGER.info(
                        "kind=%s status=ok app_id=%s tools=%d t_ms=%d",
                        req_kind,
                        app_id_str or "all",
                        len(resp["tools"]),
                        t_ms,
                    )
                    continue

                if req.get("sys") == "open_session":
                    req_kind = "sys:open_session"
                    client_name = ensure_non_empty_str("client_name", req.get("client_name", "llm-app"))
                    ttl_ms = normalize_session_ttl_ms(req.get("ttl_ms", DEFAULT_SESSION_TTL_MS))
                    resp = open_session(peer, client_name, ttl_ms)
                    _bind_agent_identity(resp["agent_id"], session_binding(resolve_session(resp["session_id"], peer)))
                    send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
                    t_ms = int((time.perf_counter() - t0) * 1000)
                    LOGGER.info(
                        "kind=%s status=ok client=%s session=%s agent=%s uid=%d pid=%d t_ms=%d",
                        req_kind,
                        client_name,
                        resp["session_id"][:12],
                        resp["agent_id"],
                        peer.uid,
                        peer.pid,
                        t_ms,
                    )
                    continue

                if req.get("sys") == "approval_decide":
                    req_kind = "sys:approval_decide"
                    ticket_id_raw = req.get("ticket_id", 0)
                    decision_raw = req.get("decision", "")
                    operator_raw = req.get("operator", "")
                    agent_id_raw = req.get("agent_id", "")
                    reason_raw = req.get("reason", "")
                    ttl_ms_raw = req.get("ttl_ms", DEFAULT_APPROVAL_TTL_MS)
                    ticket_id = ensure_int("ticket_id", ticket_id_raw)
                    decision_text = ensure_non_empty_str("decision", decision_raw)
                    operator_text = ensure_non_empty_str("operator", operator_raw)
                    reason_text = ensure_non_empty_str("reason", reason_raw)
                    ttl_ms = ensure_int("ttl_ms", ttl_ms_raw)
                    binding_hash = 0
                    binding_epoch = 0
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
                    send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
                    t_ms = int((time.perf_counter() - t0) * 1000)
                    LOGGER.info(
                        "kind=%s status=ok ticket_id=%d decision=%s t_ms=%d",
                        req_kind,
                        ticket_id,
                        decision_text.lower(),
                        t_ms,
                    )
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
                    send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
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
                session = resolve_session(session_id, peer)
                agent_id = ensure_non_empty_str("agent_id", session.get("agent_id", ""))
                app_id = ensure_non_empty_str("app_id", req.get("app_id", ""))
                tool_id = ensure_int("tool_id", req.get("tool_id", 0))
                req["_peer"] = peer
                resp = _handle_tool_exec(req)
                send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
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
                    send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
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
        _kernel_client = KernelMcpNetlinkClient()
        _ensure_runtime_registry_current(force=True)
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("failed to initialize mcpd runtime: %s", exc)
        if _kernel_client is not None:
            _kernel_client.close()
            _kernel_client = None
        return 1

    _cleanup_socket(SOCK_PATH)

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(SOCK_PATH)
            os.chmod(SOCK_PATH, 0o666)
            server.listen(128)
            server.settimeout(0.5)
            LOGGER.info("mcpd listening on %s", SOCK_PATH)

            accept_thread = threading.Thread(target=_accept_loop, args=(server,), daemon=True)
            accept_thread.start()

            while not _stop_event.is_set():
                time.sleep(0.2)
        return 0
    finally:
        _cleanup_socket(SOCK_PATH)
        if _kernel_client is not None:
            _kernel_client.close()
            _kernel_client = None
        LOGGER.info("mcpd stopped")


if __name__ == "__main__":
    raise SystemExit(main())
