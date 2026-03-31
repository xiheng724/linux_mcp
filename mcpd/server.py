#!/usr/bin/env python3
"""Kernel MCP data-plane daemon over Unix Domain Socket."""

from __future__ import annotations

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

from manifest_loader import AppManifest, ToolManifest, load_all_manifests
from netlink_client import KernelMcpNetlinkClient

SOCK_PATH = "/tmp/mcpd.sock"
MAX_MSG_SIZE = 16 * 1024 * 1024
MAX_DEFER_RETRIES = 50
LOGGER = logging.getLogger("mcpd")
HASH_RE = re.compile(r"^[0-9a-fA-F]{8}$")

_stop_event = threading.Event()
_agents_lock = threading.Lock()
_registry_lock = threading.RLock()
_registered_agents: set[str] = set()
_app_registry: Dict[str, AppManifest] = {}
_tool_registry: Dict[int, ToolManifest] = {}
_kernel_client: KernelMcpNetlinkClient | None = None


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)


def _recv_frame(conn: socket.socket) -> bytes:
    header = _recv_exact(conn, 4)
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_MSG_SIZE:
        raise ValueError(f"invalid frame length: {length}")
    return _recv_exact(conn, length)


def _send_frame(conn: socket.socket, payload: bytes) -> None:
    if len(payload) > MAX_MSG_SIZE:
        raise ValueError("payload too large")
    conn.sendall(struct.pack(">I", len(payload)))
    conn.sendall(payload)


def _ensure_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be int")
    return value


def _ensure_non_empty_str(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty string")
    return value


def _matches_primitive(expected: str, value: Any) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (isinstance(value, int) or isinstance(value, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "null":
        return value is None
    return True


def _validate_payload(input_schema: Dict[str, Any], payload: Any) -> None:
    schema_type = input_schema.get("type")
    if isinstance(schema_type, str) and not _matches_primitive(schema_type, payload):
        raise ValueError(f"payload type mismatch: expected {schema_type}")

    if schema_type != "object":
        return
    if not isinstance(payload, dict):
        raise ValueError("payload must be object")

    required = input_schema.get("required", [])
    if isinstance(required, list):
        for field in required:
            if isinstance(field, str) and field not in payload:
                raise ValueError(f"payload missing required field: {field}")

    properties = input_schema.get("properties", {})
    if not isinstance(properties, dict):
        return

    additional_properties = input_schema.get("additionalProperties", True)
    for key, value in payload.items():
        prop_schema = properties.get(key)
        if prop_schema is None:
            if additional_properties is False:
                raise ValueError(f"payload has unknown field: {key}")
            continue
        if not isinstance(prop_schema, dict):
            continue
        expected_type = prop_schema.get("type")
        if isinstance(expected_type, str) and not _matches_primitive(expected_type, value):
            raise ValueError(f"field '{key}' type mismatch: expected {expected_type}")


def _get_kernel_client() -> KernelMcpNetlinkClient:
    if _kernel_client is None:
        raise RuntimeError("kernel netlink client is not initialized")
    return _kernel_client


def _register_tool_with_kernel(tool: ToolManifest) -> None:
    client = _get_kernel_client()
    client.register_tool(
        tool_id=tool.tool_id,
        name=tool.name,
        perm=tool.perm,
        cost=tool.cost,
        tool_hash=tool.manifest_hash,
    )


def _load_runtime_registry() -> None:
    apps = load_all_manifests()
    app_registry: Dict[str, AppManifest] = {}
    tool_registry: Dict[int, ToolManifest] = {}

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


def _ensure_agent_registered(agent_id: str) -> None:
    with _agents_lock:
        if agent_id in _registered_agents:
            return

    client = _get_kernel_client()
    uid = os.getuid() if hasattr(os, "getuid") else 0
    client.register_agent(agent_id, pid=os.getpid(), uid=uid)
    LOGGER.info("agent registered via netlink: %s", agent_id)

    with _agents_lock:
        _registered_agents.add(agent_id)


def _kernel_arbitrate(
    req_id: int,
    agent_id: str,
    tool_id: int,
    tool_hash: str,
) -> Tuple[str, int, int, str, int]:
    client = _get_kernel_client()
    for attempt in range(1, MAX_DEFER_RETRIES + 1):
        decision_reply = client.tool_request(
            req_id=req_id,
            agent_id=agent_id,
            tool_id=tool_id,
            tool_hash=tool_hash,
        )
        decision = decision_reply.decision
        wait_ms = decision_reply.wait_ms
        tokens_left = decision_reply.tokens_left
        reason = decision_reply.reason
        LOGGER.info(
            "arb req_id=%d agent=%s tool=%d attempt=%d decision=%s wait_ms=%d tokens_left=%d reason=%s",
            req_id,
            agent_id,
            tool_id,
            attempt,
            decision,
            wait_ms,
            tokens_left,
            reason,
        )
        if decision in ("ALLOW", "DENY"):
            return decision, wait_ms, tokens_left, reason, attempt
        if decision != "DEFER":
            raise RuntimeError(f"unknown arbitration decision: {decision}")
        time.sleep(wait_ms / 1000.0)
    raise RuntimeError(f"defer retries exceeded max={MAX_DEFER_RETRIES}")


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
            _send_frame(conn, encoded)
            raw = _recv_frame(conn)
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


def _tool_to_public(tool: ToolManifest) -> Dict[str, Any]:
    return {
        "tool_id": tool.tool_id,
        "name": tool.name,
        "app_id": tool.app_id,
        "app_name": tool.app_name,
        "description": tool.description,
        "input_schema": tool.input_schema,
        "examples": tool.examples,
        "perm": tool.perm,
        "cost": tool.cost,
        "hash": tool.manifest_hash,
    }


def _app_to_public(app: AppManifest) -> Dict[str, Any]:
    ordered = sorted(app.tools, key=lambda item: item.tool_id)
    return {
        "app_id": app.app_id,
        "app_name": app.app_name,
        "tool_count": len(ordered),
        "tool_ids": [tool.tool_id for tool in ordered],
        "tool_names": [tool.name for tool in ordered],
    }


def _list_apps_public() -> List[Dict[str, Any]]:
    with _registry_lock:
        return [_app_to_public(_app_registry[app_id]) for app_id in sorted(_app_registry.keys())]


def _list_tools_public(app_id: str = "") -> List[Dict[str, Any]]:
    with _registry_lock:
        if app_id:
            app = _app_registry.get(app_id)
            if app is None:
                raise ValueError(f"unknown app_id: {app_id}")
            tools = sorted(app.tools, key=lambda item: item.tool_id)
        else:
            tools = sorted(_tool_registry.values(), key=lambda item: item.tool_id)
    return [_tool_to_public(tool) for tool in tools]


def _build_error(req_id: int, err: str, t_ms: int) -> Dict[str, Any]:
    return {
        "req_id": req_id,
        "status": "error",
        "result": {},
        "error": err,
        "t_ms": t_ms,
    }


def _resolve_tool_hash(req: Dict[str, Any], tool: ToolManifest) -> str:
    raw = req.get("tool_hash", "")
    if raw in (None, ""):
        return tool.manifest_hash
    if not isinstance(raw, str) or not HASH_RE.fullmatch(raw):
        raise ValueError("tool_hash must be 8 hex chars")
    return raw.lower()


def _handle_tool_exec(req: Dict[str, Any]) -> Dict[str, Any]:
    req_id = _ensure_int("req_id", req.get("req_id", 0))
    agent_id = _ensure_non_empty_str("agent_id", req.get("agent_id", ""))
    app_id = _ensure_non_empty_str("app_id", req.get("app_id", ""))
    tool_id = _ensure_int("tool_id", req.get("tool_id", 0))

    with _registry_lock:
        tool = _tool_registry.get(tool_id)
    if tool is None:
        raise ValueError(f"unsupported tool_id: {tool_id}")
    if tool.app_id != app_id:
        raise ValueError(
            f"tool_id={tool_id} does not belong to app_id={app_id} (expected {tool.app_id})"
        )

    payload = req.get("payload", {})
    _validate_payload(tool.input_schema, payload)

    tool_hash = _resolve_tool_hash(req, tool)
    _ensure_agent_registered(agent_id)
    decision, wait_ms, tokens_left, reason, arb_attempts = _kernel_arbitrate(
        req_id=req_id,
        agent_id=agent_id,
        tool_id=tool_id,
        tool_hash=tool_hash,
    )
    if decision == "DENY":
        return {
            "req_id": req_id,
            "status": "error",
            "result": {},
            "error": f"kernel arbitration denied: {reason}",
            "t_ms": 0,
            "decision": decision,
            "wait_ms": wait_ms,
            "tokens_left": tokens_left,
            "reason": reason,
            "arb_attempts": arb_attempts,
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
            "wait_ms": wait_ms,
            "tokens_left": tokens_left,
            "reason": reason,
            "arb_attempts": arb_attempts,
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
        while True:
            req_id = 0
            agent_id = "unknown"
            app_id = ""
            tool_id = 0
            req_kind = "tool:exec"
            t0 = time.perf_counter()
            try:
                raw = _recv_frame(conn)
                req = json.loads(raw.decode("utf-8"))
                if not isinstance(req, dict):
                    raise ValueError("request must be JSON object")

                if req.get("sys") == "list_apps":
                    req_kind = "sys:list_apps"
                    apps_public = _list_apps_public()
                    resp = {"status": "ok", "apps": apps_public}
                    _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                    t_ms = int((time.perf_counter() - t0) * 1000)
                    LOGGER.info("kind=%s status=ok apps=%d t_ms=%d", req_kind, len(apps_public), t_ms)
                    continue

                if req.get("sys") == "list_tools":
                    req_kind = "sys:list_tools"
                    app_id_req = req.get("app_id", "")
                    if app_id_req not in ("", None) and not isinstance(app_id_req, str):
                        raise ValueError("app_id must be string when provided")
                    app_id_str = "" if app_id_req in ("", None) else app_id_req
                    resp = {"status": "ok", "app_id": app_id_str, "tools": _list_tools_public(app_id=app_id_str)}
                    _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                    t_ms = int((time.perf_counter() - t0) * 1000)
                    LOGGER.info(
                        "kind=%s status=ok app_id=%s tools=%d t_ms=%d",
                        req_kind,
                        app_id_str or "all",
                        len(resp["tools"]),
                        t_ms,
                    )
                    continue

                if "kind" in req and req.get("kind") != "tool:exec":
                    raise ValueError(f"unsupported request kind: {req.get('kind')}")

                req_id = _ensure_int("req_id", req.get("req_id", 0))
                agent_id = _ensure_non_empty_str("agent_id", req.get("agent_id", ""))
                app_id = _ensure_non_empty_str("app_id", req.get("app_id", ""))
                tool_id = _ensure_int("tool_id", req.get("tool_id", 0))
                resp = _handle_tool_exec(req)
                _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                t_ms = int((time.perf_counter() - t0) * 1000)
                LOGGER.info(
                    "req_id=%d agent=%s app=%s tool=%d kind=%s status=%s t_ms=%d",
                    req_id,
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
                    _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
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
        _load_runtime_registry()
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
