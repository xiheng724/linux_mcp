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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from netlink_client import KernelMcpNetlinkClient

SOCK_PATH = "/tmp/mcpd.sock"
MAX_MSG_SIZE = 16 * 1024 * 1024
MAX_DEFER_RETRIES = 50
LOGGER = logging.getLogger("mcpd")
HASH_RE = re.compile(r"^[0-9a-fA-F]{8}$")
SEMANTIC_HASH_FIELDS = (
    "tool_id",
    "name",
    "app_id",
    "app_name",
    "perm",
    "cost",
    "description",
    "input_schema",
    "examples",
)

_stop_event = threading.Event()
_agents_lock = threading.Lock()
_registry_lock = threading.RLock()
_registered_agents: set[str] = set()
_app_registry: Dict[str, Dict[int, "ToolMeta"]] = {}
_kernel_client: KernelMcpNetlinkClient | None = None


@dataclass(frozen=True)
class ToolMeta:
    tool_id: int
    name: str
    app_id: str
    app_name: str
    perm: int
    cost: int
    description: str
    input_schema: Dict[str, Any]
    examples: List[Any]
    handler: str
    mode: str
    endpoint: str
    manifest_hash: str


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


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _manifest_semantic_hash(raw: Dict[str, Any], path: Path) -> str:
    semantic: Dict[str, Any] = {}
    for field in SEMANTIC_HASH_FIELDS:
        if field not in raw:
            raise ValueError(f"{path}: missing semantic hash field '{field}'")
        semantic[field] = raw[field]
    return hashlib.sha256(_canonical_json_bytes(semantic)).hexdigest()[:8]


def _ensure_int(name: str, value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be int")
    if not isinstance(value, int):
        raise ValueError(f"{name} must be int")
    return value


def _ensure_non_empty_str(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty string")
    return value


def _ensure_tool_path(name: str, value: Any, path: Path) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: {name} must be non-empty string")
    if value.startswith("/"):
        raise ValueError(f"{path}: {name} must be relative to repo root")
    if not value.startswith("tool-app/"):
        raise ValueError(f"{path}: {name} must be under tool-app/")
    return value


def _load_tool_from_app_manifest(
    app_manifest_path: str,
    app_id: str,
    app_name: str,
    mode: str,
    endpoint: str,
    tool_raw: Dict[str, Any],
) -> ToolMeta:
    required_fields = [
        "tool_id",
        "name",
        "perm",
        "cost",
        "handler",
        "description",
        "input_schema",
        "examples",
    ]
    for field in required_fields:
        if field not in tool_raw:
            raise ValueError(f"{app_manifest_path}: tool missing field '{field}'")

    tool_id = _ensure_int("tool_id", tool_raw["tool_id"])
    perm = _ensure_int("perm", tool_raw["perm"])
    cost = _ensure_int("cost", tool_raw["cost"])
    name = tool_raw["name"]
    description = tool_raw["description"]
    input_schema = tool_raw["input_schema"]
    examples = tool_raw["examples"]
    handler = _ensure_non_empty_str("handler", tool_raw["handler"])

    if not isinstance(name, str) or not name:
        raise ValueError(f"{app_manifest_path}: tool name must be non-empty string")
    if not isinstance(description, str) or not description:
        raise ValueError(f"{app_manifest_path}: description must be non-empty string")
    if not isinstance(input_schema, dict):
        raise ValueError(f"{app_manifest_path}: input_schema must be object")
    if not isinstance(examples, list):
        raise ValueError(f"{app_manifest_path}: examples must be list")

    semantic_raw: Dict[str, Any] = {
        "tool_id": tool_id,
        "name": name,
        "app_id": app_id,
        "app_name": app_name,
        "perm": perm,
        "cost": cost,
        "description": description,
        "input_schema": input_schema,
        "examples": examples,
    }
    digest = _manifest_semantic_hash(semantic_raw, app_manifest_path)

    return ToolMeta(
        tool_id=tool_id,
        name=name,
        app_id=app_id,
        app_name=app_name,
        perm=perm,
        cost=cost,
        description=description,
        input_schema=input_schema,
        examples=examples,
        handler=handler,
        mode=mode,
        endpoint=endpoint,
        manifest_hash=digest,
    )


def _load_tools_from_manifest_raw(source: str, raw: Any) -> tuple[str, str, List[ToolMeta]]:
    if not isinstance(raw, dict):
        raise ValueError(f"{source}: manifest must be JSON object")

    for field in ("app_id", "app_name", "mode", "endpoint", "app_impl", "service_path", "tools"):
        if field not in raw:
            raise ValueError(f"{source}: missing field '{field}'")

    app_id = _ensure_non_empty_str("app_id", raw["app_id"])
    app_name = _ensure_non_empty_str("app_name", raw["app_name"])
    mode = _ensure_non_empty_str("mode", raw["mode"])
    endpoint = _ensure_non_empty_str("endpoint", raw["endpoint"])
    _ensure_tool_path("app_impl", raw["app_impl"], Path(source))
    _ensure_tool_path("service_path", raw["service_path"], Path(source))

    if mode != "uds_service":
        raise ValueError(f"{source}: mode must be 'uds_service'")
    if not endpoint.startswith("/tmp/linux-mcp-apps/"):
        raise ValueError(f"{source}: endpoint must start with /tmp/linux-mcp-apps/")

    tools_raw = raw["tools"]
    if not isinstance(tools_raw, list) or not tools_raw:
        raise ValueError(f"{source}: tools must be non-empty list")

    tools: List[ToolMeta] = []
    seen_ids: set[int] = set()
    for tool_raw in tools_raw:
        if not isinstance(tool_raw, dict):
            raise ValueError(f"{source}: each tool must be object")
        tool = _load_tool_from_app_manifest(
            source,
            app_id=app_id,
            app_name=app_name,
            mode=mode,
            endpoint=endpoint,
            tool_raw=tool_raw,
        )
        if tool.tool_id in seen_ids:
            raise ValueError(f"{source}: duplicate tool_id in manifest: {tool.tool_id}")
        seen_ids.add(tool.tool_id)
        tools.append(tool)
    return app_id, app_name, tools


def _register_tool_with_kernel(tool: ToolMeta) -> None:
    client = _get_kernel_client()
    client.register_tool(
        tool_id=tool.tool_id,
        name=tool.name,
        perm=tool.perm,
        cost=tool.cost,
        tool_hash=tool.manifest_hash,
    )


def _register_manifest(raw: Any, source: str) -> Dict[str, Any]:
    app_id, app_name, tools = _load_tools_from_manifest_raw(source, raw)
    tool_map = {tool.tool_id: tool for tool in tools}

    with _registry_lock:
        for tool_id in sorted(tool_map.keys()):
            for other_app_id, other_tools in _app_registry.items():
                if other_app_id == app_id:
                    continue
                if tool_id in other_tools:
                    raise ValueError(
                        f"{source}: tool_id={tool_id} already owned by app_id={other_app_id}"
                    )
        for tool in tools:
            _register_tool_with_kernel(tool)
        _app_registry[app_id] = tool_map

    LOGGER.info(
        "registered manifest source=%s app_id=%s app_name=%s tools=%s",
        source,
        app_id,
        app_name,
        sorted(tool_map.keys()),
    )
    return {
        "status": "ok",
        "app_id": app_id,
        "app_name": app_name,
        "tool_count": len(tool_map),
        "tool_ids": sorted(tool_map.keys()),
    }


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

        if decision == "ALLOW" or decision == "DENY":
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


def _call_tool_service(tool: ToolMeta, req_id: int, agent_id: str, payload: Any) -> Dict[str, Any]:
    req = {
        "req_id": req_id,
        "agent_id": agent_id,
        "tool_id": tool.tool_id,
        "payload": payload,
    }
    encoded = json.dumps(req, ensure_ascii=True).encode("utf-8")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(30)
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


def _tool_to_public(tool: ToolMeta) -> Dict[str, Any]:
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


def _app_to_public(app_id: str, app_name: str, tools: List[ToolMeta]) -> Dict[str, Any]:
    ordered = sorted(tools, key=lambda item: item.tool_id)
    return {
        "app_id": app_id,
        "app_name": app_name,
        "tool_count": len(ordered),
        "tool_ids": [tool.tool_id for tool in ordered],
        "tool_names": [tool.name for tool in ordered],
    }


def _list_tools_public(registry: Dict[int, ToolMeta], app_id: str = "") -> List[Dict[str, Any]]:
    tools: List[ToolMeta] = []
    if app_id:
        for tool in registry.values():
            if tool.app_id == app_id:
                tools.append(tool)
    else:
        tools = list(registry.values())
    tools.sort(key=lambda item: item.tool_id)
    return [_tool_to_public(tool) for tool in tools]


def _flatten_registry_locked() -> Dict[int, ToolMeta]:
    flat: Dict[int, ToolMeta] = {}
    for app_tools in _app_registry.values():
        for tool_id, tool in app_tools.items():
            flat[tool_id] = tool
    return flat


def _list_apps_public() -> List[Dict[str, Any]]:
    with _registry_lock:
        apps_public: List[Dict[str, Any]] = []
        for app_id in sorted(_app_registry.keys()):
            tools = sorted(_app_registry[app_id].values(), key=lambda item: item.tool_id)
            if not tools:
                continue
            apps_public.append(_app_to_public(app_id, tools[0].app_name, tools))
        return apps_public


def _list_tools_public_runtime(app_id: str = "") -> List[Dict[str, Any]]:
    with _registry_lock:
        registry = _flatten_registry_locked()
        return _list_tools_public(registry, app_id=app_id)


def _build_error(req_id: int, err: str, t_ms: int) -> Dict[str, Any]:
    return {
        "req_id": req_id,
        "status": "error",
        "result": {},
        "error": err,
        "t_ms": t_ms,
    }


def _resolve_tool_hash(req: Dict[str, Any], tool: ToolMeta) -> str:
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
        tool = _flatten_registry_locked().get(tool_id)
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
                    LOGGER.info(
                        "kind=%s status=ok apps=%d t_ms=%d",
                        req_kind,
                        len(apps_public),
                        t_ms,
                    )
                    continue

                if req.get("sys") == "list_tools":
                    req_kind = "sys:list_tools"
                    app_id_req = req.get("app_id", "")
                    if app_id_req not in ("", None) and not isinstance(app_id_req, str):
                        raise ValueError("app_id must be string when provided")
                    app_id_str = "" if app_id_req in ("", None) else app_id_req
                    with _registry_lock:
                        if app_id_str and app_id_str not in _app_registry:
                            raise ValueError(f"unknown app_id: {app_id_str}")
                    resp = {
                        "status": "ok",
                        "app_id": app_id_str,
                        "tools": _list_tools_public_runtime(app_id=app_id_str),
                    }
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

                if req.get("sys") == "register_manifest":
                    req_kind = "sys:register_manifest"
                    resp = _register_manifest(req.get("manifest"), "rpc:register_manifest")
                    _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                    t_ms = int((time.perf_counter() - t0) * 1000)
                    LOGGER.info(
                        "kind=%s status=ok app_id=%s tools=%d t_ms=%d",
                        req_kind,
                        resp.get("app_id", "?"),
                        resp.get("tool_count", 0),
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
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("failed to initialize kernel netlink client: %s", exc)
        return 1

    LOGGER.info("mcpd runtime registry ready; waiting for tool-app manifest registration")
    _cleanup_socket(SOCK_PATH)

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(SOCK_PATH)
            os.chmod(SOCK_PATH, 0o666)
            server.listen(128)
            server.settimeout(0.5)
            LOGGER.info("mcpd listening on %s", SOCK_PATH)

            accept_thread = threading.Thread(
                target=_accept_loop,
                args=(server,),
                daemon=True,
            )
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
