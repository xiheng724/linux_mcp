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
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

SOCK_PATH = "/tmp/mcpd.sock"
MAX_MSG_SIZE = 16 * 1024 * 1024
MAX_DEFER_RETRIES = 50
TOOLS_DIR = Path(__file__).resolve().parent / "tools.d"
ROOT_DIR = Path(__file__).resolve().parent.parent
LOGGER = logging.getLogger("mcpd")
DECISION_RE = re.compile(
    r"decision=(?P<decision>[A-Z]+)\s+wait_ms=(?P<wait>\d+)\s+tokens_left=(?P<tokens>\d+)\s+reason=(?P<reason>.+)$"
)
HASH_RE = re.compile(r"^[0-9a-fA-F]{8}$")

_stop_event = threading.Event()
_agents_lock = threading.Lock()
_registered_agents: set[str] = set()


@dataclass(frozen=True)
class ToolMeta:
    tool_id: int
    name: str
    perm: int
    cost: int
    description: str
    input_schema: Dict[str, Any]
    examples: List[Any]
    app_path: str
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


def _load_one_manifest(path: Path) -> ToolMeta:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: manifest must be JSON object")

    required_fields = [
        "tool_id",
        "name",
        "perm",
        "cost",
        "app_path",
        "description",
        "input_schema",
        "examples",
    ]
    for field in required_fields:
        if field not in raw:
            raise ValueError(f"{path}: missing field '{field}'")

    tool_id = _ensure_int("tool_id", raw["tool_id"])
    perm = _ensure_int("perm", raw["perm"])
    cost = _ensure_int("cost", raw["cost"])
    name = raw["name"]
    description = raw["description"]
    input_schema = raw["input_schema"]
    examples = raw["examples"]
    app_path = raw["app_path"]

    if not isinstance(name, str) or not name:
        raise ValueError(f"{path}: name must be non-empty string")
    if not isinstance(app_path, str) or not app_path:
        raise ValueError(f"{path}: app_path must be non-empty string")
    if app_path.startswith("/"):
        raise ValueError(f"{path}: app_path must be relative to repo root")
    if not app_path.startswith("tool-app/"):
        raise ValueError(f"{path}: app_path must be under tool-app/")
    if not isinstance(description, str) or not description:
        raise ValueError(f"{path}: description must be non-empty string")
    if not isinstance(input_schema, dict):
        raise ValueError(f"{path}: input_schema must be object")
    if not isinstance(examples, list):
        raise ValueError(f"{path}: examples must be list")

    digest = hashlib.sha256(_canonical_json_bytes(raw)).hexdigest()[:8]

    return ToolMeta(
        tool_id=tool_id,
        name=name,
        perm=perm,
        cost=cost,
        description=description,
        input_schema=input_schema,
        examples=examples,
        app_path=app_path,
        manifest_hash=digest,
    )


def _load_tool_registry(tools_dir: Path) -> Dict[int, ToolMeta]:
    if not tools_dir.is_dir():
        raise ValueError(f"tool manifest directory missing: {tools_dir}")

    registry: Dict[int, ToolMeta] = {}
    for path in sorted(tools_dir.glob("*.json")):
        tool = _load_one_manifest(path)
        if tool.tool_id in registry:
            raise ValueError(f"duplicate tool_id in manifests: {tool.tool_id}")
        registry[tool.tool_id] = tool

    if not registry:
        raise ValueError(f"no tool manifests found under {tools_dir}")
    return registry


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


def _resolve_tool_app_path(app_path: str) -> Path:
    app_file = (ROOT_DIR / app_path).resolve()
    try:
        app_file.relative_to(ROOT_DIR)
    except ValueError as exc:
        raise ValueError(f"app_path escapes repo root: {app_path}") from exc
    return app_file


def _run_cmd(cmd: List[str]) -> str:
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT_DIR),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc.stdout


def _parse_decision(stdout: str) -> Tuple[str, int, int, str]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("empty genl_tool_request output")
    match = DECISION_RE.search(lines[-1])
    if not match:
        raise RuntimeError(f"unexpected genl_tool_request output: {lines[-1]}")
    return (
        match.group("decision"),
        int(match.group("wait")),
        int(match.group("tokens")),
        match.group("reason"),
    )


def _ensure_agent_registered(agent_id: str) -> None:
    with _agents_lock:
        if agent_id in _registered_agents:
            return

    _run_cmd(["./client/bin/genl_register_agent", "--id", agent_id])
    LOGGER.info("agent registered via netlink: %s", agent_id)

    with _agents_lock:
        _registered_agents.add(agent_id)


def _kernel_arbitrate(
    req_id: int,
    agent_id: str,
    tool_id: int,
    tool_hash: str,
) -> Tuple[str, int, int, str, int]:
    for attempt in range(1, MAX_DEFER_RETRIES + 1):
        cmd = [
            "./client/bin/genl_tool_request",
            "--agent",
            agent_id,
            "--tool",
            str(tool_id),
            "--tool-hash",
            tool_hash,
            "--n",
            "1",
        ]
        stdout = _run_cmd(cmd)
        decision, wait_ms, tokens_left, reason = _parse_decision(stdout)
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
    _run_cmd(
        [
            "./client/bin/genl_tool_complete",
            "--agent",
            agent_id,
            "--tool",
            str(tool_id),
            "--req-id",
            str(req_id),
            "--status",
            str(status_code),
            "--exec-ms",
            str(exec_ms),
        ]
    )


def _run_tool_app(tool: ToolMeta, payload: Any) -> Any:
    app_file = _resolve_tool_app_path(tool.app_path)
    if not app_file.is_file():
        raise ValueError(f"tool app missing for tool {tool.tool_id}: {tool.app_path}")

    proc = subprocess.run(
        ["python3", str(app_file), "--stdin-json"],
        cwd=str(ROOT_DIR),
        input=json.dumps(payload, ensure_ascii=True),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip() or f"exit code={proc.returncode}"
        raise ValueError(f"tool app failed ({tool.name}): {err}")

    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        raise ValueError(f"tool app returned empty output ({tool.name})")
    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"tool app returned invalid JSON ({tool.name}): {lines[-1]}") from exc


def _tool_to_public(tool: ToolMeta) -> Dict[str, Any]:
    return {
        "tool_id": tool.tool_id,
        "name": tool.name,
        "description": tool.description,
        "input_schema": tool.input_schema,
        "perm": tool.perm,
        "cost": tool.cost,
        "hash": tool.manifest_hash,
    }


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


def _handle_tool_exec(req: Dict[str, Any], registry: Dict[int, ToolMeta]) -> Dict[str, Any]:
    req_id = _ensure_int("req_id", req.get("req_id", 0))
    agent_id = _ensure_non_empty_str("agent_id", req.get("agent_id", ""))
    tool_id = _ensure_int("tool_id", req.get("tool_id", 0))
    tool = registry.get(tool_id)
    if tool is None:
        raise ValueError(f"unsupported tool_id: {tool_id}")

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
        result = _run_tool_app(tool, payload)
        status_code = 0
        return {
            "req_id": req_id,
            "status": "ok",
            "result": result,
            "error": "",
            "t_ms": int((time.perf_counter() - exec_start) * 1000),
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


def _handle_connection(conn: socket.socket, registry: Dict[int, ToolMeta]) -> None:
    with conn:
        while True:
            req_id = 0
            agent_id = "unknown"
            tool_id = 0
            req_kind = "tool:exec"
            t0 = time.perf_counter()
            try:
                raw = _recv_frame(conn)
                req = json.loads(raw.decode("utf-8"))
                if not isinstance(req, dict):
                    raise ValueError("request must be JSON object")

                if req.get("sys") == "list_tools":
                    req_kind = "sys:list_tools"
                    resp = {
                        "status": "ok",
                        "tools": [_tool_to_public(registry[idx]) for idx in sorted(registry.keys())],
                    }
                    _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                    t_ms = int((time.perf_counter() - t0) * 1000)
                    LOGGER.info(
                        "kind=%s status=ok tools=%d t_ms=%d",
                        req_kind,
                        len(resp["tools"]),
                        t_ms,
                    )
                    continue

                if "kind" in req and req.get("kind") != "tool:exec":
                    raise ValueError(f"unsupported request kind: {req.get('kind')}")

                req_id = _ensure_int("req_id", req.get("req_id", 0))
                agent_id = _ensure_non_empty_str("agent_id", req.get("agent_id", ""))
                tool_id = _ensure_int("tool_id", req.get("tool_id", 0))
                resp = _handle_tool_exec(req, registry)
                _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                t_ms = int((time.perf_counter() - t0) * 1000)
                LOGGER.info(
                    "req_id=%d agent=%s tool=%d kind=%s status=%s t_ms=%d",
                    req_id,
                    agent_id,
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
                    "req_id=%d agent=%s tool=%d kind=%s status=error err=%s",
                    req_id,
                    agent_id,
                    tool_id,
                    req_kind,
                    exc,
                )


def _accept_loop(server: socket.socket, registry: Dict[int, ToolMeta]) -> None:
    while not _stop_event.is_set():
        try:
            conn, _addr = server.accept()
        except OSError:
            if _stop_event.is_set():
                return
            continue
        th = threading.Thread(target=_handle_connection, args=(conn, registry), daemon=True)
        th.start()


def _cleanup_socket(path: str) -> None:
    p = Path(path)
    if p.exists():
        p.unlink()


def _signal_handler(_sig: int, _frame: Any) -> None:
    _stop_event.set()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    try:
        registry = _load_tool_registry(TOOLS_DIR)
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("failed to load tool manifests: %s", exc)
        return 1

    LOGGER.info("loaded tool manifests count=%d dir=%s", len(registry), TOOLS_DIR)
    _cleanup_socket(SOCK_PATH)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(SOCK_PATH)
        os.chmod(SOCK_PATH, 0o666)
        server.listen(128)
        server.settimeout(0.5)
        LOGGER.info("mcpd listening on %s", SOCK_PATH)

        accept_thread = threading.Thread(
            target=_accept_loop,
            args=(server, registry),
            daemon=True,
        )
        accept_thread.start()

        while not _stop_event.is_set():
            time.sleep(0.2)

    _cleanup_socket(SOCK_PATH)
    LOGGER.info("mcpd stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

