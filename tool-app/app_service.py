#!/usr/bin/env python3
"""Multi-tool app service that dispatches by tool_id over one UDS endpoint."""

from __future__ import annotations

import argparse
import importlib.util
import json
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict

from service_lib import recv_msg, send_msg

ROOT_DIR = Path(__file__).resolve().parent.parent
TOOL_APP_DIR = Path(__file__).resolve().parent
DEFAULT_MCPD_SOCK = "/tmp/mcpd.sock"
REGISTER_RETRY_SEC = 1.0
REGISTER_REFRESH_SEC = 5.0
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))


def _ensure_non_empty_str(name: str, value: Any, manifest: Path) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{manifest}: {name} must be non-empty string")
    return value


def _ensure_int(name: str, value: Any, manifest: Path) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{manifest}: {name} must be int")
    return value


def _ensure_tool_path(name: str, value: Any, manifest: Path) -> str:
    path = _ensure_non_empty_str(name, value, manifest)
    if path.startswith("/"):
        raise ValueError(f"{manifest}: {name} must be relative to repo root")
    if not path.startswith("tool-app/"):
        raise ValueError(f"{manifest}: {name} must be under tool-app/")
    return path


def _load_python_module(module_path: str, module_tag: str) -> Any:
    file_path = (ROOT_DIR / module_path).resolve()
    try:
        file_path.relative_to(ROOT_DIR)
    except ValueError as exc:
        raise ValueError(f"{module_tag}: module path escapes repo root") from exc
    if not file_path.is_file():
        raise ValueError(f"{module_tag}: module file missing: {module_path}")

    module_name = f"linux_mcp_{module_tag}_{file_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    if spec is None or spec.loader is None:
        raise ValueError(f"{module_tag}: unable to load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_handlers_from_app_module(app_impl: str, manifest_path: Path) -> Dict[str, Callable[[Any], Any]]:
    module = _load_python_module(app_impl, module_tag=manifest_path.stem)
    mapping = getattr(module, "HANDLERS", None)
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError(f"{manifest_path}: app_impl missing non-empty HANDLERS dict")
    handlers: Dict[str, Callable[[Any], Any]] = {}
    for key, value in mapping.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"{manifest_path}: HANDLERS key must be non-empty string")
        if not callable(value):
            raise ValueError(f"{manifest_path}: HANDLERS['{key}'] is not callable")
        handlers[key] = value
    return handlers


def _load_manifest(manifest_path: Path) -> tuple[str, str, Dict[int, Callable[[Any], Any]]]:
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{manifest_path}: manifest must be object")

    for field in ("app_id", "app_name", "endpoint", "mode", "app_impl", "tools"):
        if field not in raw:
            raise ValueError(f"{manifest_path}: missing field {field}")

    app_id = _ensure_non_empty_str("app_id", raw["app_id"], manifest_path)
    app_name = _ensure_non_empty_str("app_name", raw["app_name"], manifest_path)
    mode = _ensure_non_empty_str("mode", raw["mode"], manifest_path)
    endpoint = _ensure_non_empty_str("endpoint", raw["endpoint"], manifest_path)
    app_impl = _ensure_tool_path("app_impl", raw["app_impl"], manifest_path)
    if mode != "uds_service":
        raise ValueError(f"{manifest_path}: mode must be uds_service")
    if not endpoint.startswith("/tmp/linux-mcp-apps/"):
        raise ValueError(f"{manifest_path}: endpoint must start with /tmp/linux-mcp-apps/")

    app_handlers = _load_handlers_from_app_module(app_impl, manifest_path)

    tools = raw["tools"]
    if not isinstance(tools, list) or not tools:
        raise ValueError(f"{manifest_path}: tools must be non-empty list")

    handlers: Dict[int, Callable[[Any], Any]] = {}
    for tool in tools:
        if not isinstance(tool, dict):
            raise ValueError(f"{manifest_path}: tool item must be object")
        for field in ("tool_id", "handler"):
            if field not in tool:
                raise ValueError(f"{manifest_path}: tool missing field {field}")
        tool_id = _ensure_int("tool_id", tool["tool_id"], manifest_path)
        handler_name = _ensure_non_empty_str("handler", tool["handler"], manifest_path)
        if tool_id in handlers:
            raise ValueError(f"{manifest_path}: duplicate tool_id={tool_id}")
        handler_fn = app_handlers.get(handler_name)
        if handler_fn is None:
            raise ValueError(
                f"{manifest_path}: unknown handler '{handler_name}' for tool_id={tool_id}; available={sorted(app_handlers.keys())}"
            )
        handlers[tool_id] = handler_fn

    return app_id, app_name, handlers


def _register_manifest_once(manifest_raw: Dict[str, Any], sock_path: str, timeout_s: float = 3.0) -> Dict[str, Any]:
    payload = json.dumps({"sys": "register_manifest", "manifest": manifest_raw}, ensure_ascii=True).encode(
        "utf-8"
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout_s)
        conn.connect(sock_path)
        conn.sendall(struct.pack(">I", len(payload)))
        conn.sendall(payload)
        raw = recv_msg(conn)
    if not isinstance(raw, dict):
        raise ValueError("mcpd returned non-object response during manifest registration")
    return raw


def _registration_loop(
    manifest_raw: Dict[str, Any],
    sock_path: str,
    stop_event: threading.Event,
) -> None:
    app_id = str(manifest_raw.get("app_id", "unknown"))
    last_error = ""
    registered = False
    while not stop_event.is_set():
        try:
            resp = _register_manifest_once(manifest_raw, sock_path=sock_path)
            if resp.get("status") != "ok":
                raise ValueError(str(resp.get("error", "register_manifest failed")))
            if not registered:
                print(
                    f"[app_service] registered manifest app_id={app_id} tools={resp.get('tool_count', '?')} via={sock_path}",
                    flush=True,
                )
            registered = True
            last_error = ""
            stop_event.wait(REGISTER_REFRESH_SEC)
            continue
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if not registered or msg != last_error:
                print(
                    f"[app_service] manifest registration pending app_id={app_id} sock={sock_path} err={msg}",
                    flush=True,
                )
            registered = False
            last_error = msg
            stop_event.wait(REGISTER_RETRY_SEC)


def _serve(
    endpoint_path: str,
    handlers: Dict[int, Callable[[Any], Any]],
    *,
    stop_event: threading.Event,
) -> int:
    endpoint = Path(endpoint_path)
    endpoint.parent.mkdir(parents=True, exist_ok=True)
    if endpoint.exists():
        endpoint.unlink()

    def _signal_handler(_sig: int, _frame: Any) -> None:
        stop_event.set()

    prev_int = signal.getsignal(signal.SIGINT)
    prev_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    def _handle_client(conn: socket.socket) -> None:
        with conn:
            t0 = time.perf_counter()
            req_id = 0
            try:
                req = recv_msg(conn)
                if not isinstance(req, dict):
                    raise ValueError("request must be JSON object")

                req_id_raw = req.get("req_id", 0)
                if isinstance(req_id_raw, int) and not isinstance(req_id_raw, bool):
                    req_id = req_id_raw

                tool_id_raw = req.get("tool_id", 0)
                if isinstance(tool_id_raw, bool) or not isinstance(tool_id_raw, int):
                    raise ValueError("tool_id must be integer")
                tool_id = tool_id_raw
                handler = handlers.get(tool_id)
                if handler is None:
                    raise ValueError(f"unsupported tool_id: {tool_id}")

                payload = req.get("payload", {})
                if not isinstance(payload, dict):
                    raise ValueError("payload must be object")

                result = handler(payload)
                if not isinstance(result, dict):
                    result = {"value": result}

                send_msg(
                    conn,
                    {
                        "req_id": req_id,
                        "status": "ok",
                        "result": result,
                        "error": "",
                        "t_ms": int((time.perf_counter() - t0) * 1000),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                try:
                    send_msg(
                        conn,
                        {
                            "req_id": req_id,
                            "status": "error",
                            "result": {},
                            "error": str(exc),
                            "t_ms": int((time.perf_counter() - t0) * 1000),
                        },
                    )
                except Exception:  # noqa: BLE001
                    return

    server: socket.socket | None = None
    try:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(endpoint))
        server.listen(128)
        server.settimeout(0.5)

        while not stop_event.is_set():
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                if stop_event.is_set():
                    break
                continue
            th = threading.Thread(target=_handle_client, args=(conn,), daemon=True)
            th.start()
        return 0
    finally:
        if server is not None:
            try:
                server.close()
            except Exception:  # noqa: BLE001
                pass
        if endpoint.exists():
            endpoint.unlink()
        signal.signal(signal.SIGINT, prev_int)
        signal.signal(signal.SIGTERM, prev_term)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=str)
    parser.add_argument("--serve", required=True, type=str)
    parser.add_argument("--mcpd-sock", default=DEFAULT_MCPD_SOCK, type=str)
    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    app_id, app_name, handlers = _load_manifest(manifest_path)

    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_endpoint = str(raw["endpoint"])
    if args.serve != manifest_endpoint:
        raise ValueError(
            f"serve endpoint mismatch for app_id={app_id}: arg={args.serve} manifest={manifest_endpoint}"
        )

    print(
        f"[app_service] serving app_id={app_id} app_name={app_name} tools={sorted(handlers.keys())} endpoint={args.serve}",
        flush=True,
    )
    stop_event = threading.Event()
    registration_thread = threading.Thread(
        target=_registration_loop,
        args=(raw, args.mcpd_sock, stop_event),
        daemon=True,
    )
    registration_thread.start()
    return _serve(args.serve, handlers, stop_event=stop_event)


if __name__ == "__main__":
    raise SystemExit(main())
