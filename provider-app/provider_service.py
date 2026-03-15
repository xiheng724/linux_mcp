#!/usr/bin/env python3
"""Manifest-driven provider runtime that dispatches action requests over one UDS endpoint."""

from __future__ import annotations

import argparse
import importlib.util
import json
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict

from service_lib import recv_msg, send_msg

ROOT_DIR = Path(__file__).resolve().parent.parent
PROVIDER_APP_DIR = Path(__file__).resolve().parent
if str(PROVIDER_APP_DIR) not in sys.path:
    sys.path.insert(0, str(PROVIDER_APP_DIR))


def _ensure_non_empty_str(name: str, value: Any, manifest: Path) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{manifest}: {name} must be non-empty string")
    return value


def _ensure_int(name: str, value: Any, manifest: Path) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{manifest}: {name} must be int")
    return value


def _ensure_repo_path(name: str, value: Any, manifest: Path) -> str:
    path = _ensure_non_empty_str(name, value, manifest)
    if path.startswith("/"):
        raise ValueError(f"{manifest}: {name} must be relative to repo root")
    if not path.startswith("provider-app/"):
        raise ValueError(f"{manifest}: {name} must be under provider-app/")
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


def _load_handlers_from_provider_module(provider_impl: str, manifest_path: Path) -> Dict[str, Callable[[Any], Any]]:
    module = _load_python_module(provider_impl, module_tag=manifest_path.stem)
    mapping = getattr(module, "HANDLERS", None)
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError(f"{manifest_path}: provider_impl missing non-empty HANDLERS dict")
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

    for field in ("provider_id", "provider_impl", "endpoint", "mode", "actions"):
        if field not in raw:
            raise ValueError(f"{manifest_path}: missing field {field}")

    provider_id = _ensure_non_empty_str("provider_id", raw.get("provider_id"), manifest_path)
    if raw.get("display_name"):
        display_name = _ensure_non_empty_str("display_name", raw.get("display_name"), manifest_path)
    elif raw.get("provider_name"):
        display_name = _ensure_non_empty_str("provider_name", raw.get("provider_name"), manifest_path)
    else:
        display_name = provider_id
    mode = _ensure_non_empty_str("mode", raw["mode"], manifest_path)
    endpoint = _ensure_non_empty_str("endpoint", raw["endpoint"], manifest_path)
    provider_impl = _ensure_repo_path("provider_impl", raw.get("provider_impl"), manifest_path)
    if mode != "uds_service":
        raise ValueError(f"{manifest_path}: mode must be uds_service")
    if not endpoint.startswith("/tmp/linux-mcp-providers/"):
        raise ValueError(f"{manifest_path}: endpoint must start with /tmp/linux-mcp-providers/")

    provider_handlers = _load_handlers_from_provider_module(provider_impl, manifest_path)

    actions_raw = raw.get("actions")
    if not isinstance(actions_raw, list) or not actions_raw:
        raise ValueError(f"{manifest_path}: actions must be non-empty list")

    handlers: Dict[int, Callable[[Any], Any]] = {}
    for action in actions_raw:
        if not isinstance(action, dict):
            raise ValueError(f"{manifest_path}: action item must be object")
        if "action_id" not in action:
            raise ValueError(f"{manifest_path}: action missing field action_id")
        action_id = _ensure_int("action_id", action["action_id"], manifest_path)
        handler_name = _ensure_non_empty_str("handler", action.get("handler", ""), manifest_path)
        if action_id in handlers:
            raise ValueError(f"{manifest_path}: duplicate action_id={action_id}")
        handler_fn = provider_handlers.get(handler_name)
        if handler_fn is None:
            raise ValueError(
                f"{manifest_path}: unknown handler '{handler_name}' for action_id={action_id}; available={sorted(provider_handlers.keys())}"
            )
        handlers[action_id] = handler_fn

    return provider_id, display_name, handlers


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

                action_id_raw = req.get("action_id", 0)
                if isinstance(action_id_raw, bool) or not isinstance(action_id_raw, int):
                    raise ValueError("action_id must be integer")
                action_id = action_id_raw
                handler = handlers.get(action_id)
                if handler is None:
                    raise ValueError(f"unsupported action_id: {action_id}")

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
    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    provider_id, display_name, handlers = _load_manifest(manifest_path)

    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_endpoint = str(raw["endpoint"])
    if args.serve != manifest_endpoint:
        raise ValueError(
            f"serve endpoint mismatch for provider_id={provider_id}: arg={args.serve} manifest={manifest_endpoint}"
        )

    print(
        f"[provider-service] serving provider_id={provider_id} display_name={display_name} actions={sorted(handlers.keys())} endpoint={args.serve}",
        flush=True,
    )
    stop_event = threading.Event()
    print("[provider-service] manifest autoload is canonical; no runtime manifest registration", flush=True)
    return _serve(args.serve, handlers, stop_event=stop_event)


if __name__ == "__main__":
    raise SystemExit(main())
