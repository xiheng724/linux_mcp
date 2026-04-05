#!/usr/bin/env python3
"""Shared UDS RPC helpers for demo tool apps."""

from __future__ import annotations

import argparse
import json
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from mcpd.rpc_framing import recv_frame, send_frame
from sandbox import apply_process_sandbox

MAX_MSG_SIZE = 16 * 1024 * 1024


def recv_msg(sock: socket.socket) -> Any:
    payload = recv_frame(sock, max_msg_size=MAX_MSG_SIZE)
    return json.loads(payload.decode("utf-8"))


def send_msg(sock: socket.socket, obj: Any) -> None:
    payload = json.dumps(obj, ensure_ascii=True).encode("utf-8")
    send_frame(sock, payload, max_msg_size=MAX_MSG_SIZE)


def load_manifest(manifest_path: str) -> Dict[str, Any]:
    raw = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{manifest_path}: manifest must be object")
    return raw


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=str)
    return parser.parse_args()


def serve(
    manifest_path: str,
    operations: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]],
) -> int:
    raw = load_manifest(manifest_path)
    apply_process_sandbox()
    endpoint = raw.get("endpoint", "")
    app_id = raw.get("app_id", "unknown")
    if not isinstance(endpoint, str) or not endpoint:
        raise ValueError(f"{manifest_path}: endpoint must be non-empty string")

    endpoint_path = Path(endpoint)
    endpoint_path.parent.mkdir(parents=True, exist_ok=True)
    if endpoint_path.exists():
        endpoint_path.unlink()

    stop_event = threading.Event()

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
                    raise ValueError("request must be object")
                req_id_raw = req.get("req_id", 0)
                if isinstance(req_id_raw, int) and not isinstance(req_id_raw, bool):
                    req_id = req_id_raw
                operation = req.get("operation", "")
                if not isinstance(operation, str) or not operation:
                    raise ValueError("operation must be non-empty string")
                handler = operations.get(operation)
                if handler is None:
                    raise ValueError(f"unsupported operation: {operation}")
                payload = req.get("payload", {})
                if not isinstance(payload, dict):
                    raise ValueError("payload must be object")
                result = handler(payload)
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
        server.bind(str(endpoint_path))
        server.listen(128)
        server.settimeout(0.5)
        print(
            f"[demo_app] serving app_id={app_id} endpoint={endpoint} operations={sorted(operations.keys())}",
            flush=True,
        )
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
        if endpoint_path.exists():
            endpoint_path.unlink()
        signal.signal(signal.SIGINT, prev_int)
        signal.signal(signal.SIGTERM, prev_term)
