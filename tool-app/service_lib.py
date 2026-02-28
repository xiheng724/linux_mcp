#!/usr/bin/env python3
"""Shared Unix domain socket service helpers for tool resident services."""

from __future__ import annotations

import json
import signal
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any, Callable, Tuple

MAX_MSG_SIZE = 16 * 1024 * 1024


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_msg(sock: socket.socket) -> Any:
    """Receive one framed JSON message."""
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_MSG_SIZE:
        raise ValueError(f"invalid frame length: {length}")
    payload = _recv_exact(sock, length)
    return json.loads(payload.decode("utf-8"))


def send_msg(sock: socket.socket, obj: Any) -> None:
    """Send one framed JSON message."""
    payload = json.dumps(obj, ensure_ascii=True).encode("utf-8")
    if len(payload) > MAX_MSG_SIZE:
        raise ValueError("payload too large")
    sock.sendall(struct.pack(">I", len(payload)))
    sock.sendall(payload)


def _parse_handler_output(out: Any) -> Tuple[str, Any, str]:
    if isinstance(out, tuple) and len(out) == 2 and isinstance(out[0], str):
        status = out[0].lower()
        if status == "ok":
            return "ok", out[1], ""
        if status == "error":
            err = out[1]
            return "error", {}, str(err)
        raise ValueError("handler tuple status must be 'ok' or 'error'")
    return "ok", out, ""


def serve(
    endpoint_path: str,
    handler_fn: Callable[[dict[str, Any]], Any],
    *,
    tool_id: int,
    tool_name: str,
) -> int:
    """Run a resident tool service with framed JSON protocol."""
    endpoint = Path(endpoint_path)
    endpoint.parent.mkdir(parents=True, exist_ok=True)
    if endpoint.exists():
        endpoint.unlink()

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
                    raise ValueError("request must be JSON object")
                req_id_raw = req.get("req_id", 0)
                if isinstance(req_id_raw, int) and not isinstance(req_id_raw, bool):
                    req_id = req_id_raw
                payload = req.get("payload", {})
                if not isinstance(payload, dict):
                    raise ValueError("payload must be object")

                out = handler_fn(payload)
                status, result, err = _parse_handler_output(out)
                send_msg(
                    conn,
                    {
                        "req_id": req_id,
                        "status": status,
                        "result": result if status == "ok" else {},
                        "error": err if status == "error" else "",
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

