#!/usr/bin/env python3
"""Shared UDS RPC helpers for demo tool apps."""

from __future__ import annotations

import argparse
import json
import signal
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict

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
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_MSG_SIZE:
        raise ValueError(f"invalid frame length: {length}")
    payload = _recv_exact(sock, length)
    return json.loads(payload.decode("utf-8"))


def send_msg(sock: socket.socket, obj: Any) -> None:
    payload = json.dumps(obj, ensure_ascii=True).encode("utf-8")
    if len(payload) > MAX_MSG_SIZE:
        raise ValueError("payload too large")
    sock.sendall(struct.pack(">I", len(payload)))
    sock.sendall(payload)


def load_manifest(manifest_path: str) -> Dict[str, Any]:
    raw = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{manifest_path}: manifest must be object")
    return raw


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=str)
    return parser.parse_args()


def _bind_socket(transport: str, endpoint: str) -> socket.socket:
    """Create and bind an AF_UNIX socket according to the manifest's transport.

    uds_rpc binds to a filesystem path (we mkdir the parent and clear any
    stale socket file first). uds_abstract binds to the Linux abstract
    namespace by prefixing NUL; no filesystem artefact to clean.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if transport == "uds_abstract":
        sock.bind(b"\x00" + endpoint.encode("utf-8"))
        return sock
    if transport == "uds_rpc":
        endpoint_path = Path(endpoint)
        endpoint_path.parent.mkdir(parents=True, exist_ok=True)
        if endpoint_path.exists():
            endpoint_path.unlink()
        sock.bind(str(endpoint_path))
        return sock
    sock.close()
    raise ValueError(f"unsupported transport for demo_rpc: {transport!r}")


def serve(
    manifest_path: str,
    operations: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]],
) -> int:
    raw = load_manifest(manifest_path)
    endpoint = raw.get("endpoint", "")
    transport = raw.get("transport", "uds_rpc")
    app_id = raw.get("app_id", "unknown")
    if not isinstance(endpoint, str) or not endpoint:
        raise ValueError(f"{manifest_path}: endpoint must be non-empty string")
    if not isinstance(transport, str) or not transport:
        raise ValueError(f"{manifest_path}: transport must be non-empty string")

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
        server = _bind_socket(transport, endpoint)
        server.listen(128)
        server.settimeout(0.5)
        print(
            f"[demo_app] serving app_id={app_id} transport={transport} "
            f"endpoint={endpoint} operations={sorted(operations.keys())}",
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
        # Only path-based endpoints leave filesystem artefacts.
        if transport == "uds_rpc":
            p = Path(endpoint)
            if p.exists():
                p.unlink()
        signal.signal(signal.SIGINT, prev_int)
        signal.signal(signal.SIGTERM, prev_term)
