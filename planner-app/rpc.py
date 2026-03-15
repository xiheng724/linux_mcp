#!/usr/bin/env python3
"""Minimal UDS RPC helper for mcpd."""

from __future__ import annotations

import json
import socket
import struct
from typing import Any, Dict

DEFAULT_SOCK_PATH = "/tmp/mcpd.sock"
DEFAULT_TIMEOUT_S = 5.0
MAX_MSG_SIZE = 16 * 1024 * 1024


def _error(msg: str) -> Dict[str, Any]:
    return {"status": "error", "error": msg}


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed while receiving frame")
        buf.extend(chunk)
    return bytes(buf)


def _send_frame(conn: socket.socket, payload: bytes) -> None:
    conn.sendall(struct.pack(">I", len(payload)))
    conn.sendall(payload)


def _recv_frame(conn: socket.socket) -> bytes:
    header = _recv_exact(conn, 4)
    (length,) = struct.unpack(">I", header)
    if length <= 0 or length > MAX_MSG_SIZE:
        raise ValueError(f"invalid frame length: {length}")
    return _recv_exact(conn, length)


def mcpd_call(
    req: Dict[str, Any],
    sock_path: str = DEFAULT_SOCK_PATH,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> Dict[str, Any]:
    """Call mcpd and return dict response or {'status':'error', ...}."""
    if not isinstance(req, dict):
        return _error("request must be dict")

    try:
        payload = json.dumps(req, ensure_ascii=True).encode("utf-8")
    except Exception as exc:  # noqa: BLE001
        return _error(f"request serialization failed: {exc}")

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout_s)
            conn.connect(sock_path)
            _send_frame(conn, payload)
            raw = _recv_frame(conn)
    except FileNotFoundError:
        return _error(f"mcpd socket not found: {sock_path}")
    except PermissionError:
        return _error(f"no permission to access mcpd socket: {sock_path}")
    except socket.timeout:
        return _error(f"mcpd request timeout after {timeout_s:.1f}s")
    except (ConnectionError, OSError, ValueError) as exc:
        return _error(f"mcpd rpc failed: {exc}")

    try:
        resp = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return _error(f"invalid JSON response from mcpd: {exc}")
    if not isinstance(resp, dict):
        return _error("mcpd response is not a JSON object")
    return resp


def _selftest() -> int:
    resp = mcpd_call({"sys": "list_capabilities"})
    if resp.get("status") != "ok":
        print(f"[rpc] ERROR: {resp.get('error', 'unknown error')}", flush=True)
        print("[rpc] Hint: start mcpd with: bash scripts/run_mcpd.sh", flush=True)
        return 1

    capabilities = resp.get("capabilities", [])
    if not isinstance(capabilities, list):
        print("[rpc] ERROR: list_capabilities response missing capabilities list", flush=True)
        return 1

    print(f"[rpc] list_capabilities ok: count={len(capabilities)}", flush=True)
    for capability in capabilities[:2]:
        if isinstance(capability, dict):
            print(
                f"[rpc] capability id={capability.get('capability_id')} domain={capability.get('capability_domain')} hash={capability.get('hash', '-')}",
                flush=True,
            )
    return 0


def main() -> int:
    return _selftest()


if __name__ == "__main__":
    raise SystemExit(main())
