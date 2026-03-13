#!/usr/bin/env python3
"""Shared Unix domain socket service helpers."""

from __future__ import annotations

import json
import socket
import struct
from typing import Any

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
