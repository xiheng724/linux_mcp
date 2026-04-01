#!/usr/bin/env python3
"""Shared framed socket helpers for mcpd and demo RPC peers."""

from __future__ import annotations

import socket
import struct


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(conn: socket.socket, *, max_msg_size: int) -> bytes:
    header = recv_exact(conn, 4)
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > max_msg_size:
        raise ValueError(f"invalid frame length: {length}")
    return recv_exact(conn, length)


def send_frame(conn: socket.socket, payload: bytes, *, max_msg_size: int) -> None:
    if len(payload) > max_msg_size:
        raise ValueError("payload too large")
    conn.sendall(struct.pack(">I", len(payload)))
    conn.sendall(payload)
