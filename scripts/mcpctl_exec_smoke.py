#!/usr/bin/env python3
"""Minimal end-to-end exerciser that bypasses the llm-app planner.

Opens a session and invokes a low-risk tool directly via the mcpd UDS JSON
RPC so that we can validate the audit pipeline (kernel call_log, sysfs)
without depending on an LLM API key or any LLM planning.

Default target is tool_id=2 (note_list), which is read-only (risk_flags=0x20).
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys

SOCK_PATH = "/tmp/mcpd.sock"


def _rpc(req: dict, timeout_s: float = 5.0) -> dict:
    raw = json.dumps(req, ensure_ascii=True).encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout_s)
        conn.connect(SOCK_PATH)
        conn.sendall(struct.pack(">I", len(raw)))
        conn.sendall(raw)
        hdr = conn.recv(4)
        if len(hdr) != 4:
            raise RuntimeError("short reply header")
        (length,) = struct.unpack(">I", hdr)
        body = b""
        while len(body) < length:
            chunk = conn.recv(length - len(body))
            if not chunk:
                raise RuntimeError("short reply body")
            body += chunk
    return json.loads(body.decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-id", default="notes_app")
    parser.add_argument("--tool-id", type=int, default=2)
    parser.add_argument(
        "--payload",
        default="{}",
        help="JSON payload to send (default: {})",
    )
    parser.add_argument(
        "--client-name",
        default="mcpctl-smoke",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="send tool:exec N times (useful for filling call_log)",
    )
    args = parser.parse_args(argv)

    payload = json.loads(args.payload)

    sess = _rpc({"sys": "open_session", "req_id": 1, "client_name": args.client_name})
    print(f"session: id={sess['session_id'][:12]}… agent={sess['agent_id']}")
    sid = sess["session_id"]

    for i in range(args.repeat):
        req = {
            "kind": "tool:exec",
            "req_id": 1000 + i,
            "session_id": sid,
            "app_id": args.app_id,
            "tool_id": args.tool_id,
            "payload": payload,
        }
        resp = _rpc(req)
        status = resp.get("status")
        decision = resp.get("decision")
        reason = resp.get("reason")
        t_ms = resp.get("t_ms")
        print(
            f"[{i+1}/{args.repeat}] status={status} decision={decision} "
            f"reason={reason} t_ms={t_ms}"
        )
        if status != "ok":
            print(f"    error: {resp.get('error', '')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
