#!/usr/bin/env python3
"""Demo client: kernel control-plane arbitration + UDS data-plane execution."""

from __future__ import annotations

import argparse
import json
import re
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Tuple

ROOT = Path(__file__).resolve().parent.parent
SOCK_PATH = "/tmp/mcpd.sock"
LINE_RE = re.compile(
    r"decision=(?P<decision>[A-Z]+)\s+wait_ms=(?P<wait>\d+)\s+tokens_left=(?P<tokens>\d+)\s+reason=(?P<reason>.+)$"
)


def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def register_basics(agent_id: str) -> None:
    run_cmd(
        ["./client/bin/genl_register_tool", "--id", "1", "--name", "echo", "--perm", "1", "--cost", "1"]
    )
    run_cmd(
        ["./client/bin/genl_register_tool", "--id", "2", "--name", "cpu_burn", "--perm", "1", "--cost", "3"]
    )
    run_cmd(["./client/bin/genl_register_agent", "--id", agent_id])


def parse_decision(out: str) -> Tuple[str, int, int, str]:
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if not lines:
        raise ValueError("empty tool_request output")
    m = LINE_RE.search(lines[-1])
    if not m:
        raise ValueError(f"unexpected output: {lines[-1]}")
    return (
        m.group("decision"),
        int(m.group("wait")),
        int(m.group("tokens")),
        m.group("reason"),
    )


def tool_request_once(agent_id: str, tool_id: int) -> Tuple[str, int, int, str]:
    proc = run_cmd(
        [
            "./client/bin/genl_tool_request",
            "--agent",
            agent_id,
            "--tool",
            str(tool_id),
            "--n",
            "1",
        ]
    )
    return parse_decision(proc.stdout)


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(conn: socket.socket) -> bytes:
    header = recv_exact(conn, 4)
    (length,) = struct.unpack(">I", header)
    if length <= 0:
        raise ValueError("invalid length")
    return recv_exact(conn, length)


def send_frame(conn: socket.socket, payload: bytes) -> None:
    conn.sendall(struct.pack(">I", len(payload)))
    conn.sendall(payload)


def exec_via_mcpd(
    req_id: int, agent_id: str, tool_id: int, payload: Dict[str, Any], sock_path: str
) -> Dict[str, Any]:
    if tool_id == 2:
        app_id = "settings_app"
    else:
        app_id = "utility_app"
    req = {
        "req_id": req_id,
        "agent_id": agent_id,
        "app_id": app_id,
        "tool_id": tool_id,
        "payload": payload,
    }
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.connect(sock_path)
        send_frame(conn, json.dumps(req, ensure_ascii=True).encode("utf-8"))
        resp_raw = recv_frame(conn)
    resp = json.loads(resp_raw.decode("utf-8"))
    if not isinstance(resp, dict):
        raise ValueError("invalid response type")
    return resp


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", default="a1")
    parser.add_argument("--tool", type=int, default=2)
    parser.add_argument("--count", type=int, default=8)
    parser.add_argument("--cpu-ms", type=int, default=200)
    parser.add_argument("--socket", default=SOCK_PATH)
    parser.add_argument("--skip-register", action="store_true")
    args = parser.parse_args()

    if not args.skip_register:
        register_basics(args.agent)

    defer_seen = False
    ok_seen = False

    for i in range(1, args.count + 1):
        while True:
            decision, wait_ms, tokens_left, reason = tool_request_once(args.agent, args.tool)
            print(
                f"req={i} decision={decision} wait_ms={wait_ms} tokens_left={tokens_left} reason={reason}",
                flush=True,
            )

            if decision == "DENY":
                print("arbitration denied; stopping", flush=True)
                return 2
            if decision == "DEFER":
                defer_seen = True
                time.sleep(wait_ms / 1000.0)
                continue
            if decision != "ALLOW":
                return 3

            payload: Dict[str, Any]
            if args.tool == 2:
                payload = {"ms": args.cpu_ms}
            else:
                payload = {"echo": f"req-{i}"}

            resp = exec_via_mcpd(i, args.agent, args.tool, payload, args.socket)
            print(f"req={i} mcpd_response={json.dumps(resp, ensure_ascii=True)}", flush=True)
            if resp.get("status") == "ok":
                ok_seen = True
            break

    if not defer_seen:
        print("WARN: no DEFER observed", flush=True)
    if not ok_seen:
        print("ERROR: no successful mcpd execution", flush=True)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
