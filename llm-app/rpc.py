#!/usr/bin/env python3
"""Minimal UDS RPC helper for mcpd."""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path
from typing import Any, Dict

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from mcpd.rpc_framing import recv_frame, send_frame

DEFAULT_SOCK_PATH = "/tmp/mcpd.sock"
DEFAULT_TIMEOUT_S = 5.0
MAX_MSG_SIZE = 16 * 1024 * 1024


def _error(msg: str) -> Dict[str, Any]:
    return {"status": "error", "error": msg}


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
            send_frame(conn, payload, max_msg_size=MAX_MSG_SIZE)
            raw = recv_frame(conn, max_msg_size=MAX_MSG_SIZE)
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
    resp = mcpd_call({"sys": "list_tools"})
    if resp.get("status") != "ok":
        print(f"[rpc] ERROR: {resp.get('error', 'unknown error')}", flush=True)
        print("[rpc] Hint: start mcpd with: bash scripts/run_mcpd.sh", flush=True)
        return 1

    tools = resp.get("tools", [])
    if not isinstance(tools, list):
        print("[rpc] ERROR: list_tools response missing tools list", flush=True)
        return 1

    print(f"[rpc] list_tools ok: count={len(tools)}", flush=True)
    for tool in tools[:2]:
        if isinstance(tool, dict):
            print(
                f"[rpc] tool id={tool.get('tool_id')} name={tool.get('name')} hash={tool.get('hash', '-')}",
                flush=True,
            )
    return 0


def main() -> int:
    return _selftest()


if __name__ == "__main__":
    raise SystemExit(main())
