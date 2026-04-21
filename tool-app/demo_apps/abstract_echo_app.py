#!/usr/bin/env python3
"""Minimal demo backend that binds on a Linux abstract UDS.

Exercises the uds_abstract transport end-to-end: the mcpd gateway can
dial it, SO_PEERCRED still yields the backend pid, and the binary_hash
probe still hashes /proc/<pid>/exe (which is the Python interpreter —
same caveat as the other Python demos; the native_echo demo is what
drives the replacement-attack test).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve


def op_abstract_echo(payload: Dict[str, Any]) -> Dict[str, Any]:
    note = payload.get("note", "")
    if not isinstance(note, str):
        raise ValueError("note must be string")
    return {
        "transport": "uds_abstract",
        "echoed": True,
        "note": note,
    }


def main() -> int:
    args = parse_args()
    return serve(args.manifest, {"abstract_echo": op_abstract_echo})


if __name__ == "__main__":
    raise SystemExit(main())
