#!/usr/bin/env python3
"""Demo Utility App exposed over UDS RPC."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve


def echo(payload: Dict[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {"echo": payload}
    message = payload.get("message")
    if isinstance(message, str):
        result["message"] = message
    return result


def main() -> int:
    args = parse_args()
    return serve(args.manifest, {"echo": echo})


if __name__ == "__main__":
    raise SystemExit(main())
