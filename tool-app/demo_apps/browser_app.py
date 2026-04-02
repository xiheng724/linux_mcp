#!/usr/bin/env python3
"""Semantic wrappers for the Firefox browser."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve
from real_app_support import (
    find_executable,
    optional_string,
    require_gui_session,
    require_non_empty_string,
    spawn_detached,
)


def open_tab(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    url = require_non_empty_string(payload, "url")
    firefox = find_executable("firefox")
    proc = spawn_detached([firefox, "--new-tab", url])
    return {"opened": True, "mode": "tab", "url": url, "pid": proc.pid}


def open_private_window(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    url = optional_string(payload, "url")
    firefox = find_executable("firefox")
    args = [firefox, "--private-window"]
    if url:
        args.append(url)
    proc = spawn_detached(args)
    return {"opened": True, "mode": "private_window", "url": url, "pid": proc.pid}


def search_web(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    query = require_non_empty_string(payload, "query")
    firefox = find_executable("firefox")
    proc = spawn_detached([firefox, "--search", query])
    return {"opened": True, "mode": "search", "query": query, "pid": proc.pid}


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "open_tab": open_tab,
            "open_private_window": open_private_window,
            "search_web": search_web,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
