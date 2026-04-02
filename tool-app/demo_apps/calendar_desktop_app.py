#!/usr/bin/env python3
"""Semantic wrappers for the GNOME Calendar desktop application."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve
from real_app_support import file_uri_from_path, require_gui_session, run_gdbus_method

DESTINATION = "org.gnome.Calendar"
OBJECT_PATH = "/org/gnome/Calendar"
INTERFACE = "org.freedesktop.Application"


def open_calendar(payload: Dict[str, Any]) -> Dict[str, Any]:
    del payload
    require_gui_session()
    result = run_gdbus_method(
        bus="session",
        destination=DESTINATION,
        object_path=OBJECT_PATH,
        interface=INTERFACE,
        method="Activate",
        arguments=["{}"],
    )
    return {"opened": result["ok"], **result}


def open_calendar_file(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    file_path = payload.get("path", "")
    if not isinstance(file_path, str) or not file_path.strip():
        raise ValueError("path must be non-empty string")
    uri = file_uri_from_path(file_path, expect_dir=False)
    result = run_gdbus_method(
        bus="session",
        destination=DESTINATION,
        object_path=OBJECT_PATH,
        interface=INTERFACE,
        method="Open",
        arguments=[f"['{uri}']", "{}"],
    )
    return {"opened": result["ok"], "path": str(Path(file_path).expanduser().resolve()), "uri": uri, **result}


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "open_calendar": open_calendar,
            "open_calendar_file": open_calendar_file,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
