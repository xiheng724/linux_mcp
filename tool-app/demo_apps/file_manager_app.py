#!/usr/bin/env python3
"""Semantic wrappers for the real Linux file manager interface."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve
from real_app_support import require_gui_session, require_non_empty_string, run_gdbus_method

DESTINATION = "org.freedesktop.FileManager1"
OBJECT_PATH = "/org/freedesktop/FileManager1"
INTERFACE = "org.freedesktop.FileManager1"


def _file_uri(raw_path: str) -> str:
    path = Path(raw_path).expanduser().resolve()
    if not path.exists():
        raise ValueError(f"path does not exist: {path}")
    return path.as_uri()


def open_directory(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    directory_path = require_non_empty_string(payload, "path")
    uri = _file_uri(directory_path)
    path = Path(directory_path).expanduser().resolve()
    if not path.is_dir():
        raise ValueError(f"path is not a directory: {path}")
    result = run_gdbus_method(
        bus="session",
        destination=DESTINATION,
        object_path=OBJECT_PATH,
        interface=INTERFACE,
        method="ShowFolders",
        arguments=[f"['{uri}']", ""],
    )
    return {"opened": result["ok"], "path": str(path), "uri": uri, **result}


def reveal_path(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    target_path = require_non_empty_string(payload, "path")
    path = Path(target_path).expanduser().resolve()
    if not path.exists():
        raise ValueError(f"path does not exist: {path}")
    uri = path.as_uri()
    result = run_gdbus_method(
        bus="session",
        destination=DESTINATION,
        object_path=OBJECT_PATH,
        interface=INTERFACE,
        method="ShowItems",
        arguments=[f"['{uri}']", ""],
    )
    return {"revealed": result["ok"], "path": str(path), "uri": uri, **result}


def show_item_properties(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    target_path = require_non_empty_string(payload, "path")
    path = Path(target_path).expanduser().resolve()
    if not path.exists():
        raise ValueError(f"path does not exist: {path}")
    uri = path.as_uri()
    result = run_gdbus_method(
        bus="session",
        destination=DESTINATION,
        object_path=OBJECT_PATH,
        interface=INTERFACE,
        method="ShowItemProperties",
        arguments=[f"['{uri}']", ""],
    )
    return {"requested": result["ok"], "path": str(path), "uri": uri, **result}


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "open_directory": open_directory,
            "reveal_path": reveal_path,
            "show_item_properties": show_item_properties,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
