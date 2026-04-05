#!/usr/bin/env python3
"""Launcher App bridging installed desktop applications."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from desktop_catalog import find_desktop_app, has_gui_session, iter_desktop_apps
from demo_rpc import parse_args, serve
from sandbox import deny_subprocess_if_sandboxed

MAX_RESULTS = 100


def _spawn_cmd(args: List[str]) -> subprocess.Popen[str]:
    deny_subprocess_if_sandboxed(args)
    return subprocess.Popen(  # noqa: S603
        args,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )


def _validate_target(target: str) -> str:
    target = target.strip()
    if not target:
        return target
    parsed = urlparse(target)
    if parsed.scheme:
        if parsed.scheme not in {"http", "https", "file", "mailto"}:
            raise ValueError("unsupported target URL scheme")
        return target
    path = Path(target).expanduser()
    return str(path)


def list_launchable_apps(payload: Dict[str, Any]) -> Dict[str, Any]:
    query = payload.get("query", "")
    limit = payload.get("limit", 20)
    if not isinstance(query, str):
        raise ValueError("list_launchable_apps payload.query must be string")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("list_launchable_apps payload.limit must be integer")
    needle = query.strip().lower()
    limit = max(1, min(MAX_RESULTS, limit))

    items: List[Dict[str, Any]] = []
    for app in iter_desktop_apps():
        if needle and needle not in app["name"].lower() and needle not in app["desktop_id"].lower():
            continue
        items.append(
            {
                "desktop_id": app["desktop_id"],
                "name": app["name"],
                "executable": app["executable"],
                "terminal": app["terminal"],
            }
        )
        if len(items) >= limit:
            break
    return {"query": query.strip(), "count": len(items), "items": items}


def launch_app(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not has_gui_session():
        raise ValueError("no GUI session available (DISPLAY/WAYLAND_DISPLAY unset)")
    desktop_id = payload.get("desktop_id", "")
    name = payload.get("name", "")
    executable = payload.get("executable", "")
    target = payload.get("target", "")
    if not isinstance(desktop_id, str) or not isinstance(name, str) or not isinstance(executable, str):
        raise ValueError("launch_app selectors must be strings")
    if not isinstance(target, str):
        raise ValueError("launch_app payload.target must be string")
    app = find_desktop_app(desktop_id=desktop_id, name=name, executable=executable)
    if shutil.which(app["executable"]) is None:
        raise ValueError(f"executable not found on host: {app['executable']}")

    args = [app["executable"]]
    normalized_target = _validate_target(target)
    if normalized_target:
        args.append(normalized_target)
    proc = _spawn_cmd(args)
    return {
        "launched": True,
        "desktop_id": app["desktop_id"],
        "name": app["name"],
        "executable": app["executable"],
        "target": normalized_target,
        "pid": proc.pid,
    }


def open_with_app(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not has_gui_session():
        raise ValueError("no GUI session available (DISPLAY/WAYLAND_DISPLAY unset)")
    target = payload.get("target", "")
    desktop_id = payload.get("desktop_id", "")
    name = payload.get("name", "")
    executable = payload.get("executable", "")
    if not isinstance(target, str) or not target.strip():
        raise ValueError("open_with_app payload.target must be non-empty string")
    if not isinstance(desktop_id, str) or not isinstance(name, str) or not isinstance(executable, str):
        raise ValueError("open_with_app selectors must be strings")
    app = find_desktop_app(desktop_id=desktop_id, name=name, executable=executable)
    if shutil.which(app["executable"]) is None:
        raise ValueError(f"executable not found on host: {app['executable']}")

    normalized_target = _validate_target(target)
    proc = _spawn_cmd([app["executable"], normalized_target])
    return {
        "opened": True,
        "desktop_id": app["desktop_id"],
        "name": app["name"],
        "executable": app["executable"],
        "target": normalized_target,
        "pid": proc.pid,
    }


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "list_launchable_apps": list_launchable_apps,
            "launch_app": launch_app,
            "open_with_app": open_with_app,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
