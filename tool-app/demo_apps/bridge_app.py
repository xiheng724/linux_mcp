#!/usr/bin/env python3
"""Bridge App for invoking real Linux application entrypoints."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from desktop_catalog import find_desktop_app, has_gui_session, iter_desktop_apps
from demo_rpc import parse_args, serve

MAX_RESULTS = 100


def _spawn_cmd(args: List[str]) -> subprocess.Popen[str]:
    return subprocess.Popen(  # noqa: S603
        args,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )


def _run_cmd(args: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)  # noqa: S603


def list_desktop_entries(payload: Dict[str, Any]) -> Dict[str, Any]:
    query = payload.get("query", "")
    limit = payload.get("limit", 20)
    if not isinstance(query, str):
        raise ValueError("list_desktop_entries payload.query must be string")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("list_desktop_entries payload.limit must be integer")
    limit = max(1, min(MAX_RESULTS, limit))
    needle = query.strip().lower()

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


def launch_desktop_entry(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not has_gui_session():
        raise ValueError("no GUI session available (DISPLAY/WAYLAND_DISPLAY unset)")
    desktop_id = payload.get("desktop_id", "")
    name = payload.get("name", "")
    executable = payload.get("executable", "")
    target = payload.get("target", "")
    if not isinstance(desktop_id, str) or not isinstance(name, str) or not isinstance(executable, str):
        raise ValueError("launch_desktop_entry selectors must be strings")
    if not isinstance(target, str):
        raise ValueError("launch_desktop_entry payload.target must be string")
    app = find_desktop_app(desktop_id=desktop_id, name=name, executable=executable)
    gio = shutil.which("gio")
    if gio is None:
        raise ValueError("gio not found on host")

    args = [gio, "launch", app["path"]]
    if target.strip():
        args.append(target.strip())
    proc = _spawn_cmd(args)
    return {
        "launched": True,
        "desktop_id": app["desktop_id"],
        "name": app["name"],
        "backend": "gio launch",
        "target": target.strip(),
        "pid": proc.pid,
    }


def run_cli_entry(payload: Dict[str, Any]) -> Dict[str, Any]:
    executable = payload.get("executable", "")
    args_raw = payload.get("args", [])
    if not isinstance(executable, str) or not executable.strip():
        raise ValueError("run_cli_entry payload.executable must be non-empty string")
    if not isinstance(args_raw, list):
        raise ValueError("run_cli_entry payload.args must be list[string]")
    args: List[str] = []
    for item in args_raw:
        if not isinstance(item, str):
            raise ValueError("run_cli_entry payload.args must be list[string]")
        args.append(item)
    resolved = shutil.which(executable.strip())
    if resolved is None:
        raise ValueError(f"executable not found on host: {executable.strip()}")
    proc = _run_cmd([resolved, *args])
    return {
        "executable": resolved,
        "args": args,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def call_dbus_method(payload: Dict[str, Any]) -> Dict[str, Any]:
    bus = payload.get("bus", "session")
    destination = payload.get("destination", "")
    object_path = payload.get("object_path", "")
    interface = payload.get("interface", "")
    method = payload.get("method", "")
    args_raw = payload.get("arguments", [])
    if not isinstance(bus, str) or bus not in {"session", "system"}:
        raise ValueError("call_dbus_method payload.bus must be session or system")
    if not isinstance(destination, str) or not destination.strip():
        raise ValueError("call_dbus_method payload.destination must be non-empty string")
    if not isinstance(object_path, str) or not object_path.strip():
        raise ValueError("call_dbus_method payload.object_path must be non-empty string")
    if not isinstance(interface, str) or not interface.strip():
        raise ValueError("call_dbus_method payload.interface must be non-empty string")
    if not isinstance(method, str) or not method.strip():
        raise ValueError("call_dbus_method payload.method must be non-empty string")
    if not isinstance(args_raw, list):
        raise ValueError("call_dbus_method payload.arguments must be list[string]")
    arguments: List[str] = []
    for item in args_raw:
        if not isinstance(item, str):
            raise ValueError("call_dbus_method payload.arguments must be list[string]")
        arguments.append(item)

    gdbus = shutil.which("gdbus")
    if gdbus is None:
        raise ValueError("gdbus not found on host")
    proc = _run_cmd(
        [
            gdbus,
            "call",
            f"--{bus}",
            "--dest",
            destination.strip(),
            "--object-path",
            object_path.strip(),
            "--method",
            f"{interface.strip()}.{method.strip()}",
            *arguments,
        ]
    )
    return {
        "bus": bus,
        "destination": destination.strip(),
        "object_path": object_path.strip(),
        "interface": interface.strip(),
        "method": method.strip(),
        "arguments": arguments,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "ok": proc.returncode == 0,
    }


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "list_desktop_entries": list_desktop_entries,
            "launch_desktop_entry": launch_desktop_entry,
            "run_cli_entry": run_cli_entry,
            "call_dbus_method": call_dbus_method,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
