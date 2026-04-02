#!/usr/bin/env python3
"""Shared desktop entry discovery helpers for real-app bridge services."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Set

DESKTOP_DIRS = [
    Path.home() / ".local/share/applications",
    Path("/usr/local/share/applications"),
    Path("/usr/share/applications"),
]
FIELD_RE = re.compile(r"%[fFuUdDnNickvm]")


def has_gui_session() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _normalize_match_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _desktop_stem(desktop_id: str) -> str:
    return _normalize_match_text(desktop_id[:-8] if desktop_id.endswith(".desktop") else desktop_id)


def _match_keys(data: Dict[str, str], desktop_id: str, executable: str) -> List[str]:
    keys: Set[str] = set()
    for raw in (
        data.get("Name", ""),
        data.get("GenericName", ""),
        executable,
        Path(executable).name,
        desktop_id,
        _desktop_stem(desktop_id),
    ):
        normalized = _normalize_match_text(raw)
        if normalized:
            keys.add(normalized)
    keywords_raw = data.get("Keywords", "")
    for keyword in keywords_raw.split(";"):
        normalized = _normalize_match_text(keyword)
        if normalized:
            keys.add(normalized)
    return sorted(keys)


def parse_desktop_file(path: Path) -> Dict[str, Any] | None:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    in_entry = False
    data: Dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            in_entry = line == "[Desktop Entry]"
            continue
        if not in_entry or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in ("Name", "GenericName", "Keywords", "Exec", "NoDisplay", "Terminal", "Type"):
            data[key] = value.strip()
    if data.get("Type", "Application") != "Application":
        return None
    if data.get("NoDisplay", "").lower() == "true":
        return None
    exec_line = data.get("Exec", "")
    name = data.get("Name", "")
    if not exec_line or not name:
        return None
    desktop_id = path.name
    command = FIELD_RE.sub("", exec_line).replace("%%", "%").strip()
    argv = command.split()
    if not argv:
        return None
    executable = argv[0]
    return {
        "desktop_id": desktop_id,
        "name": name,
        "generic_name": data.get("GenericName", ""),
        "exec": exec_line,
        "command": command,
        "executable": executable,
        "path": str(path),
        "terminal": data.get("Terminal", "").lower() == "true",
        "match_keys": _match_keys(data, desktop_id, executable),
    }


def iter_desktop_apps() -> List[Dict[str, Any]]:
    apps: Dict[str, Dict[str, Any]] = {}
    for directory in DESKTOP_DIRS:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.desktop")):
            parsed = parse_desktop_file(path)
            if parsed is None:
                continue
            apps.setdefault(parsed["desktop_id"], parsed)
    return sorted(apps.values(), key=lambda item: (item["name"].lower(), item["desktop_id"]))


def find_desktop_app(*, desktop_id: str = "", name: str = "", executable: str = "") -> Dict[str, Any]:
    desktop_id = desktop_id.strip()
    name = _normalize_match_text(name)
    executable = executable.strip()
    if not any((desktop_id, name, executable)):
        raise ValueError("must provide desktop_id, name, or executable")

    matches: List[Dict[str, Any]] = []
    for app in iter_desktop_apps():
        if desktop_id and app["desktop_id"] == desktop_id:
            return app
        if executable and app["executable"] == executable:
            matches.append(app)
            continue
        if name and name in app.get("match_keys", []):
            matches.append(app)
    if not matches:
        raise ValueError("launchable app not found")
    if len(matches) > 1:
        raise ValueError(
            "launchable app is ambiguous: " + ", ".join(item["desktop_id"] for item in matches[:5])
        )
    return matches[0]
