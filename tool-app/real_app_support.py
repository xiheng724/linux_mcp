#!/usr/bin/env python3
"""Shared helpers for semantic wrappers around real Linux desktop apps."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse

from desktop_catalog import has_gui_session

ALLOWED_URI_SCHEMES = {"file", "mailto", "http", "https", "webcal", "webcals"}


def require_gui_session() -> None:
    if not has_gui_session():
        raise ValueError("no GUI session available (DISPLAY/WAYLAND_DISPLAY unset)")


def require_string(payload: Dict[str, Any], field: str) -> str:
    value = payload.get(field, "")
    if not isinstance(value, str):
        raise ValueError(f"{field} must be string")
    return value


def require_non_empty_string(payload: Dict[str, Any], field: str) -> str:
    value = require_string(payload, field).strip()
    if not value:
        raise ValueError(f"{field} must be non-empty string")
    return value


def optional_string(payload: Dict[str, Any], field: str) -> str:
    return require_string(payload, field).strip()


def optional_int(payload: Dict[str, Any], field: str) -> int | None:
    value = payload.get(field)
    if value in (None, ""):
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be integer")
    return value


def resolve_existing_path(raw_path: str, *, expect_dir: bool | None = None) -> Path:
    path = Path(raw_path).expanduser().resolve()
    if not path.exists():
        raise ValueError(f"path does not exist: {path}")
    if expect_dir is True and not path.is_dir():
        raise ValueError(f"path is not a directory: {path}")
    if expect_dir is False and not path.is_file():
        raise ValueError(f"path is not a file: {path}")
    return path


def file_uri_from_path(raw_path: str, *, expect_dir: bool | None = None) -> str:
    return resolve_existing_path(raw_path, expect_dir=expect_dir).as_uri()


def normalize_uri_or_path(value: str, *, expect_existing_file: bool = False) -> str:
    value = value.strip()
    if not value:
        raise ValueError("uri must be non-empty string")
    parsed = urlparse(value)
    if parsed.scheme:
        if parsed.scheme not in ALLOWED_URI_SCHEMES:
            raise ValueError(f"unsupported URI scheme: {parsed.scheme}")
        return value
    return file_uri_from_path(value, expect_dir=False if expect_existing_file else None)


def find_executable(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise ValueError(f"executable not found on host: {name}")
    return resolved


def spawn_detached(args: List[str]) -> subprocess.Popen[str]:
    return subprocess.Popen(  # noqa: S603
        args,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )


def run_cmd(args: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)  # noqa: S603


def run_gdbus_method(
    *,
    bus: str,
    destination: str,
    object_path: str,
    interface: str,
    method: str,
    arguments: Iterable[str] = (),
) -> Dict[str, Any]:
    gdbus = find_executable("gdbus")
    proc = run_cmd(
        [
            gdbus,
            "call",
            f"--{bus}",
            "--dest",
            destination,
            "--object-path",
            object_path,
            "--method",
            f"{interface}.{method}",
            *list(arguments),
        ]
    )
    return {
        "bus": bus,
        "destination": destination,
        "object_path": object_path,
        "interface": interface,
        "method": method,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "ok": proc.returncode == 0,
    }


def thunderbird_compose_value(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"
