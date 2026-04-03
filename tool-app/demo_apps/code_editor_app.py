#!/usr/bin/env python3
"""Semantic wrappers for Visual Studio Code."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve
from real_app_support import (
    find_executable,
    optional_int,
    require_gui_session,
    require_non_empty_string,
    resolve_existing_path,
    spawn_detached,
)


def _code_args_for_path(path: Path, *, line: int | None = None, column: int | None = None) -> List[str]:
    code = find_executable("code")
    if line is None:
        return [code, str(path)]
    if line < 1:
        raise ValueError("line must be >= 1")
    if column is not None and column < 1:
        raise ValueError("column must be >= 1")
    goto = f"{path}:{line}"
    if column is not None:
        goto = f"{goto}:{column}"
    return [code, "--goto", goto]


def open_path(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    path = resolve_existing_path(require_non_empty_string(payload, "path"))
    proc = spawn_detached(_code_args_for_path(path))
    return {"opened": True, "path": str(path), "pid": proc.pid}


def open_file_at_line(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    path = resolve_existing_path(require_non_empty_string(payload, "path"))
    if not path.is_file():
        raise ValueError(f"path is not a file: {path}")
    line = optional_int(payload, "line")
    if line is None:
        raise ValueError("line must be integer")
    column = optional_int(payload, "column")
    proc = spawn_detached(_code_args_for_path(path, line=line, column=column))
    return {"opened": True, "path": str(path), "line": line, "column": column, "pid": proc.pid}


def compare_files(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    left_path = resolve_existing_path(require_non_empty_string(payload, "left_path"))
    right_path = resolve_existing_path(require_non_empty_string(payload, "right_path"))
    code = find_executable("code")
    proc = spawn_detached([code, "--diff", str(left_path), str(right_path)])
    return {"opened": True, "left_path": str(left_path), "right_path": str(right_path), "pid": proc.pid}


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "open_path": open_path,
            "open_file_at_line": open_file_at_line,
            "compare_files": compare_files,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
