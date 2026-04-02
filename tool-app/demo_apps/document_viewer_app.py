#!/usr/bin/env python3
"""Semantic wrappers for the Evince document viewer."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve
from real_app_support import find_executable, optional_int, require_gui_session, require_non_empty_string, spawn_detached


def _document_args(raw_path: str, *, page_index: int | None = None) -> List[str]:
    path = Path(raw_path).expanduser().resolve()
    if not path.exists():
        raise ValueError(f"path does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"path is not a file: {path}")
    evince = find_executable("evince")
    args = [evince]
    if page_index is not None:
        if page_index < 1:
            raise ValueError("page_index must be >= 1")
        args.extend(["--page-index", str(page_index - 1)])
    args.append(str(path))
    return args


def open_document(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    file_path = require_non_empty_string(payload, "path")
    args = _document_args(file_path)
    proc = spawn_detached(args)
    return {"opened": True, "path": str(Path(file_path).expanduser().resolve()), "pid": proc.pid}


def open_document_page(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    file_path = require_non_empty_string(payload, "path")
    page_index = optional_int(payload, "page_index")
    if page_index is None:
        raise ValueError("page_index must be integer")
    args = _document_args(file_path, page_index=page_index)
    proc = spawn_detached(args)
    return {
        "opened": True,
        "path": str(Path(file_path).expanduser().resolve()),
        "page_index": page_index,
        "pid": proc.pid,
    }


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "open_document": open_document,
            "open_document_page": open_document_page,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
