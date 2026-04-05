#!/usr/bin/env python3
"""Demo Workspace App exposed over UDS RPC."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
MAX_READ_BYTES = 1024 * 1024
MAX_CONTENT_BYTES = 1024 * 1024
MAX_ENTRIES_LIMIT = 1000


def _resolve_repo_path(raw_path: str, *, allow_missing: bool = False) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("path must be non-empty string")
    rel = Path(raw_path.strip()).expanduser()
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("path must stay under repo root")
    resolved = (ROOT_DIR / rel).resolve()
    try:
        resolved.relative_to(ROOT_DIR)
    except ValueError as exc:
        raise ValueError("path escapes repo root") from exc
    if not allow_missing and not resolved.exists():
        raise ValueError(f"path not found: {raw_path}")
    return resolved


def _entry_info(entry: Path) -> Dict[str, Any]:
    stat = entry.stat()
    return {
        "name": entry.name,
        "type": "dir" if entry.is_dir() else "file",
        "size_bytes": int(stat.st_size),
    }


def workspace_overview(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw_path = payload.get("path", ".")
    max_entries = payload.get("max_entries", 30)
    if not isinstance(raw_path, str):
        raise ValueError("workspace_overview payload.path must be string")
    if isinstance(max_entries, bool) or not isinstance(max_entries, int):
        raise ValueError("workspace_overview payload.max_entries must be integer")
    max_entries = max(1, min(MAX_ENTRIES_LIMIT, max_entries))
    target = _resolve_repo_path(raw_path)
    rel_target = str(target.relative_to(ROOT_DIR)) or "."
    if target.is_file():
        return {"path": rel_target, "type": "file", "entries": [_entry_info(target)], "entry_count": 1}

    entries: List[Dict[str, Any]] = []
    total_dirs = 0
    total_files = 0
    for child in sorted(target.iterdir(), key=lambda item: item.name):
        if child.is_dir():
            total_dirs += 1
        else:
            total_files += 1
        if len(entries) < max_entries:
            entries.append(_entry_info(child))

    return {
        "path": rel_target,
        "type": "dir",
        "entry_count": len(entries),
        "total_dirs": total_dirs,
        "total_files": total_files,
        "truncated": (total_dirs + total_files) > len(entries),
        "entries": entries,
    }


def read_document(payload: Dict[str, Any]) -> Dict[str, Any]:
    target = _resolve_repo_path(payload.get("path", ""))
    if not target.is_file():
        raise ValueError(f"file not found: {target.relative_to(ROOT_DIR)}")
    start_line = payload.get("start_line", 1)
    max_lines = payload.get("max_lines", 40)
    if isinstance(start_line, bool) or not isinstance(start_line, int) or start_line <= 0:
        raise ValueError("read_document payload.start_line must be positive integer")
    if isinstance(max_lines, bool) or not isinstance(max_lines, int):
        raise ValueError("read_document payload.max_lines must be integer")
    max_lines = max(1, min(200, max_lines))

    raw = target.read_bytes()[:MAX_READ_BYTES]
    text = raw.decode("utf-8", errors="replace")
    all_lines = text.splitlines()
    start_idx = min(len(all_lines), start_line - 1)
    excerpt = all_lines[start_idx : start_idx + max_lines]
    numbered = [{"line": start_idx + idx + 1, "text": line} for idx, line in enumerate(excerpt)]
    return {
        "path": str(target.relative_to(ROOT_DIR)),
        "start_line": start_idx + 1 if all_lines else 1,
        "line_count": len(numbered),
        "truncated": (start_idx + max_lines) < len(all_lines),
        "lines": numbered,
    }


def write_document(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw_path = payload.get("path", "")
    content = payload.get("content", "")
    overwrite = payload.get("overwrite", False)
    create_parents = payload.get("create_parents", True)
    if not isinstance(content, str):
        raise ValueError("write_document payload.content must be string")
    if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise ValueError(f"content too large (max {MAX_CONTENT_BYTES} bytes)")
    if not isinstance(overwrite, bool) or not isinstance(create_parents, bool):
        raise ValueError("overwrite/create_parents must be boolean")

    target = _resolve_repo_path(raw_path, allow_missing=True)
    existed = target.exists()
    if existed and target.is_dir():
        raise ValueError(f"path is a directory: {target.relative_to(ROOT_DIR)}")
    if existed and not overwrite:
        raise ValueError(f"file already exists: {target.relative_to(ROOT_DIR)}")
    if create_parents:
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {
        "path": str(target.relative_to(ROOT_DIR)),
        "created": not existed,
        "overwritten": existed,
        "size_bytes": target.stat().st_size,
    }


def move_document(payload: Dict[str, Any]) -> Dict[str, Any]:
    src_path = payload.get("src_path", "")
    dst_path = payload.get("dst_path", "")
    overwrite = payload.get("overwrite", False)
    create_parents = payload.get("create_parents", True)
    if not isinstance(overwrite, bool) or not isinstance(create_parents, bool):
        raise ValueError("overwrite/create_parents must be boolean")
    src = _resolve_repo_path(src_path)
    dst = _resolve_repo_path(dst_path, allow_missing=True)
    if not src.is_file():
        raise ValueError(f"source is not a file: {src.relative_to(ROOT_DIR)}")
    if src == dst:
        raise ValueError("source and destination are identical")
    dst_existed = dst.exists()
    if dst_existed and dst.is_dir():
        raise ValueError(f"destination is a directory: {dst.relative_to(ROOT_DIR)}")
    if dst_existed and not overwrite:
        raise ValueError(f"destination exists: {dst.relative_to(ROOT_DIR)}")
    if not dst_existed and create_parents:
        dst.parent.mkdir(parents=True, exist_ok=True)
    if dst_existed:
        dst.unlink()
    src.rename(dst)
    return {
        "src_path": str(src.relative_to(ROOT_DIR)),
        "dst_path": str(dst.relative_to(ROOT_DIR)),
        "moved": True,
        "overwritten": dst_existed,
    }


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "workspace_overview": workspace_overview,
            "read_document": read_document,
            "write_document": write_document,
            "move_document": move_document,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
