#!/usr/bin/env python3
"""Demo File Manager App exposed over UDS RPC."""

from __future__ import annotations

import hashlib
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
WORD_RE = re.compile(r"\b\w+\b", re.UNICODE)
MAX_READ_BYTES = 1024 * 1024
MAX_CONTENT_BYTES = 512 * 1024
MAX_ENTRIES_LIMIT = 1000
MAX_COPY_BYTES = 16 * 1024 * 1024
SUPPORTED_ALGOS = {"sha256", "sha1", "md5"}


def _resolve_repo_path(raw_path: str, *, allow_missing: bool = False) -> Path:
    p = Path(raw_path).expanduser()
    if p.is_absolute():
        raise ValueError("path must be relative")
    if any(part == ".." for part in p.parts):
        raise ValueError("path must not contain '..'")
    resolved = (ROOT_DIR / p).resolve()
    try:
        resolved.relative_to(ROOT_DIR)
    except ValueError as exc:
        raise ValueError("only allows paths under repo root") from exc
    if (not allow_missing) and (not resolved.exists()):
        raise ValueError(f"path not found: {resolved}")
    return resolved


def text_stats(payload: Dict[str, Any]) -> Dict[str, Any]:
    text = payload.get("text")
    if not isinstance(text, str):
        raise ValueError("text_stats payload.text must be string")
    words = WORD_RE.findall(text)
    lines = text.splitlines()
    non_empty_lines = [line for line in lines if line.strip()]
    return {
        "chars": len(text),
        "words": len(words),
        "unique_words": len({word.lower() for word in words}),
        "lines": len(lines) if text else 0,
        "non_empty_lines": len(non_empty_lines),
        "preview": text[:80],
    }


def _extract_preview_path(payload: Dict[str, Any]) -> str:
    raw_path = payload.get("path", "")
    if isinstance(raw_path, str) and raw_path.strip():
        return raw_path.strip()
    msg = payload.get("message", "")
    if not isinstance(msg, str):
        return "README.md"
    quoted = re.search(r"`([^`]+)`|\"([^\"]+)\"|'([^']+)'", msg)
    if quoted:
        for idx in (1, 2, 3):
            part = quoted.group(idx)
            if part:
                return part.strip()
    return "README.md"


def file_preview(payload: Dict[str, Any]) -> Dict[str, Any]:
    file_path = _resolve_repo_path(_extract_preview_path(payload))
    if not file_path.is_file():
        raise ValueError(f"file not found: {file_path}")
    max_lines = payload.get("max_lines", 30)
    if isinstance(max_lines, bool) or not isinstance(max_lines, int):
        raise ValueError("file_preview payload.max_lines must be integer")
    max_lines = max(1, min(200, max_lines))
    raw = file_path.read_bytes()[:MAX_READ_BYTES]
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    preview = lines[:max_lines]
    return {
        "path": str(file_path.relative_to(ROOT_DIR)),
        "size_bytes": file_path.stat().st_size,
        "preview_line_count": len(preview),
        "total_lines_sampled": len(lines),
        "truncated": len(lines) > max_lines,
        "preview": preview,
    }


def hash_text(payload: Dict[str, Any]) -> Dict[str, Any]:
    algorithm = payload.get("algorithm", "sha256")
    if not isinstance(algorithm, str):
        raise ValueError("hash_text payload.algorithm must be string")
    algorithm = algorithm.lower().strip()
    if algorithm not in SUPPORTED_ALGOS:
        raise ValueError(f"unsupported algorithm: {algorithm}")
    text = payload.get("text", "")
    if not isinstance(text, str):
        raise ValueError("hash_text payload.text must be string")
    if not text and isinstance(payload.get("message"), str):
        text = payload["message"]
    return {
        "algorithm": algorithm,
        "length": len(text),
        "digest": hashlib.new(algorithm, text.encode("utf-8")).hexdigest(),
    }


def file_create(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw_path = payload.get("path", "")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("file_create payload.path must be non-empty string")
    target = _resolve_repo_path(raw_path.strip(), allow_missing=True)
    if target.exists() and target.is_dir():
        raise ValueError(f"path is a directory: {target}")
    content = payload.get("content", "")
    if not isinstance(content, str):
        raise ValueError("file_create payload.content must be string")
    if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise ValueError(f"content too large (max {MAX_CONTENT_BYTES} bytes)")
    overwrite = payload.get("overwrite", False)
    create_parents = payload.get("create_parents", True)
    if not isinstance(overwrite, bool) or not isinstance(create_parents, bool):
        raise ValueError("overwrite/create_parents must be boolean")
    existed = target.exists()
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


def _entry_info(entry: Path) -> Dict[str, Any]:
    stat = entry.stat()
    return {"name": entry.name, "type": "dir" if entry.is_dir() else "file", "size_bytes": int(stat.st_size)}


def file_list(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw_path = payload.get("path", ".")
    if not isinstance(raw_path, str):
        raise ValueError("file_list payload.path must be string")
    max_entries = payload.get("max_entries", 100)
    if isinstance(max_entries, bool) or not isinstance(max_entries, int):
        raise ValueError("file_list payload.max_entries must be integer")
    max_entries = max(1, min(MAX_ENTRIES_LIMIT, max_entries))
    target = _resolve_repo_path(raw_path)
    rel_target = str(target.relative_to(ROOT_DIR))
    if target.is_file():
        return {"path": rel_target, "type": "file", "entries": [_entry_info(target)], "truncated": False, "entry_count": 1}
    entries: List[Dict[str, Any]] = []
    for child in sorted(target.iterdir(), key=lambda item: item.name):
        entries.append(_entry_info(child))
        if len(entries) >= max_entries:
            break
    total = sum(1 for _ in target.iterdir())
    return {
        "path": rel_target if rel_target else ".",
        "type": "dir",
        "entries": entries,
        "truncated": total > len(entries),
        "entry_count": len(entries),
        "total_entries": total,
    }


def file_delete(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw_path = payload.get("path", "")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("file_delete payload.path must be non-empty string")
    if raw_path.strip() in ("", ".", "./"):
        raise ValueError("file_delete path must not be repo root")
    target = _resolve_repo_path(raw_path.strip(), allow_missing=True)
    recursive = payload.get("recursive", False)
    allow_missing = payload.get("allow_missing", False)
    if not isinstance(recursive, bool) or not isinstance(allow_missing, bool):
        raise ValueError("recursive/allow_missing must be boolean")
    rel_target = str(target.relative_to(ROOT_DIR))
    if not target.exists():
        if allow_missing:
            return {"path": rel_target, "deleted": False, "missing": True}
        raise ValueError(f"path not found: {rel_target}")
    if target.is_dir():
        if not recursive:
            raise ValueError("directory deletion requires recursive=true")
        shutil.rmtree(target)
        return {"path": rel_target, "deleted": True, "type": "dir"}
    target.unlink()
    return {"path": rel_target, "deleted": True, "type": "file"}


def file_copy(payload: Dict[str, Any]) -> Dict[str, Any]:
    src_raw = payload.get("src_path", "")
    dst_raw = payload.get("dst_path", "")
    if not isinstance(src_raw, str) or not src_raw.strip():
        raise ValueError("file_copy payload.src_path must be non-empty string")
    if not isinstance(dst_raw, str) or not dst_raw.strip():
        raise ValueError("file_copy payload.dst_path must be non-empty string")
    overwrite = payload.get("overwrite", False)
    create_parents = payload.get("create_parents", True)
    if not isinstance(overwrite, bool) or not isinstance(create_parents, bool):
        raise ValueError("overwrite/create_parents must be boolean")
    src = _resolve_repo_path(src_raw.strip())
    dst = _resolve_repo_path(dst_raw.strip(), allow_missing=True)
    if src.is_dir() or not src.is_file():
        raise ValueError(f"source is not a file: {src}")
    if src.stat().st_size > MAX_COPY_BYTES:
        raise ValueError(f"source file too large (max {MAX_COPY_BYTES} bytes)")
    dst_existed = dst.exists()
    if dst_existed:
        if dst.is_dir():
            raise ValueError(f"destination is a directory: {dst}")
        if not overwrite:
            raise ValueError(f"destination exists: {dst.relative_to(ROOT_DIR)}")
    elif create_parents:
        dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return {
        "src_path": str(src.relative_to(ROOT_DIR)),
        "dst_path": str(dst.relative_to(ROOT_DIR)),
        "size_bytes": dst.stat().st_size,
        "overwritten": dst_existed,
    }


def file_rename(payload: Dict[str, Any]) -> Dict[str, Any]:
    src_raw = payload.get("src_path", "")
    dst_raw = payload.get("dst_path", "")
    if not isinstance(src_raw, str) or not src_raw.strip():
        raise ValueError("file_rename payload.src_path must be non-empty string")
    if not isinstance(dst_raw, str) or not dst_raw.strip():
        raise ValueError("file_rename payload.dst_path must be non-empty string")
    overwrite = payload.get("overwrite", False)
    create_parents = payload.get("create_parents", True)
    if not isinstance(overwrite, bool) or not isinstance(create_parents, bool):
        raise ValueError("overwrite/create_parents must be boolean")
    src = _resolve_repo_path(src_raw.strip())
    dst = _resolve_repo_path(dst_raw.strip(), allow_missing=True)
    if not src.is_file():
        raise ValueError(f"source is not a file: {src}")
    if src == dst:
        raise ValueError("source and destination are identical")
    dst_existed = dst.exists()
    if dst_existed and dst.is_dir():
        raise ValueError(f"destination is a directory: {dst}")
    if dst_existed and not overwrite:
        raise ValueError(f"destination exists: {dst.relative_to(ROOT_DIR)}")
    if (not dst_existed) and create_parents:
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


OPERATIONS = {
    "text_stats": text_stats,
    "file_preview": file_preview,
    "hash_text": hash_text,
    "file_create": file_create,
    "file_list": file_list,
    "file_delete": file_delete,
    "file_copy": file_copy,
    "file_rename": file_rename,
}


def main() -> int:
    args = parse_args()
    return serve(args.manifest, OPERATIONS)


if __name__ == "__main__":
    raise SystemExit(main())
