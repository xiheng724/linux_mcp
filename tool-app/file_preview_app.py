#!/usr/bin/env python3
"""File preview tool app with repo-root path guard."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict

ROOT_DIR = Path(__file__).resolve().parent.parent
MAX_READ_BYTES = 1024 * 1024


def _extract_path(payload: Dict[str, Any]) -> str:
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


def _resolve_path(raw_path: str) -> Path:
    p = Path(raw_path).expanduser()
    if p.is_absolute():
        resolved = p.resolve()
    else:
        resolved = (ROOT_DIR / p).resolve()
    try:
        resolved.relative_to(ROOT_DIR)
    except ValueError as exc:
        raise ValueError("file_preview only allows files under repo root") from exc
    if not resolved.is_file():
        raise ValueError(f"file not found: {resolved}")
    return resolved


def run(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("file_preview payload must be object")

    raw_path = _extract_path(payload)
    file_path = _resolve_path(raw_path)

    max_lines = payload.get("max_lines", 30)
    if isinstance(max_lines, bool) or not isinstance(max_lines, int):
        raise ValueError("file_preview payload.max_lines must be integer")
    if max_lines < 1:
        max_lines = 1
    if max_lines > 200:
        max_lines = 200

    raw = file_path.read_bytes()[:MAX_READ_BYTES]
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    preview = lines[:max_lines]
    truncated = len(lines) > max_lines

    return {
        "path": str(file_path.relative_to(ROOT_DIR)),
        "size_bytes": file_path.stat().st_size,
        "preview_line_count": len(preview),
        "total_lines_sampled": len(lines),
        "truncated": truncated,
        "preview": preview,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdin-json", action="store_true")
    args = parser.parse_args()

    try:
        if args.stdin_json:
            payload = json.loads(sys.stdin.read())
        else:
            payload = {}
        print(json.dumps(run(payload), ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
