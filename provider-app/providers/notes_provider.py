#!/usr/bin/env python3
"""Sample notes provider for manifest-only onboarding under external.write."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
NOTES_ROOT = ROOT_DIR / "tmp" / "provider-notes"


def _resolve_note_path(raw_path: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("path must be non-empty string")
    candidate = Path(raw_path.strip())
    if candidate.is_absolute():
        raise ValueError("path must be relative")
    if any(part == ".." for part in candidate.parts):
        raise ValueError("path must not contain '..'")
    resolved = (NOTES_ROOT / candidate).resolve()
    try:
        resolved.relative_to(NOTES_ROOT)
    except ValueError as exc:
        raise ValueError("path escapes notes root") from exc
    return resolved


def write_note(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("write_note payload must be object")

    note = payload.get("note", "")
    if not isinstance(note, str) or not note.strip():
        raise ValueError("write_note payload.note must be non-empty string")
    path = _resolve_note_path(str(payload.get("path", "inbox/notes.log")))
    append = payload.get("append", True)
    if not isinstance(append, bool):
        raise ValueError("write_note payload.append must be boolean")

    tags_raw = payload.get("tags", [])
    if not isinstance(tags_raw, list) or any(not isinstance(item, str) for item in tags_raw):
        raise ValueError("write_note payload.tags must be a list of strings")
    tags: List[str] = [item.strip() for item in tags_raw if item.strip()]

    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "note": note.strip(),
        "tags": tags,
    }
    encoded = json.dumps(entry, ensure_ascii=True) + "\n"
    mode = "a" if append else "w"
    with path.open(mode, encoding="utf-8") as handle:
        handle.write(encoded)

    return {
        "path": str(path.relative_to(ROOT_DIR)),
        "append": append,
        "bytes_written": len(encoded.encode("utf-8")),
        "tags": tags,
        "note_preview": note.strip()[:80],
    }


HANDLERS: Dict[str, Callable[[Any], Dict[str, Any]]] = {
    "write_note": write_note,
}
