#!/usr/bin/env python3
"""Demo Notes App exposed over UDS RPC."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = ROOT_DIR / "tool-app" / "demo_data" / "notes"
MAX_NOTE_BODY_BYTES = 128 * 1024
MAX_RESULTS = 100
SLUG_RE = re.compile(r"[^a-z0-9]+")


def _ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _clean_segment(raw: str, *, field_name: str, fallback: str) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"{field_name} must be string")
    cleaned = SLUG_RE.sub("-", raw.lower().strip()).strip("-")
    return cleaned or fallback


def _note_path(note_id: str) -> Path:
    if not isinstance(note_id, str) or not note_id.strip():
        raise ValueError("note_id must be non-empty string")
    rel = Path(note_id.strip())
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("note_id must be relative")
    path = (DATA_DIR / rel).with_suffix(".json")
    try:
        path.resolve().relative_to(DATA_DIR.resolve())
    except ValueError as exc:
        raise ValueError("note_id escapes notes data dir") from exc
    return path


def _load_note(path: Path) -> Dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"invalid note record: {path}")
    return raw


def _iter_notes() -> List[Dict[str, Any]]:
    _ensure_data_dir()
    notes: List[Dict[str, Any]] = []
    for path in sorted(DATA_DIR.rglob("*.json")):
        note = _load_note(path)
        note["storage_path"] = str(path.relative_to(DATA_DIR))
        notes.append(note)
    return notes


def note_create(payload: Dict[str, Any]) -> Dict[str, Any]:
    title = payload.get("title")
    body = payload.get("body")
    if not isinstance(title, str) or not title.strip():
        raise ValueError("note_create payload.title must be non-empty string")
    if not isinstance(body, str):
        raise ValueError("note_create payload.body must be string")
    if len(body.encode("utf-8")) > MAX_NOTE_BODY_BYTES:
        raise ValueError(f"note body too large (max {MAX_NOTE_BODY_BYTES} bytes)")

    notebook = _clean_segment(payload.get("notebook", "inbox"), field_name="notebook", fallback="inbox")
    title_slug = _clean_segment(title, field_name="title", fallback="note")
    tags_raw = payload.get("tags", [])
    if not isinstance(tags_raw, list):
        raise ValueError("note_create payload.tags must be list[string]")
    tags: List[str] = []
    for item in tags_raw:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("note_create payload.tags must be list[string]")
        tags.append(item.strip())

    now = datetime.now(timezone.utc)
    note_id = f"{notebook}/{title_slug}-{now.strftime('%Y%m%d-%H%M%S')}"
    target = _note_path(note_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "note_id": note_id,
        "title": title.strip(),
        "body": body,
        "notebook": notebook,
        "tags": tags,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }
    target.write_text(json.dumps(record, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return {
        "note_id": note_id,
        "title": record["title"],
        "notebook": notebook,
        "tag_count": len(tags),
        "size_bytes": target.stat().st_size,
    }


def note_list(payload: Dict[str, Any]) -> Dict[str, Any]:
    notebook_filter = payload.get("notebook", "")
    tag_filter = payload.get("tag", "")
    limit = payload.get("limit", 20)
    if not isinstance(notebook_filter, str) or not isinstance(tag_filter, str):
        raise ValueError("note_list filters must be strings")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("note_list payload.limit must be integer")
    limit = max(1, min(MAX_RESULTS, limit))

    items = []
    for note in reversed(_iter_notes()):
        if notebook_filter and note.get("notebook") != notebook_filter.strip():
            continue
        if tag_filter and tag_filter.strip() not in note.get("tags", []):
            continue
        items.append(
            {
                "note_id": note.get("note_id", ""),
                "title": note.get("title", ""),
                "notebook": note.get("notebook", ""),
                "tags": note.get("tags", []),
                "updated_at": note.get("updated_at", ""),
            }
        )
        if len(items) >= limit:
            break
    return {"count": len(items), "items": items}


def note_read(payload: Dict[str, Any]) -> Dict[str, Any]:
    target = _note_path(payload.get("note_id", ""))
    if not target.exists():
        raise ValueError(f"note not found: {payload.get('note_id', '')}")
    note = _load_note(target)
    return {
        "note_id": note.get("note_id", ""),
        "title": note.get("title", ""),
        "notebook": note.get("notebook", ""),
        "tags": note.get("tags", []),
        "body": note.get("body", ""),
        "created_at": note.get("created_at", ""),
        "updated_at": note.get("updated_at", ""),
    }


def note_search(payload: Dict[str, Any]) -> Dict[str, Any]:
    query = payload.get("query", "")
    notebook_filter = payload.get("notebook", "")
    limit = payload.get("limit", 10)
    if not isinstance(query, str) or not query.strip():
        raise ValueError("note_search payload.query must be non-empty string")
    if not isinstance(notebook_filter, str):
        raise ValueError("note_search payload.notebook must be string")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("note_search payload.limit must be integer")
    limit = max(1, min(MAX_RESULTS, limit))
    needle = query.strip().lower()

    matches = []
    for note in reversed(_iter_notes()):
        if notebook_filter and note.get("notebook") != notebook_filter.strip():
            continue
        haystack = " ".join(
            [
                str(note.get("title", "")),
                str(note.get("body", "")),
                " ".join(note.get("tags", [])),
            ]
        ).lower()
        if needle not in haystack:
            continue
        body = str(note.get("body", ""))
        idx = body.lower().find(needle)
        excerpt = body[max(idx - 30, 0) : idx + 70].replace("\n", " ").strip() if idx >= 0 else body[:100]
        matches.append(
            {
                "note_id": note.get("note_id", ""),
                "title": note.get("title", ""),
                "notebook": note.get("notebook", ""),
                "tags": note.get("tags", []),
                "excerpt": excerpt,
            }
        )
        if len(matches) >= limit:
            break
    return {"query": query.strip(), "count": len(matches), "items": matches}


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "note_create": note_create,
            "note_list": note_list,
            "note_read": note_read,
            "note_search": note_search,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
