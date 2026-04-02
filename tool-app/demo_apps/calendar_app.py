#!/usr/bin/env python3
"""Demo Calendar App exposed over UDS RPC."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = ROOT_DIR / "tool-app" / "demo_data" / "calendar"
EVENTS_FILE = DATA_DIR / "events.json"
MAX_EVENTS_RETURNED = 100


def _ensure_store() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not EVENTS_FILE.exists():
        EVENTS_FILE.write_text("[]\n", encoding="utf-8")


def _load_events() -> List[Dict[str, Any]]:
    _ensure_store()
    raw = json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("calendar store must be list")
    return [item for item in raw if isinstance(item, dict)]


def _save_events(events: List[Dict[str, Any]]) -> None:
    EVENTS_FILE.write_text(json.dumps(events, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def _normalize_text(name: str, value: Any, *, default: str = "") -> str:
    if value in ("", None):
        return default
    if not isinstance(value, str):
        raise ValueError(f"{name} must be string")
    return value.strip()


def _parse_time(name: str, value: Any, *, required: bool) -> str:
    if value in ("", None):
        if required:
            raise ValueError(f"{name} must be non-empty ISO-8601 string")
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{name} must be string")
    text = value.strip()
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be valid ISO-8601 time") from exc
    return text


def event_create(payload: Dict[str, Any]) -> Dict[str, Any]:
    title = _normalize_text("title", payload.get("title"))
    if not title:
        raise ValueError("event_create payload.title must be non-empty string")
    start_time = _parse_time("start_time", payload.get("start_time"), required=True)
    end_time = _parse_time("end_time", payload.get("end_time"), required=False)
    calendar = _normalize_text("calendar", payload.get("calendar"), default="default") or "default"
    now = datetime.now(timezone.utc)
    event = {
        "event_id": f"{calendar.lower().replace(' ', '-')}-{now.strftime('%Y%m%d-%H%M%S')}",
        "title": title,
        "start_time": start_time,
        "end_time": end_time,
        "location": _normalize_text("location", payload.get("location")),
        "notes": _normalize_text("notes", payload.get("notes")),
        "calendar": calendar,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }
    events = _load_events()
    events.append(event)
    _save_events(events)
    return event


def event_list(payload: Dict[str, Any]) -> Dict[str, Any]:
    calendar = _normalize_text("calendar", payload.get("calendar"))
    date_prefix = _normalize_text("date", payload.get("date"))
    query = _normalize_text("query", payload.get("query"))
    limit = payload.get("limit", 20)
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("event_list payload.limit must be integer")
    limit = max(1, min(MAX_EVENTS_RETURNED, limit))
    needle = query.lower()

    items = []
    for event in sorted(_load_events(), key=lambda item: str(item.get("start_time", ""))):
        if calendar and event.get("calendar") != calendar:
            continue
        if date_prefix and not str(event.get("start_time", "")).startswith(date_prefix):
            continue
        if needle:
            haystack = " ".join(
                [
                    str(event.get("title", "")),
                    str(event.get("location", "")),
                    str(event.get("notes", "")),
                    str(event.get("calendar", "")),
                ]
            ).lower()
            if needle not in haystack:
                continue
        items.append(event)
        if len(items) >= limit:
            break
    return {"count": len(items), "items": items}


def event_update(payload: Dict[str, Any]) -> Dict[str, Any]:
    event_id = _normalize_text("event_id", payload.get("event_id"))
    if not event_id:
        raise ValueError("event_update payload.event_id must be non-empty string")
    events = _load_events()
    target = None
    for event in events:
        if event.get("event_id") == event_id:
            target = event
            break
    if target is None:
        raise ValueError(f"event not found: {event_id}")

    for key in ("title", "location", "notes", "calendar"):
        if key in payload:
            target[key] = _normalize_text(key, payload.get(key))
    if "start_time" in payload:
        target["start_time"] = _parse_time("start_time", payload.get("start_time"), required=True)
    if "end_time" in payload:
        target["end_time"] = _parse_time("end_time", payload.get("end_time"), required=False)
    target["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save_events(events)
    return target


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "event_create": event_create,
            "event_list": event_list,
            "event_update": event_update,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
