#!/usr/bin/env python3
"""Semantic wrappers for the GNOME Calendar desktop application."""

from __future__ import annotations

import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve
from real_app_support import file_uri_from_path, require_gui_session, run_gdbus_method

DESTINATION = "org.gnome.Calendar"
OBJECT_PATH = "/org/gnome/Calendar"
INTERFACE = "org.freedesktop.Application"

ICS_DIR = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "linux-mcp" / "events"


def open_calendar(payload: Dict[str, Any]) -> Dict[str, Any]:
    del payload
    require_gui_session()
    result = run_gdbus_method(
        bus="session",
        destination=DESTINATION,
        object_path=OBJECT_PATH,
        interface=INTERFACE,
        method="Activate",
        arguments=["{}"],
    )
    return {"opened": result["ok"], **result}


def open_calendar_file(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    file_path = payload.get("path", "")
    if not isinstance(file_path, str) or not file_path.strip():
        raise ValueError("path must be non-empty string")
    uri = file_uri_from_path(file_path, expect_dir=False)
    result = run_gdbus_method(
        bus="session",
        destination=DESTINATION,
        object_path=OBJECT_PATH,
        interface=INTERFACE,
        method="Open",
        arguments=[f"['{uri}']", "{}"],
    )
    return {"opened": result["ok"], "path": str(Path(file_path).expanduser().resolve()), "uri": uri, **result}


def _parse_iso_to_utc(name: str, raw: Any, *, required: bool) -> datetime | None:
    if raw in ("", None):
        if required:
            raise ValueError(f"{name} must be a non-empty ISO-8601 datetime string")
        return None
    if not isinstance(raw, str):
        raise ValueError(f"{name} must be a string")
    try:
        dt = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be valid ISO-8601 (e.g. 2026-05-10T15:00:00+00:00)") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _ics_dt(dt: datetime) -> str:
    return dt.strftime("%Y%m%dT%H%M%SZ")


def _ics_escape(text: str) -> str:
    # RFC 5545 §3.3.11: backslash, comma, semicolon must be escaped;
    # newlines become literal "\n".
    return (
        text.replace("\\", "\\\\")
        .replace(";", "\\;")
        .replace(",", "\\,")
        .replace("\r\n", "\n")
        .replace("\n", "\\n")
    )


def _render_ics(*, uid: str, dtstart: datetime, dtend: datetime | None,
                summary: str, location: str, description: str) -> str:
    now = datetime.now(timezone.utc)
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//linux-mcp//gnome_event_create//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        "BEGIN:VEVENT",
        f"UID:{uid}",
        f"DTSTAMP:{_ics_dt(now)}",
        f"DTSTART:{_ics_dt(dtstart)}",
    ]
    if dtend is not None:
        lines.append(f"DTEND:{_ics_dt(dtend)}")
    lines.append(f"SUMMARY:{_ics_escape(summary)}")
    if location:
        lines.append(f"LOCATION:{_ics_escape(location)}")
    if description:
        lines.append(f"DESCRIPTION:{_ics_escape(description)}")
    lines += ["END:VEVENT", "END:VCALENDAR"]
    return "\r\n".join(lines) + "\r\n"


def gnome_event_create(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Add a single event to the real GNOME Calendar.

    We don't write the EDS calendar database directly (D-Bus surface is
    version-fragile and requires resolving a source registry). Instead
    we generate a standards-compliant .ics file in a stable cache dir
    and ask GNOME Calendar to open it via D-Bus — GNOME Calendar then
    presents an "Add to calendar" dialog which the user confirms with
    one click. That click is the real consent gate.
    """
    require_gui_session()
    title = payload.get("title", "")
    if not isinstance(title, str) or not title.strip():
        raise ValueError("gnome_event_create payload.title must be non-empty string")

    dtstart = _parse_iso_to_utc("start_time", payload.get("start_time"), required=True)
    dtend = _parse_iso_to_utc("end_time", payload.get("end_time"), required=False)
    location = payload.get("location", "") or ""
    notes = payload.get("notes", "") or ""
    if not isinstance(location, str) or not isinstance(notes, str):
        raise ValueError("location and notes must be strings")

    ICS_DIR.mkdir(parents=True, exist_ok=True)
    uid = f"linux-mcp-{_ics_dt(datetime.now(timezone.utc))}-{secrets.token_hex(4)}"
    ics_path = ICS_DIR / f"{uid}.ics"
    ics_path.write_text(
        _render_ics(
            uid=f"{uid}@linux-mcp",
            dtstart=dtstart,
            dtend=dtend,
            summary=title.strip(),
            location=location.strip(),
            description=notes.strip(),
        ),
        encoding="utf-8",
    )

    uri = file_uri_from_path(str(ics_path), expect_dir=False)
    result = run_gdbus_method(
        bus="session",
        destination=DESTINATION,
        object_path=OBJECT_PATH,
        interface=INTERFACE,
        method="Open",
        arguments=[f"['{uri}']", "{}"],
    )
    return {
        "event_uid": uid,
        "title": title.strip(),
        "start_time_utc": dtstart.isoformat(),
        "end_time_utc": dtend.isoformat() if dtend else "",
        "ics_path": str(ics_path),
        "opened": result["ok"],
        "note": "GNOME Calendar will show an 'Add to calendar' dialog — click Add to commit.",
        **result,
    }


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "open_calendar": open_calendar,
            "open_calendar_file": open_calendar_file,
            "gnome_event_create": gnome_event_create,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
