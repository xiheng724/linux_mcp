#!/usr/bin/env python3
"""Demo Contacts App exposed over UDS RPC."""

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
DATA_DIR = ROOT_DIR / "tool-app" / "demo_data" / "contacts"
CONTACTS_FILE = DATA_DIR / "contacts.json"
MAX_CONTACTS_RETURNED = 100


def _ensure_store() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not CONTACTS_FILE.exists():
        CONTACTS_FILE.write_text("[]\n", encoding="utf-8")


def _load_contacts() -> List[Dict[str, Any]]:
    _ensure_store()
    raw = json.loads(CONTACTS_FILE.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("contacts store must be list")
    return [item for item in raw if isinstance(item, dict)]


def _save_contacts(contacts: List[Dict[str, Any]]) -> None:
    CONTACTS_FILE.write_text(json.dumps(contacts, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def _normalize_text(name: str, value: Any, *, required: bool = False) -> str:
    if value in ("", None):
        if required:
            raise ValueError(f"{name} must be non-empty string")
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{name} must be string")
    text = value.strip()
    if required and not text:
        raise ValueError(f"{name} must be non-empty string")
    return text


def contact_add(payload: Dict[str, Any]) -> Dict[str, Any]:
    name = _normalize_text("name", payload.get("name"), required=True)
    now = datetime.now(timezone.utc)
    contact = {
        "contact_id": f"contact-{now.strftime('%Y%m%d-%H%M%S')}",
        "name": name,
        "email": _normalize_text("email", payload.get("email")),
        "phone": _normalize_text("phone", payload.get("phone")),
        "company": _normalize_text("company", payload.get("company")),
        "notes": _normalize_text("notes", payload.get("notes")),
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }
    contacts = _load_contacts()
    contacts.append(contact)
    _save_contacts(contacts)
    return contact


def contact_list(payload: Dict[str, Any]) -> Dict[str, Any]:
    company = _normalize_text("company", payload.get("company"))
    limit = payload.get("limit", 20)
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("contact_list payload.limit must be integer")
    limit = max(1, min(MAX_CONTACTS_RETURNED, limit))

    items = []
    for contact in _load_contacts():
        if company and contact.get("company") != company:
            continue
        items.append(contact)
        if len(items) >= limit:
            break
    return {"count": len(items), "items": items}


def contact_find(payload: Dict[str, Any]) -> Dict[str, Any]:
    query = _normalize_text("query", payload.get("query"), required=True).lower()
    limit = payload.get("limit", 10)
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("contact_find payload.limit must be integer")
    limit = max(1, min(MAX_CONTACTS_RETURNED, limit))

    items = []
    for contact in _load_contacts():
        haystack = " ".join(
            [
                str(contact.get("name", "")),
                str(contact.get("email", "")),
                str(contact.get("phone", "")),
                str(contact.get("company", "")),
                str(contact.get("notes", "")),
            ]
        ).lower()
        if query not in haystack:
            continue
        items.append(contact)
        if len(items) >= limit:
            break
    return {"query": query, "count": len(items), "items": items}


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "contact_add": contact_add,
            "contact_list": contact_list,
            "contact_find": contact_find,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
