#!/usr/bin/env python3
"""Demo Planner App exposed over UDS RPC."""

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
DATA_DIR = ROOT_DIR / "tool-app" / "demo_data" / "planner"
TASKS_FILE = DATA_DIR / "tasks.json"
VALID_STATUS = {"open", "done", "cancelled"}
VALID_PRIORITY = {"low", "medium", "high"}
MAX_TASKS_RETURNED = 100


def _ensure_store() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not TASKS_FILE.exists():
        TASKS_FILE.write_text("[]\n", encoding="utf-8")


def _load_tasks() -> List[Dict[str, Any]]:
    _ensure_store()
    raw = json.loads(TASKS_FILE.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("planner store must be list")
    return [item for item in raw if isinstance(item, dict)]


def _save_tasks(tasks: List[Dict[str, Any]]) -> None:
    TASKS_FILE.write_text(json.dumps(tasks, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def _normalize_priority(raw: Any) -> str:
    if raw in ("", None):
        return "medium"
    if not isinstance(raw, str):
        raise ValueError("priority must be string")
    value = raw.strip().lower()
    if value not in VALID_PRIORITY:
        raise ValueError(f"priority must be one of: {sorted(VALID_PRIORITY)}")
    return value


def _normalize_status(raw: Any) -> str:
    if raw in ("", None):
        return "open"
    if not isinstance(raw, str):
        raise ValueError("status must be string")
    value = raw.strip().lower()
    if value not in VALID_STATUS:
        raise ValueError(f"status must be one of: {sorted(VALID_STATUS)}")
    return value


def task_add(payload: Dict[str, Any]) -> Dict[str, Any]:
    title = payload.get("title", "")
    if not isinstance(title, str) or not title.strip():
        raise ValueError("task_add payload.title must be non-empty string")
    project = payload.get("project", "inbox")
    due_date = payload.get("due_date", "")
    notes = payload.get("notes", "")
    if not isinstance(project, str) or not isinstance(due_date, str) or not isinstance(notes, str):
        raise ValueError("project, due_date, and notes must be strings")
    now = datetime.now(timezone.utc)
    project_id = project.strip().lower().replace(" ", "-") or "inbox"
    task = {
        "task_id": f"{project_id}-{now.strftime('%Y%m%d-%H%M%S')}",
        "title": title.strip(),
        "project": project.strip() or "inbox",
        "priority": _normalize_priority(payload.get("priority")),
        "status": "open",
        "due_date": due_date.strip(),
        "notes": notes,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }
    tasks = _load_tasks()
    tasks.append(task)
    _save_tasks(tasks)
    return task


def task_list(payload: Dict[str, Any]) -> Dict[str, Any]:
    project = payload.get("project", "")
    status = payload.get("status", "")
    priority = payload.get("priority", "")
    query = payload.get("query", "")
    limit = payload.get("limit", 20)
    if not isinstance(project, str) or not isinstance(status, str) or not isinstance(priority, str) or not isinstance(query, str):
        raise ValueError("task_list filters must be strings")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("task_list payload.limit must be integer")
    limit = max(1, min(MAX_TASKS_RETURNED, limit))
    status_filter = status.strip().lower()
    priority_filter = priority.strip().lower()
    needle = query.strip().lower()
    if status_filter and status_filter not in VALID_STATUS:
        raise ValueError(f"status must be one of: {sorted(VALID_STATUS)}")
    if priority_filter and priority_filter not in VALID_PRIORITY:
        raise ValueError(f"priority must be one of: {sorted(VALID_PRIORITY)}")

    items = []
    for task in reversed(_load_tasks()):
        if project.strip() and task.get("project") != project.strip():
            continue
        if status_filter and task.get("status") != status_filter:
            continue
        if priority_filter and task.get("priority") != priority_filter:
            continue
        if needle:
            haystack = " ".join(
                [
                    str(task.get("title", "")),
                    str(task.get("notes", "")),
                    str(task.get("project", "")),
                    str(task.get("due_date", "")),
                ]
            ).lower()
            if needle not in haystack:
                continue
        items.append(task)
        if len(items) >= limit:
            break
    return {"count": len(items), "items": items}


def task_update(payload: Dict[str, Any]) -> Dict[str, Any]:
    task_id = payload.get("task_id", "")
    if not isinstance(task_id, str) or not task_id.strip():
        raise ValueError("task_update payload.task_id must be non-empty string")
    tasks = _load_tasks()
    target = None
    for task in tasks:
        if task.get("task_id") == task_id.strip():
            target = task
            break
    if target is None:
        raise ValueError(f"task not found: {task_id}")

    if "status" in payload:
        target["status"] = _normalize_status(payload.get("status"))
    if "priority" in payload:
        target["priority"] = _normalize_priority(payload.get("priority"))
    for key in ("due_date", "title", "notes"):
        if key in payload:
            value = payload.get(key)
            if not isinstance(value, str):
                raise ValueError(f"{key} must be string")
            target[key] = value.strip() if key in ("due_date", "title") else value
    target["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save_tasks(tasks)
    return target


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "task_add": task_add,
            "task_list": task_list,
            "task_update": task_update,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
