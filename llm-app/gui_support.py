#!/usr/bin/env python3
"""Small GUI helpers for llm-app."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from debug_render import render_execution_debug_lines
from model_client import SessionInfo
from presentation import render_app_lines, render_execution_user_lines, render_tool_catalog_text
from app_logic import load_catalog


def fmt_json(data: Any) -> str:
    try:
        return json.dumps(data, ensure_ascii=False)
    except Exception:
        return str(data)


def fetch_catalog(sock_path: str) -> Dict[str, Any]:
    try:
        apps, tools = load_catalog(sock_path)
    except RuntimeError as exc:
        return {"status": "error", "error": str(exc)}
    return {"status": "ok", "apps": apps, "tools": tools, "tools_at": time.time()}


def render_catalog_view(apps: List[Dict[str, Any]], tools: List[Dict[str, Any]], *, detailed: bool) -> Dict[str, Any]:
    app_lines = render_app_lines(apps, detailed=detailed)[1:]
    tool_text = render_tool_catalog_text(tools, detailed=detailed)
    label = f"Apps: {len(apps)}   Tools: {len(tools)}   Mode: {'dev' if detailed else 'user'}"
    return {"label": label, "app_lines": app_lines, "tool_text": tool_text}


def execution_lines(execution: Dict[str, Any], *, dev_mode: bool) -> List[str]:
    if dev_mode:
        return render_execution_debug_lines(execution, prefix="[llm-app]", show_payload=True)
    return [f"Assistant: {line}" for line in render_execution_user_lines(execution)]


def pull_worker_state(payload: Dict[str, Any], current_session: SessionInfo | None) -> Dict[str, Any]:
    session = payload.get("session")
    if isinstance(session, SessionInfo):
        current_session = session
    return {
        "apps": payload.get("apps") if isinstance(payload.get("apps"), list) else None,
        "tools": payload.get("tools") if isinstance(payload.get("tools"), list) else None,
        "tools_at": payload.get("tools_at") if isinstance(payload.get("tools_at"), (int, float)) else None,
        "session": current_session,
    }


def approval_message(payload: Dict[str, Any]) -> str:
    ticket_id = payload.get("ticket_id", 0)
    ticket_line = f"ticket_id: {ticket_id}\n" if isinstance(ticket_id, int) and ticket_id > 0 else ""
    return (
        f"Allow {payload.get('tool_name', 'tool')} from {payload.get('app_name', 'app')}?\n\n"
        f"Purpose: {payload.get('purpose', '')}\n"
        f"{ticket_line}"
        f"reason: {payload.get('reason', '')}\n\n"
        f"payload: {fmt_json(payload.get('payload', {}))}"
    )
