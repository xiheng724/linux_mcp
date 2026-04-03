#!/usr/bin/env python3
"""User/dev presentation helpers for llm-app surfaces."""

from __future__ import annotations

import json
from typing import Any, Dict, List


def clip_text(text: Any, limit: int = 96) -> str:
    value = str(text).strip()
    if len(value) <= limit:
        return value
    return f"{value[: limit - 3].rstrip()}..."


def render_app_lines(apps: List[Dict[str, Any]], *, detailed: bool) -> List[str]:
    lines = [f"Apps ({len(apps)})"]
    for app in apps:
        app_name = str(app.get("app_name", app.get("app_id", "app")))
        app_id = str(app.get("app_id", ""))
        tool_count = app.get("tool_count", 0)
        if detailed:
            tool_names = app.get("tool_names", [])
            tool_text = ", ".join(str(name) for name in tool_names[:8]) if isinstance(tool_names, list) else ""
            lines.append(f"- {app_name} ({app_id}) tools={tool_count}")
            if tool_text:
                lines.append(f"  tools: {clip_text(tool_text, 120)}")
        else:
            lines.append(f"- {app_name} ({tool_count} tools)")
    return lines


def render_tool_lines(tools: List[Dict[str, Any]], *, detailed: bool) -> List[str]:
    lines = [f"Tools ({len(tools)})"]
    for tool in tools:
        name = str(tool.get("name", "tool"))
        app_name = str(tool.get("app_name", tool.get("app_id", "app")))
        desc = clip_text(tool.get("description", ""), 100)
        if detailed:
            lines.append(
                f"- #{tool.get('tool_id', '?')} {name} [{app_name}] hash={tool.get('hash', '-')}"
            )
            if desc:
                lines.append(f"  {desc}")
        else:
            lines.append(f"- {name} [{app_name}]")
            if desc:
                lines.append(f"  {desc}")
    return lines


def render_tool_catalog_text(tools: List[Dict[str, Any]], *, detailed: bool) -> str:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for tool in tools:
        app_name = str(tool.get("app_name", tool.get("app_id", "Other")))
        grouped.setdefault(app_name, []).append(tool)

    lines: List[str] = []
    for app_name in sorted(grouped.keys()):
        group = sorted(grouped[app_name], key=lambda item: int(item.get("tool_id", 0)))
        lines.append(f"{app_name} ({len(group)})")
        for tool in group:
            name = str(tool.get("name", "tool"))
            desc = clip_text(tool.get("description", ""), 100)
            if detailed:
                lines.append(
                    f"  - #{tool.get('tool_id', '?')} {name}  hash={tool.get('hash', '-')}"
                )
            else:
                lines.append(f"  - {name}")
            if desc:
                lines.append(f"    {desc}")
        lines.append("")
    return "\n".join(lines).strip()


def render_execution_user_lines(execution: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    response = execution.get("response", {})
    if not isinstance(response, dict):
        return lines
    status = response.get("status")

    steps = execution.get("steps", [])
    if status == "ok" and isinstance(steps, list) and steps:
        if len(steps) == 1:
            lines.append("Request completed.")
        else:
            lines.append(f"Request completed in {len(steps)} steps.")
    result = response.get("result", {})
    if status != "ok":
        lines.append(f"Failed: {response.get('error', execution.get('error', 'unknown error'))}")
        return lines
    lines.extend(_summarize_result(result))
    return lines or ["Done."]


def _summarize_result(result: Any) -> List[str]:
    if isinstance(result, dict):
        path = result.get("path")
        if isinstance(path, str) and path:
            if result.get("created") is True:
                return [f"Done. Saved `{path}`."]
            if result.get("overwritten") is True:
                return [f"Done. Updated `{path}`."]
            return [f"Done. Result path: `{path}`."]

        note_id = result.get("note_id")
        title = result.get("title")
        if isinstance(note_id, str) and note_id:
            if isinstance(title, str) and title:
                return [f"Done. Note ready: {title} (`{note_id}`)."]
            return [f"Done. Note ready: `{note_id}`."]

        items = result.get("items")
        count = result.get("count")
        if isinstance(items, list):
            header = f"Found {count if isinstance(count, int) else len(items)} item(s)."
            lines = [header]
            for item in items[:5]:
                if not isinstance(item, dict):
                    lines.append(f"- {clip_text(item, 80)}")
                    continue
                label = (
                    item.get("title")
                    or item.get("name")
                    or item.get("path")
                    or item.get("note_id")
                    or item.get("id")
                    or json.dumps(item, ensure_ascii=False)
                )
                meta = item.get("updated_at") or item.get("notebook") or item.get("app_name")
                if meta:
                    lines.append(f"- {clip_text(label, 80)} ({clip_text(meta, 32)})")
                else:
                    lines.append(f"- {clip_text(label, 80)}")
            return lines

        body = result.get("body")
        if isinstance(body, str) and body.strip():
            title_prefix = f"{title}: " if isinstance(title, str) and title else ""
            return [f"{title_prefix}{clip_text(body, 180)}"]

        if isinstance(count, int):
            return [f"Done. Count: {count}."]

        preferred_keys = [
            "message",
            "summary",
            "status",
            "created",
            "updated",
            "size_bytes",
            "tag_count",
        ]
        fragments: List[str] = []
        for key in preferred_keys:
            value = result.get(key)
            if value in (None, "", [], {}):
                continue
            fragments.append(f"{key}={value}")
        if fragments:
            return [f"Done. {'; '.join(fragments[:4])}."]
        if result:
            return [f"Done. {clip_text(json.dumps(result, ensure_ascii=False), 200)}"]

    if isinstance(result, list):
        return [f"Done. Returned {len(result)} item(s)."]
    if result not in (None, ""):
        return [f"Done. {clip_text(result, 200)}"]
    return ["Done."]
