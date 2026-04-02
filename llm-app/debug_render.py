#!/usr/bin/env python3
"""Render execution traces for CLI and GUI."""

from __future__ import annotations

import json
from typing import Any, Dict, List


def render_execution_debug_lines(
    execution: Dict[str, Any],
    *,
    prefix: str = "[llm-app]",
    show_payload: bool = True,
) -> List[str]:
    lines: List[str] = []
    plan_reason = execution.get("plan_reason", "")
    if isinstance(plan_reason, str) and plan_reason:
        lines.append(f"{prefix} plan: {plan_reason}")

    steps = execution.get("steps", [])
    if not isinstance(steps, list):
        return lines

    for raw_step in steps:
        if not isinstance(raw_step, dict):
            continue
        idx = raw_step.get("index", "?")
        app_name = raw_step.get("app_name", raw_step.get("app_id", ""))
        app_id = raw_step.get("app_id", "")
        tool_name = raw_step.get("tool_name", "unknown")
        tool_id = raw_step.get("tool_id", "?")
        purpose = raw_step.get("purpose", "")
        if not isinstance(purpose, str):
            purpose = str(purpose)
        lines.append(
            f"{prefix} step {idx} route: {app_name} ({app_id}) -> {tool_name} #{tool_id}"
            + (f" | {purpose}" if purpose else "")
        )
        if show_payload:
            payload_final = raw_step.get("payload_final", {})
            lines.append(
                f"{prefix} step {idx} payload: "
                f"{json.dumps(payload_final, ensure_ascii=True, sort_keys=True)}"
            )
        response = raw_step.get("response", {})
        if not isinstance(response, dict):
            continue
        lines.append(
            f"{prefix} step {idx} exec: req_id={raw_step.get('req_id', '?')} "
            f"status={response.get('status')} t_ms={response.get('t_ms')}"
        )
        if response.get("status") == "ok":
            lines.append(
                f"{prefix} step {idx} result: "
                f"{json.dumps(response.get('result', {}), ensure_ascii=True)}"
            )
        else:
            lines.append(f"{prefix} step {idx} error: {response.get('error', 'unknown error')}")
    return lines
