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
        step_id = raw_step.get("step_id", "")
        if not isinstance(purpose, str):
            purpose = str(purpose)
        lines.append(
            f"{prefix} step {idx} route: {app_name} ({app_id}) -> {tool_name} #{tool_id}"
            + (f" [{step_id}]" if isinstance(step_id, str) and step_id else "")
            + (f" | {purpose}" if purpose else "")
        )
        if show_payload:
            payload_seed = raw_step.get("payload_seed")
            if isinstance(payload_seed, dict):
                lines.append(
                    f"{prefix} step {idx} payload seed: "
                    f"{json.dumps(payload_seed, ensure_ascii=True, sort_keys=True)}"
                )
            payload_final = raw_step.get("payload_final", {})
            lines.append(
                f"{prefix} step {idx} payload: "
                f"{json.dumps(payload_final, ensure_ascii=True, sort_keys=True)}"
            )
        generated_fields = raw_step.get("generated_fields", [])
        if isinstance(generated_fields, list) and generated_fields:
            lines.append(
                f"{prefix} step {idx} generated: "
                f"{', '.join(str(item) for item in generated_fields)}"
            )
        approval_request = raw_step.get("approval_request", {})
        if isinstance(approval_request, dict) and approval_request:
            lines.append(
                f"{prefix} step {idx} approval: "
                f"ticket_id={approval_request.get('ticket_id', 0)} "
                f"reason={approval_request.get('reason', '')}"
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
        fallback_payload = raw_step.get("fallback_payload")
        if isinstance(fallback_payload, dict):
            fallback_approval_request = raw_step.get("fallback_approval_request", {})
            if isinstance(fallback_approval_request, dict) and fallback_approval_request:
                lines.append(
                    f"{prefix} step {idx} fallback approval: "
                    f"ticket_id={fallback_approval_request.get('ticket_id', 0)} "
                    f"reason={fallback_approval_request.get('reason', '')}"
                )
            lines.append(
                f"{prefix} step {idx} fallback payload: "
                f"{json.dumps(fallback_payload, ensure_ascii=True, sort_keys=True)}"
            )
            fallback_response = raw_step.get("fallback_response", {})
            if isinstance(fallback_response, dict):
                lines.append(
                    f"{prefix} step {idx} fallback exec: req_id={raw_step.get('fallback_req_id', '?')} "
                    f"status={fallback_response.get('status')} t_ms={fallback_response.get('t_ms')}"
                )
                if fallback_response.get("status") == "ok":
                    lines.append(
                        f"{prefix} step {idx} fallback result: "
                        f"{json.dumps(fallback_response.get('result', {}), ensure_ascii=True)}"
                    )
                else:
                    lines.append(
                        f"{prefix} step {idx} fallback error: "
                        f"{fallback_response.get('error', 'unknown error')}"
                    )
        no_match = raw_step.get("no_match", {})
        if isinstance(no_match, dict) and no_match:
            lines.append(
                f"{prefix} step {idx} halted: {no_match.get('message', 'no matching items found')}"
            )
    return lines
