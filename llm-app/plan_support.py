#!/usr/bin/env python3
"""Plan normalization, payload validation, and result reference helpers."""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Tuple

from mcpd.schema_utils import validate_payload as validate_payload_against_schema


@dataclasses.dataclass(frozen=True)
class PlannedStep:
    index: int
    tool: Dict[str, Any]
    tool_id: int
    app_id: str
    app_name: str
    tool_name: str
    purpose: str
    save_as: str
    payload_raw: Dict[str, Any]


def _as_string(value: Any, *, default: str = "") -> str:
    if value is None:
        return default
    return value if isinstance(value, str) else str(value)


def _require_list(value: Any, *, err: str) -> List[Any]:
    if not isinstance(value, list) or not value:
        raise RuntimeError(err)
    return value


def _require_dict(value: Any, *, err: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(err)
    return value


def _require_int(value: Any, *, err: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(err)
    return value

def normalize_plan(
    plan_obj: Dict[str, Any],
    tools_by_id: Dict[int, Dict[str, Any]],
    *,
    max_plan_steps: int,
) -> Tuple[str, List[PlannedStep]]:
    reason = _as_string(plan_obj.get("reason", "")).strip() or "model-planned"
    raw_steps = _require_list(plan_obj.get("steps", []), err=f"plan missing steps: {plan_obj}")
    if len(raw_steps) > max_plan_steps:
        raise RuntimeError(f"plan has too many steps ({len(raw_steps)} > {max_plan_steps})")

    normalized: List[PlannedStep] = []
    seen_aliases: set[str] = set()
    for idx, raw_step in enumerate(raw_steps, start=1):
        step = _require_dict(raw_step, err=f"plan step {idx} must be object")
        tool_id = _require_int(step.get("tool_id"), err=f"plan step {idx} missing valid tool_id")
        tool = tools_by_id.get(tool_id)
        if tool is None:
            raise RuntimeError(f"plan step {idx} selected unavailable tool_id={tool_id}")

        alias = _as_string(step.get("save_as", f"step{idx}"), default=f"step{idx}").strip() or f"step{idx}"
        if alias in seen_aliases:
            raise RuntimeError(f"plan step {idx} duplicate save_as alias: {alias}")
        seen_aliases.add(alias)

        normalized.append(
            PlannedStep(
                index=idx,
                tool=tool,
                tool_id=tool_id,
                app_id=_as_string(tool.get("app_id", "")),
                app_name=_as_string(tool.get("app_name", "")),
                tool_name=_as_string(tool.get("name", "")),
                purpose=_as_string(step.get("purpose", "")).strip() or f"step {idx}",
                save_as=alias,
                payload_raw=_require_dict(step.get("payload", {}), err=f"plan step {idx} payload must be object"),
            )
        )
    return reason, normalized


def _parse_ref_tokens(token: str) -> List[Any]:
    parts: List[Any] = []
    buf = ""
    idx = 0
    while idx < len(token):
        ch = token[idx]
        if ch == ".":
            if buf:
                parts.append(buf)
                buf = ""
            idx += 1
            continue
        if ch == "[":
            if buf:
                parts.append(buf)
                buf = ""
            end = token.find("]", idx)
            if end < 0:
                raise ValueError(f"invalid reference token: {token}")
            raw_index = token[idx + 1 : end]
            if not raw_index.isdigit():
                raise ValueError(f"invalid list index in reference: {token}")
            parts.append(int(raw_index))
            idx = end + 1
            continue
        buf += ch
        idx += 1
    if buf:
        parts.append(buf)
    return parts


def _resolve_ref(ref: str, context: Dict[str, Any]) -> Any:
    if not ref.startswith("$"):
        return ref
    body = ref[1:]
    if not body:
        raise ValueError("empty reference")
    alias, dot, rest = body.partition(".")
    current = context.get(alias)
    if current is None:
        raise ValueError(f"unknown reference alias: {alias}")
    if not dot:
        return current
    for token in _parse_ref_tokens(rest):
        if isinstance(token, int):
            if not isinstance(current, list):
                raise ValueError(f"reference index applied to non-list in {ref}")
            if token >= len(current):
                raise ValueError(f"reference index out of range in {ref}")
            current = current[token]
            continue
        if not isinstance(current, dict):
            raise ValueError(f"reference field applied to non-object in {ref}")
        if token not in current:
            raise ValueError(f"reference field missing in {ref}: {token}")
        current = current[token]
    return current


def resolve_payload_refs(payload: Any, context: Dict[str, Any]) -> Any:
    if isinstance(payload, dict):
        return {key: resolve_payload_refs(value, context) for key, value in payload.items()}
    if isinstance(payload, list):
        return [resolve_payload_refs(item, context) for item in payload]
    if isinstance(payload, str) and payload.startswith("$"):
        return _resolve_ref(payload, context)
    return payload
