#!/usr/bin/env python3
"""Plan normalization, explicit workflow semantics, and payload resolution helpers."""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from mcpd.schema_utils import validate_payload as validate_payload_against_schema


@dataclasses.dataclass(frozen=True)
class EmptyPolicy:
    action: str
    collection_path: str
    remove_payload_fields: Tuple[str, ...] = ()
    message: str = "no matching results found"


@dataclasses.dataclass(frozen=True)
class PlannedStep:
    index: int
    step_id: str
    tool: Dict[str, Any]
    tool_id: int
    app_id: str
    app_name: str
    tool_name: str
    purpose: str
    payload_template: Dict[str, Any]
    empty_policy: EmptyPolicy | None = None


@dataclasses.dataclass(frozen=True)
class NoMatchOutcome:
    step_index: int
    step_id: str
    tool_name: str
    message: str
    original_payload: Dict[str, Any]
    fallback_attempted: bool
    fallback_payload: Dict[str, Any] | None = None


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


def _normalize_empty_policy(raw: Any, *, step_index: int) -> EmptyPolicy | None:
    if raw in (None, {}):
        return None
    policy = _require_dict(raw, err=f"plan step {step_index} on_empty must be object")
    action = _as_string(policy.get("action", "")).strip()
    if action not in {"fail", "retry_without_fields"}:
        raise RuntimeError(
            f"plan step {step_index} on_empty.action must be fail or retry_without_fields"
        )
    collection_path = _as_string(policy.get("collection_path", "items")).strip() or "items"
    remove_fields_raw = policy.get("remove_payload_fields", [])
    if not isinstance(remove_fields_raw, list):
        raise RuntimeError(f"plan step {step_index} on_empty.remove_payload_fields must be list")
    remove_fields = tuple(_as_string(item).strip() for item in remove_fields_raw if _as_string(item).strip())
    message = _as_string(policy.get("message", "no matching results found")).strip()
    return EmptyPolicy(
        action=action,
        collection_path=collection_path,
        remove_payload_fields=remove_fields,
        message=message or "no matching results found",
    )


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
    seen_ids: set[str] = set()
    for idx, raw_step in enumerate(raw_steps, start=1):
        step = _require_dict(raw_step, err=f"plan step {idx} must be object")
        tool_id = _require_int(step.get("tool_id"), err=f"plan step {idx} missing valid tool_id")
        tool = tools_by_id.get(tool_id)
        if tool is None:
            raise RuntimeError(f"plan step {idx} selected unavailable tool_id={tool_id}")

        step_id = _as_string(step.get("step_id") or step.get("save_as") or f"step{idx}").strip() or f"step{idx}"
        if step_id in seen_ids:
            raise RuntimeError(f"plan step {idx} duplicate step_id: {step_id}")
        seen_ids.add(step_id)

        normalized.append(
            PlannedStep(
                index=idx,
                step_id=step_id,
                tool=tool,
                tool_id=tool_id,
                app_id=_as_string(tool.get("app_id", "")),
                app_name=_as_string(tool.get("app_name", "")),
                tool_name=_as_string(tool.get("name", "")),
                purpose=_as_string(step.get("purpose", "")).strip() or f"step {idx}",
                payload_template=_require_dict(
                    step.get("payload", {}),
                    err=f"plan step {idx} payload must be object",
                ),
                empty_policy=_normalize_empty_policy(step.get("on_empty"), step_index=idx),
            )
        )
    return reason, normalized


def _parse_path_tokens(path: str) -> List[Any]:
    parts: List[Any] = []
    buf = ""
    idx = 0
    while idx < len(path):
        ch = path[idx]
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
            end = path.find("]", idx)
            if end < 0:
                raise ValueError(f"invalid path token: {path}")
            raw_index = path[idx + 1 : end]
            if not raw_index.isdigit():
                raise ValueError(f"invalid list index in path: {path}")
            parts.append(int(raw_index))
            idx = end + 1
            continue
        buf += ch
        idx += 1
    if buf:
        parts.append(buf)
    return parts


def _resolve_path_value(current: Any, path: str, *, ref_desc: str) -> Any:
    if not path:
        return current
    for token in _parse_path_tokens(path):
        if isinstance(token, int):
            if not isinstance(current, list):
                raise ValueError(f"reference index applied to non-list in {ref_desc}")
            if token >= len(current):
                raise ValueError(f"reference index out of range in {ref_desc}")
            current = current[token]
            continue
        if not isinstance(current, dict):
            raise ValueError(f"reference field applied to non-object in {ref_desc}")
        if token not in current:
            raise ValueError(f"reference field missing in {ref_desc}: {token}")
        current = current[token]
    return current


def _resolve_legacy_ref(ref: str, context: Dict[str, Any]) -> Any:
    body = ref[1:]
    if not body:
        raise ValueError("empty reference")
    step_id, dot, rest = body.partition(".")
    current = context.get(step_id)
    if current is None:
        raise ValueError(f"unknown reference step_id: {step_id}")
    return current if not dot else _resolve_path_value(current, rest, ref_desc=ref)


def _resolve_selector(spec: Dict[str, Any], context: Dict[str, Any]) -> Any:
    step_id = _as_string(spec.get("step", "")).strip()
    if not step_id:
        raise ValueError("selector.step must be non-empty string")
    current = context.get(step_id)
    if current is None:
        raise ValueError(f"unknown selector step_id: {step_id}")

    path = _as_string(spec.get("path", "")).strip()
    selected = _resolve_path_value(current, path, ref_desc=f"selector({step_id})") if path else current

    mode = _as_string(spec.get("mode", "value")).strip() or "value"
    if mode == "first":
        if not isinstance(selected, list):
            raise ValueError(f"selector({step_id}) mode=first requires list")
        if not selected:
            raise ValueError(f"selector({step_id}) has no items")
        selected = selected[0]
    elif mode == "only":
        if not isinstance(selected, list):
            raise ValueError(f"selector({step_id}) mode=only requires list")
        if len(selected) != 1:
            raise ValueError(f"selector({step_id}) mode=only requires exactly one item")
        selected = selected[0]
    elif mode != "value":
        raise ValueError(f"unsupported selector mode: {mode}")

    field = _as_string(spec.get("field", "")).strip()
    return _resolve_path_value(selected, field, ref_desc=f"selector({step_id}).{field}") if field else selected


def resolve_payload_template(payload: Any, context: Dict[str, Any]) -> Any:
    if isinstance(payload, dict):
        if set(payload.keys()) == {"$select"}:
            selector = _require_dict(payload["$select"], err="selector must be object")
            return _resolve_selector(selector, context)
        return {key: resolve_payload_template(value, context) for key, value in payload.items()}
    if isinstance(payload, list):
        return [resolve_payload_template(item, context) for item in payload]
    if isinstance(payload, str) and payload.startswith("$"):
        return _resolve_legacy_ref(payload, context)
    return payload


def collection_empty_state(result: Dict[str, Any], collection_path: str) -> bool | None:
    try:
        selected = _resolve_path_value(result, collection_path, ref_desc=f"result.{collection_path}")
    except ValueError:
        return None
    if isinstance(selected, list):
        return not selected
    return None


def apply_empty_policy(payload: Dict[str, Any], policy: EmptyPolicy) -> Dict[str, Any]:
    if policy.action != "retry_without_fields":
        return payload
    return {
        key: value
        for key, value in payload.items()
        if key not in set(policy.remove_payload_fields)
    }


def build_no_match_outcome(
    step: PlannedStep,
    original_payload: Dict[str, Any],
    fallback_payload: Dict[str, Any] | None,
) -> NoMatchOutcome:
    policy_message = step.empty_policy.message if step.empty_policy is not None else ""
    return NoMatchOutcome(
        step_index=step.index,
        step_id=step.step_id,
        tool_name=step.tool_name,
        message=policy_message or "no matching results found",
        original_payload=original_payload,
        fallback_attempted=fallback_payload is not None,
        fallback_payload=fallback_payload,
    )
