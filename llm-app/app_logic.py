#!/usr/bin/env python3
"""Shared planning, execution, and debug rendering for llm-app."""

from __future__ import annotations

import dataclasses
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

from model_client import SelectorConfig, SessionInfo, call_model, current_time_context, require_api_key, runtime_context
from plan_support import (
    EmptyPolicy,
    NoMatchOutcome,
    PlannedStep,
    apply_empty_policy,
    build_no_match_outcome,
    collection_empty_state,
    normalize_plan,
    resolve_payload_template,
    validate_payload_against_schema,
)
from rpc import mcpd_call

MAX_PLAN_STEPS = 4
MAX_PLAN_CANDIDATE_TOOLS = 6
DEFAULT_APPROVAL_TTL_MS = 5 * 60 * 1000
ToolDict = Dict[str, Any]
ApprovalEvaluator = Callable[[ToolDict, Dict[str, Any], Dict[str, Any]], str | None]
PathResolver = Callable[[str, Dict[str, str]], Path]


@dataclasses.dataclass(frozen=True)
class ApprovalRequest:
    step_index: int
    step_id: str
    app_name: str
    app_id: str
    tool_name: str
    tool_id: int
    purpose: str
    payload: Dict[str, Any]
    req_id: int
    ticket_id: int
    reason: str


def _resolve_repo_rel_path(raw_path: str, context: Dict[str, str]) -> Path:
    return (Path(context["repo_root_abs"]).resolve(strict=False) / raw_path.strip()).resolve(strict=False)


def _resolve_host_any_path(raw_path: str, context: Dict[str, str]) -> Path:
    text = raw_path.strip()
    path_obj = Path(text)
    if text.startswith("~"):
        return path_obj.expanduser().resolve(strict=False)
    if path_obj.is_absolute():
        return path_obj.resolve(strict=False)
    if path_obj.parts and path_obj.parts[0].lower() == "desktop":
        desktop_dir = Path(context["desktop_dir_abs"]).resolve(strict=False)
        return desktop_dir.joinpath(*path_obj.parts[1:]).resolve(strict=False)
    home_dir = Path(context["home_dir_abs"]).resolve(strict=False)
    return (home_dir / path_obj).resolve(strict=False)


PATH_RESOLVERS: Dict[str, PathResolver] = {
    "repo_rel": _resolve_repo_rel_path,
    "host_any": _resolve_host_any_path,
}




def load_apps(sock_path: str) -> List[Dict[str, Any]]:
    resp = mcpd_call({"sys": "list_apps"}, sock_path=sock_path, timeout_s=5)
    if resp.get("status") != "ok":
        raise RuntimeError(resp.get("error", "list_apps failed"))
    raw_apps = resp.get("apps", [])
    if not isinstance(raw_apps, list):
        raise RuntimeError("list_apps response missing apps list")
    return [app for app in raw_apps if isinstance(app, dict)]


def load_tools(sock_path: str, app_id: str = "") -> List[Dict[str, Any]]:
    req: Dict[str, Any] = {"sys": "list_tools"}
    if app_id:
        req["app_id"] = app_id
    resp = mcpd_call(req, sock_path=sock_path, timeout_s=5)
    if resp.get("status") != "ok":
        raise RuntimeError(resp.get("error", "list_tools failed"))
    raw_tools = resp.get("tools", [])
    if not isinstance(raw_tools, list):
        raise RuntimeError("list_tools response missing tools list")
    return [tool for tool in raw_tools if isinstance(tool, dict)]


def load_catalog(sock_path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    return load_apps(sock_path), load_tools(sock_path)


def _index_tools(tools: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    out: Dict[int, Dict[str, Any]] = {}
    for tool in tools:
        tool_id = tool.get("tool_id")
        if isinstance(tool_id, int):
            out[tool_id] = tool
    return out


def _compact_tool(tool: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tool_id": tool.get("tool_id"),
        "name": tool.get("name", ""),
        "app_id": tool.get("app_id", ""),
        "app_name": tool.get("app_name", ""),
        "description": tool.get("description", ""),
        "path_semantics": tool.get("path_semantics", {}),
        "approval_policy": tool.get("approval_policy", {}),
    }


def _call_payload_builder_with_seed(
    *,
    user_text: str,
    tool: Dict[str, Any],
    step_purpose: str,
    seed_payload: Dict[str, Any],
    api_key: str,
    cfg: SelectorConfig,
) -> Dict[str, Any]:
    prompt = {
        "user_input": user_text,
        "step_purpose": step_purpose,
        "time_context": current_time_context(),
        "selected_tool": {
            "tool_id": tool.get("tool_id"),
            "name": tool.get("name", ""),
            "app_id": tool.get("app_id", ""),
            "app_name": tool.get("app_name", ""),
            "description": tool.get("description", ""),
            "input_schema": tool.get("input_schema", {}),
            "examples": tool.get("examples", []),
        },
        "seed_payload": seed_payload,
        "output_format": "payload JSON object",
        "rule": "Return one JSON object only. The object itself must be the payload.",
    }
    return call_model(
        prompt,
        (
            "You format tool payloads. Given the selected tool description, input schema, examples, "
            "the user's request, and an optional seed_payload with known field values, "
            "return exactly one strict JSON object representing the payload to send. "
            "Do not use markdown. Do not wrap the payload in extra fields. "
            "Preserve the explicit values from seed_payload unless they are invalid for the schema. "
            "Fill in any missing required or implied fields needed to satisfy the user request. "
            "If the schema uses absolute timestamp fields such as start_time or end_time, "
            "convert relative expressions like today/tomorrow/next Monday into valid ISO-8601 strings "
            "using the provided time_context."
        ),
        api_key,
        cfg,
    )


def build_payload_for_step(
    tool: Dict[str, Any],
    user_text: str,
    step_purpose: str,
    seed_payload: Dict[str, Any],
    cfg: SelectorConfig,
) -> Dict[str, Any]:
    api_key = require_api_key()
    input_schema = tool.get("input_schema", {})
    if not isinstance(input_schema, dict):
        raise RuntimeError("selected tool missing valid input_schema")

    last_error: Exception | None = None
    feedback = ""
    for _attempt in range(3):
        try:
            prompt_text = user_text if not feedback else f"{user_text}\n\nPrevious payload error: {feedback}"
            payload = _call_payload_builder_with_seed(
                user_text=prompt_text,
                tool=tool,
                step_purpose=step_purpose,
                seed_payload=seed_payload,
                api_key=api_key,
                cfg=cfg,
            )
            validate_payload_against_schema(input_schema, payload)
            return payload
        except ValueError as exc:
            last_error = exc
            feedback = str(exc)

    raise RuntimeError(f"failed to build valid payload after retries: {last_error}") from last_error


def _call_plan_builder(
    user_text: str,
    apps: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    api_key: str,
    cfg: SelectorConfig,
) -> Dict[str, Any]:
    prompt = {
        "user_input": user_text,
        "time_context": current_time_context(),
        "runtime_context": runtime_context(),
        "apps": [
            {
                "app_id": app.get("app_id", ""),
                "app_name": app.get("app_name", ""),
                "tool_names": app.get("tool_names", []),
            }
            for app in apps
            if isinstance(app.get("app_id"), str)
        ],
        "tools": [
            {
                "tool_id": tool.get("tool_id"),
                "name": tool.get("name", ""),
                "app_id": tool.get("app_id", ""),
                "app_name": tool.get("app_name", ""),
                "description": tool.get("description", ""),
                "input_schema": tool.get("input_schema", {}),
                "examples": tool.get("examples", []),
                "path_semantics": tool.get("path_semantics", {}),
                "approval_policy": tool.get("approval_policy", {}),
            }
            for tool in tools
            if isinstance(tool.get("tool_id"), int)
        ],
        "reference_syntax": {
            "description": "Prefer explicit selector objects to read values from prior step results.",
            "examples": [
                "$context.workspace_root_rel",
                {"$select": {"step": "matches", "path": "items", "mode": "first", "field": "note_id"}},
                {"$select": {"step": "events", "path": "items", "mode": "first", "field": "event_id"}},
            ],
        },
        "output_format": {
            "reason": "string",
            "steps": [
                {
                    "step_id": "string",
                    "tool_id": "int",
                    "purpose": "string",
                    "payload": "partial JSON object with literal values, selector objects, or legacy $step.path string references",
                    "on_empty": {
                        "action": "retry_without_fields or fail",
                        "collection_path": "string path to the collection to inspect, usually items",
                        "remove_payload_fields": "list[string] optional when action=retry_without_fields",
                        "message": "user-facing no-match message",
                    },
                }
            ],
        },
        "rule": "Return one JSON object only. No markdown. Use 1-4 steps.",
    }
    obj = call_model(
        prompt,
        (
            "You are a planning router for tool execution. Build the smallest valid sequential plan. "
            "A runtime_context object is available for environment values such as the current workspace root. "
            "When the user refers to the current project folder or current workspace, use $context.workspace_root_rel "
            "instead of inventing a lookup step. "
            "Use each tool's path_semantics metadata to match the user's path scope. "
            "repo_rel means the path must stay under the repository root. "
            "host_any means the path targets the real host filesystem. "
            "When the user specifies a non-repository path, prefer a tool whose path_semantics matches that host path scope. "
            "If the user refers to an item semantically but the write/read tool needs an exact identifier, "
            "first use a search/list/find tool to resolve candidates, then use an explicit selector object in a later step. "
            "The plan payload for each step may be partial. Include constrained fields you know, "
            "but do not inline large freeform text such as source code or full documents into the plan. "
            "If a step may need an explicit empty-result policy, declare it with on_empty rather than relying on implicit executor behavior. "
            "Only attach on_empty to steps whose result schema is collection-shaped, such as an object containing items. "
            "Do not attach on_empty to create/write steps that return a single object summary. "
            "If a tool schema expects an absolute timestamp field, plan for a payload that contains a valid ISO-8601 time, "
            "not a relative phrase. Use the provided time_context for date resolution. "
            "Do not invent IDs. Prefer plans that can succeed with the available tool schemas. "
            "Respond with strict JSON only in the format "
            "{\"reason\":\"...\",\"steps\":[{\"step_id\":\"search_notes\",\"tool_id\":1,\"purpose\":\"...\",\"payload\":{},\"on_empty\":{\"action\":\"retry_without_fields\",\"collection_path\":\"items\",\"remove_payload_fields\":[\"notebook\"],\"message\":\"no matching notes found\"}}]}."
        ),
        api_key,
        cfg,
    )
    if not isinstance(obj, dict):
        raise RuntimeError(f"plan builder returned non-object: {obj!r}")
    return obj


def _call_tool_selector(
    user_text: str,
    apps: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    api_key: str,
    cfg: SelectorConfig,
) -> Dict[str, Any]:
    prompt = {
        "user_input": user_text,
        "runtime_context": runtime_context(),
        "apps": [
            {
                "app_id": app.get("app_id", ""),
                "app_name": app.get("app_name", ""),
            }
            for app in apps
            if isinstance(app.get("app_id"), str)
        ],
        "tools": [_compact_tool(tool) for tool in tools if isinstance(tool.get("tool_id"), int)],
        "output_format": {
            "reason": "string",
            "tool_ids": ["int"],
        },
        "rule": f"Return one JSON object only. Choose 1-{MAX_PLAN_CANDIDATE_TOOLS} tool_ids.",
    }
    obj = call_model(
        prompt,
        (
            "You are a lightweight tool selector. Choose the smallest set of tools needed to satisfy the user request and any identifier-resolution steps implied by the selected tool schemas. "
            "Use each tool's path_semantics metadata to match explicit user path scope. "
            "repo_rel tools are for repository-root paths. "
            "host_any tools are for real host filesystem paths. "
            "When the user specifies a non-repository path, prefer a host-path tool instead of a repo_rel tool. "
            "Do not invent tool ids. Return strict JSON only in the format "
            "{\"reason\":\"...\",\"tool_ids\":[1,2]}."
        ),
        api_key,
        cfg,
    )
    if not isinstance(obj, dict):
        raise RuntimeError(f"tool selector returned non-object: {obj!r}")
    return obj


def _select_candidate_tools(
    user_text: str,
    apps: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    cfg: SelectorConfig,
) -> Tuple[str, List[Dict[str, Any]]]:
    api_key = require_api_key()
    tools_by_id = _index_tools(tools)
    selector_obj = _call_tool_selector(user_text, apps, tools, api_key, cfg)
    reason = str(selector_obj.get("reason", "")).strip() or "model-selected"
    raw_ids = selector_obj.get("tool_ids", [])
    if not isinstance(raw_ids, list) or not raw_ids:
        return reason, tools
    selected: List[Dict[str, Any]] = []
    seen_ids: set[int] = set()
    for raw_id in raw_ids:
        if isinstance(raw_id, bool) or not isinstance(raw_id, int):
            continue
        if raw_id in seen_ids:
            continue
        tool = tools_by_id.get(raw_id)
        if tool is None:
            continue
        selected.append(tool)
        seen_ids.add(raw_id)
        if len(selected) >= MAX_PLAN_CANDIDATE_TOOLS:
            break
    return (reason, selected or tools)


def build_execution_plan(
    user_text: str,
    apps: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    cfg: SelectorConfig,
) -> Dict[str, Any]:
    selector_reason, candidate_tools = _select_candidate_tools(user_text, apps, tools, cfg)
    tools_by_id = _index_tools(candidate_tools)
    if not tools_by_id:
        raise RuntimeError("no valid tools discovered from mcpd")
    plan_obj = _call_plan_builder(user_text, apps, candidate_tools, require_api_key(), cfg)
    reason, steps = normalize_plan(plan_obj, tools_by_id, max_plan_steps=MAX_PLAN_STEPS)
    plan_reason = reason if selector_reason == "model-selected" else f"{selector_reason}; {reason}"
    return {"reason": plan_reason, "steps": steps}


def _exec_tool_request(
    *,
    session: SessionInfo,
    sock_path: str,
    step: PlannedStep,
    payload: Dict[str, Any],
    req_id: int | None = None,
    approval_ticket_id: int = 0,
) -> Dict[str, Any]:
    request_id = req_id if req_id is not None else int(time.time_ns() & 0xFFFFFFFFFFFF)
    tool_hash_raw = step.tool.get("hash")
    tool_hash = tool_hash_raw if isinstance(tool_hash_raw, str) else ""
    req_obj = {
        "kind": "tool:exec",
        "req_id": request_id,
        "session_id": session.session_id,
        "app_id": step.app_id,
        "tool_id": step.tool_id,
        "tool_hash": tool_hash,
        "payload": payload,
    }
    if approval_ticket_id > 0:
        req_obj["approval_ticket_id"] = approval_ticket_id
    response = mcpd_call(req_obj, sock_path=sock_path, timeout_s=20)
    return {"req_id": request_id, "response": response}


def _execute_candidate_fallback(
    *,
    session: SessionInfo,
    sock_path: str,
    step: PlannedStep,
    input_schema: Dict[str, Any],
    empty_policy: EmptyPolicy,
    original_payload: Dict[str, Any],
    approval_handler: Callable[[ApprovalRequest], bool] | None,
) -> Dict[str, Any] | None:
    fallback_payload = apply_empty_policy(original_payload, empty_policy)
    if fallback_payload == original_payload:
        return None
    validate_payload_against_schema(input_schema, fallback_payload)
    resolved_exec = _execute_step_with_approvals(
        session=session,
        sock_path=sock_path,
        step=step,
        payload=fallback_payload,
        approval_handler=approval_handler,
    )
    return {
        "payload": fallback_payload,
        "req_id": resolved_exec["req_id"],
        "response": resolved_exec["response"],
        "approval_request": resolved_exec.get("approval_request"),
    }


def _build_approval_request(
    *,
    step: PlannedStep,
    payload: Dict[str, Any],
    req_id: int,
    response: Dict[str, Any],
) -> ApprovalRequest | None:
    if response.get("status") != "error":
        return None
    if response.get("decision") != "DEFER":
        return None
    ticket_id = response.get("ticket_id", 0)
    if isinstance(ticket_id, bool) or not isinstance(ticket_id, int) or ticket_id <= 0:
        return None
    return ApprovalRequest(
        step_index=step.index,
        step_id=step.step_id,
        app_name=step.app_name,
        app_id=step.app_id,
        tool_name=step.tool_name,
        tool_id=step.tool_id,
        purpose=step.purpose,
        payload=payload,
        req_id=req_id,
        ticket_id=ticket_id,
        reason=str(response.get("reason", "")),
    )


def _approval_reason_always(
    tool: ToolDict,
    payload: Dict[str, Any],
    user_confirmation: Dict[str, Any],
) -> str | None:
    del tool, payload
    return str(user_confirmation.get("reason", "")).strip() or "user confirmation required"


def _approval_reason_path_outside_repo(
    tool: ToolDict,
    payload: Dict[str, Any],
    user_confirmation: Dict[str, Any],
) -> str | None:
    path_fields = user_confirmation.get("path_fields", [])
    if not isinstance(path_fields, list):
        return None
    reason_prefix = str(user_confirmation.get("reason", "")).strip() or "user confirmation required"
    context = runtime_context()
    repo_root = Path(context["repo_root_abs"]).resolve(strict=False)
    for field_name in path_fields:
        raw_path = payload.get(field_name, "")
        if not isinstance(raw_path, str) or not raw_path.strip():
            continue
        target_path = _resolve_policy_path(tool, field_name, raw_path, context)
        try:
            target_path.relative_to(repo_root)
        except ValueError:
            return f"{reason_prefix}: {target_path}"
    return None


APPROVAL_EVALUATORS: Dict[str, ApprovalEvaluator] = {
    "always": _approval_reason_always,
    "path_outside_repo": _approval_reason_path_outside_repo,
}


def _submit_approval_reply(
    *,
    sock_path: str,
    session: SessionInfo,
    ticket_id: int,
    approved: bool,
) -> Dict[str, Any]:
    return mcpd_call(
        {
            "sys": "approval_reply",
            "session_id": session.session_id,
            "ticket_id": ticket_id,
            "decision": "approve" if approved else "deny",
            "reason": "approved in llm-app" if approved else "denied in llm-app",
            "ttl_ms": DEFAULT_APPROVAL_TTL_MS,
        },
        sock_path=sock_path,
        timeout_s=5,
    )


def _resolve_deferred_exec(
    *,
    session: SessionInfo,
    sock_path: str,
    step: PlannedStep,
    payload: Dict[str, Any],
    req_id: int,
    response: Dict[str, Any],
    approval_handler: Callable[[ApprovalRequest], bool] | None,
) -> Dict[str, Any]:
    approval_request = _build_approval_request(
        step=step,
        payload=payload,
        req_id=req_id,
        response=response,
    )
    if approval_request is None:
        return {"req_id": req_id, "response": response, "approval_request": None}
    if approval_handler is None:
        return {"req_id": req_id, "response": response, "approval_request": approval_request}

    approved = approval_handler(approval_request)
    approval_resp = _submit_approval_reply(
        sock_path=sock_path,
        session=session,
        ticket_id=approval_request.ticket_id,
        approved=approved,
    )
    if approval_resp.get("status") not in ("ok", "error"):
        return {
            "req_id": req_id,
            "response": {
                "status": "error",
                "error": approval_resp.get("error", "approval reply failed"),
            },
            "approval_request": approval_request,
        }
    return {
        "req_id": req_id,
        "response": approval_resp,
        "approval_request": approval_request,
    }


def _build_local_approval_request(
    *,
    step: PlannedStep,
    payload: Dict[str, Any],
) -> ApprovalRequest | None:
    approval_policy = step.tool.get("approval_policy", {})
    if not isinstance(approval_policy, dict):
        return None
    user_confirmation = approval_policy.get("user_confirmation", {})
    if not isinstance(user_confirmation, dict) or not user_confirmation:
        return None
    when = user_confirmation.get("when", "")
    evaluator = APPROVAL_EVALUATORS.get(when)
    if evaluator is None:
        return None
    reason = evaluator(step.tool, payload, user_confirmation)
    if not reason:
        return None
    return ApprovalRequest(
        step_index=step.index,
        step_id=step.step_id,
        app_name=step.app_name,
        app_id=step.app_id,
        tool_name=step.tool_name,
        tool_id=step.tool_id,
        purpose=step.purpose,
        payload=payload,
        req_id=0,
        ticket_id=0,
        reason=reason,
    )


def _resolve_policy_path(
    tool: Dict[str, Any],
    field_name: str,
    raw_path: str,
    context: Dict[str, str] | None = None,
) -> Path:
    active_context = runtime_context() if context is None else context
    text = raw_path.strip()
    path_semantics = tool.get("path_semantics", {})
    mode = path_semantics.get(field_name, "") if isinstance(path_semantics, dict) else ""
    resolver = PATH_RESOLVERS.get(mode, lambda value, _context: Path(value).expanduser().resolve(strict=False))
    return resolver(text, active_context)


def _execute_step_with_approvals(
    *,
    session: SessionInfo,
    sock_path: str,
    step: PlannedStep,
    payload: Dict[str, Any],
    approval_handler: Callable[[ApprovalRequest], bool] | None,
) -> Dict[str, Any]:
    local_approval = _build_local_approval_request(step=step, payload=payload)
    if local_approval is not None:
        if approval_handler is None:
            return {
                "req_id": 0,
                "response": {
                    "status": "error",
                    "result": {},
                    "error": "approval required for host filesystem write",
                    "decision": "DEFER",
                    "reason": local_approval.reason,
                    "ticket_id": 0,
                    "t_ms": 0,
                },
                "approval_request": local_approval,
            }
        if not approval_handler(local_approval):
            return {
                "req_id": 0,
                "response": {
                    "status": "error",
                    "result": {},
                    "error": "host filesystem write declined by user",
                    "decision": "DENY",
                    "reason": "user_declined_host_filesystem_write",
                    "ticket_id": 0,
                    "t_ms": 0,
                },
                "approval_request": local_approval,
            }

    primary_exec = _exec_tool_request(
        session=session,
        sock_path=sock_path,
        step=step,
        payload=payload,
    )
    resolved_exec = _resolve_deferred_exec(
        session=session,
        sock_path=sock_path,
        step=step,
        payload=payload,
        req_id=primary_exec["req_id"],
        response=primary_exec["response"],
        approval_handler=approval_handler,
    )
    if local_approval is not None and resolved_exec.get("approval_request") is None:
        resolved_exec["approval_request"] = local_approval
    return resolved_exec


def _materialize_step_payload(
    *,
    user_text: str,
    step: PlannedStep,
    results_by_alias: Dict[str, Any],
    cfg: SelectorConfig,
) -> Dict[str, Any]:
    input_schema = step.tool.get("input_schema", {})
    if not isinstance(input_schema, dict):
        raise RuntimeError(f"tool {step.tool.get('name', 'unknown')} missing valid input_schema")

    payload_seed = resolve_payload_template(step.payload_template, results_by_alias)
    if not isinstance(payload_seed, dict):
        raise RuntimeError(f"step {step.step_id} payload template must resolve to object")

    payload_final = payload_seed
    generated_fields: List[str] = []
    try:
        validate_payload_against_schema(input_schema, payload_final)
    except ValueError:
        payload_final = build_payload_for_step(
            step.tool,
            user_text,
            step.purpose,
            payload_seed,
            cfg,
        )
        generated_fields = ["payload"]
        validate_payload_against_schema(input_schema, payload_final)
    return {
        "input_schema": input_schema,
        "payload_seed": payload_seed,
        "payload_final": payload_final,
        "generated_fields": generated_fields,
    }


def _make_executed_step(
    *,
    step: PlannedStep,
    payload_info: Dict[str, Any],
    req_id: int,
    response: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "index": step.index,
        "tool": step.tool,
        "tool_id": step.tool_id,
        "app_id": step.app_id,
        "app_name": step.app_name,
        "tool_name": step.tool_name,
        "purpose": step.purpose,
        "step_id": step.step_id,
        "payload_template": step.payload_template,
        "payload_seed": payload_info["payload_seed"],
        "payload_final": payload_info["payload_final"],
        "generated_fields": payload_info["generated_fields"],
        "req_id": req_id,
        "response": response,
    }


def execute_plan(
    user_text: str,
    session: SessionInfo,
    sock_path: str,
    cfg: SelectorConfig,
    apps: List[Dict[str, Any]] | None = None,
    tools: List[Dict[str, Any]] | None = None,
    approval_handler: Callable[[ApprovalRequest], bool] | None = None,
) -> Dict[str, Any]:
    if apps is None or tools is None:
        apps, tools = load_catalog(sock_path)
    plan = build_execution_plan(user_text, apps, tools, cfg)

    results_by_alias: Dict[str, Any] = {"context": runtime_context()}
    executed_steps: List[Dict[str, Any]] = []
    final_response: Dict[str, Any] = {}
    final_status = "ok"
    error_text = ""
    no_match: NoMatchOutcome | None = None

    for step in plan["steps"]:
        payload_info = _materialize_step_payload(
            user_text=user_text,
            step=step,
            results_by_alias=results_by_alias,
            cfg=cfg,
        )
        resolved_exec = _execute_step_with_approvals(
            session=session,
            sock_path=sock_path,
            step=step,
            payload=payload_info["payload_final"],
            approval_handler=approval_handler,
        )
        response = resolved_exec["response"]
        executed_step = _make_executed_step(
            step=step,
            payload_info=payload_info,
            req_id=resolved_exec["req_id"],
            response=response,
        )
        approval_request = resolved_exec.get("approval_request")
        if isinstance(approval_request, ApprovalRequest):
            executed_step["approval_request"] = dataclasses.asdict(approval_request)
        executed_steps.append(executed_step)
        final_response = response

        if response.get("status") != "ok":
            final_status = "error"
            error_text = str(response.get("error", "unknown error"))
            break

        result = response.get("result", {})
        empty_policy = step.empty_policy
        empty_state = (
            collection_empty_state(result, empty_policy.collection_path)
            if isinstance(result, dict) and empty_policy is not None
            else None
        )
        if empty_state is True:
            fallback_exec = _execute_candidate_fallback(
                session=session,
                sock_path=sock_path,
                step=step,
                input_schema=payload_info["input_schema"],
                empty_policy=empty_policy,
                original_payload=payload_info["payload_final"],
                approval_handler=approval_handler,
            )
            if fallback_exec is not None:
                executed_step["fallback_payload"] = fallback_exec["payload"]
                executed_step["fallback_req_id"] = fallback_exec["req_id"]
                executed_step["fallback_response"] = fallback_exec["response"]
                fallback_approval_request = fallback_exec.get("approval_request")
                if isinstance(fallback_approval_request, ApprovalRequest):
                    executed_step["fallback_approval_request"] = dataclasses.asdict(
                        fallback_approval_request
                    )
                final_response = fallback_exec["response"]
                if fallback_exec["response"].get("status") != "ok":
                    final_status = "error"
                    error_text = str(fallback_exec["response"].get("error", "unknown error"))
                    break
                fallback_result = fallback_exec["response"].get("result", {})
                fallback_empty_state = (
                    collection_empty_state(fallback_result, empty_policy.collection_path)
                    if isinstance(fallback_result, dict)
                    else None
                )
                if fallback_empty_state is True:
                    no_match = build_no_match_outcome(
                        step,
                        payload_info["payload_final"],
                        fallback_exec["payload"],
                    )
                else:
                    result = fallback_result
                    executed_step["response"] = fallback_exec["response"]
                    executed_step["req_id"] = fallback_exec["req_id"]
                    executed_step["payload_final"] = fallback_exec["payload"]
            else:
                no_match = build_no_match_outcome(step, payload_info["payload_final"], None)

        if no_match is not None:
            executed_step["no_match"] = dataclasses.asdict(no_match)
            final_status = "error"
            error_text = no_match.message
            final_response = {
                "status": "error",
                "error": no_match.message,
                "result": {
                    "kind": "no_match",
                    "step_index": no_match.step_index,
                    "step_id": no_match.step_id,
                    "tool_name": no_match.tool_name,
                    "original_payload": no_match.original_payload,
                    "fallback_attempted": no_match.fallback_attempted,
                    "fallback_payload": no_match.fallback_payload,
                    "message": no_match.message,
                },
            }
            break

        results_by_alias[step.step_id] = result

    return {
        "status": final_status,
        "error": error_text,
        "plan_reason": plan["reason"],
        "steps": executed_steps,
        "response": final_response,
        "no_match": dataclasses.asdict(no_match) if no_match is not None else None,
        "apps": apps,
        "tools": tools,
    }
