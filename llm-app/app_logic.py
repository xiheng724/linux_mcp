#!/usr/bin/env python3
"""Shared planning, execution, and debug rendering for llm-app."""

from __future__ import annotations

import dataclasses
import json
import os
import time
from datetime import datetime, timezone
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

from debug_render import render_execution_debug_lines
from plan_support import PlannedStep, normalize_plan, resolve_payload_refs, validate_payload_against_schema
from rpc import mcpd_call

DEFAULT_DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
DEFAULT_DEEPSEEK_MODEL = "deepseek-chat"
MAX_PLAN_STEPS = 4


@dataclasses.dataclass(frozen=True)
class SelectorConfig:
    deepseek_url: str
    deepseek_model: str
    deepseek_timeout_sec: int


def _require_api_key() -> str:
    api_key = os.getenv("DEEPSEEK_API_KEY", "")
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY not set")
    return api_key


def _extract_json_object(text: str) -> Dict[str, Any]:
    decoder = json.JSONDecoder()
    for idx, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _end = decoder.raw_decode(text[idx:])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    raise ValueError(f"no JSON object found in model output: {text!r}")


def _call_model(prompt: Dict[str, Any], system_text: str, api_key: str, cfg: SelectorConfig) -> Dict[str, Any]:
    req_obj = {
        "model": cfg.deepseek_model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system_text},
            {"role": "user", "content": json.dumps(prompt, ensure_ascii=True)},
        ],
    }
    payload = json.dumps(req_obj, ensure_ascii=True).encode("utf-8")
    req = urllib.request.Request(
        cfg.deepseek_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=cfg.deepseek_timeout_sec) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"DeepSeek HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"DeepSeek request failed: {exc}") from exc

    data = json.loads(raw.decode("utf-8"))
    choices = data.get("choices", [])
    if not isinstance(choices, list) or not choices:
        raise RuntimeError(f"invalid DeepSeek response, missing choices: {data}")
    msg = choices[0].get("message", {})
    content = msg.get("content", "")
    if not isinstance(content, str) or not content:
        raise RuntimeError(f"invalid DeepSeek response content: {data}")
    return _extract_json_object(content)


def _current_time_context() -> Dict[str, str]:
    now = datetime.now(timezone.utc)
    return {
        "current_utc_time": now.isoformat(),
        "current_utc_date": now.date().isoformat(),
        "current_timezone": "UTC",
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


def _call_payload_builder(user_text: str, tool: Dict[str, Any], api_key: str, cfg: SelectorConfig) -> Dict[str, Any]:
    prompt = {
        "user_input": user_text,
        "time_context": _current_time_context(),
        "selected_tool": {
            "tool_id": tool.get("tool_id"),
            "name": tool.get("name", ""),
            "app_id": tool.get("app_id", ""),
            "app_name": tool.get("app_name", ""),
            "description": tool.get("description", ""),
            "input_schema": tool.get("input_schema", {}),
            "examples": tool.get("examples", []),
        },
        "output_format": "payload JSON object",
        "rule": "Return one JSON object only. The object itself must be the payload.",
    }
    return _call_model(
        prompt,
        (
            "You format tool payloads. Given the selected tool description, input schema, and examples, "
            "return exactly one strict JSON object representing the payload to send. "
            "Do not use markdown. Do not wrap the payload in extra fields. "
            "If the schema uses absolute timestamp fields such as start_time or end_time, "
            "convert relative expressions like today/tomorrow/next Monday into valid ISO-8601 strings "
            "using the provided time_context."
        ),
        api_key,
        cfg,
    )


def build_payload_for_tool(tool: Dict[str, Any], user_text: str, cfg: SelectorConfig) -> Dict[str, Any]:
    api_key = _require_api_key()
    input_schema = tool.get("input_schema", {})
    if not isinstance(input_schema, dict):
        raise RuntimeError("selected tool missing valid input_schema")

    last_error: Exception | None = None
    feedback = ""
    for _attempt in range(3):
        try:
            prompt_text = user_text if not feedback else f"{user_text}\n\nPrevious payload error: {feedback}"
            payload = _call_payload_builder(prompt_text, tool, api_key, cfg)
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
        "time_context": _current_time_context(),
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
            }
            for tool in tools
            if isinstance(tool.get("tool_id"), int)
        ],
        "reference_syntax": {
            "description": "Use a string like $alias.items[0].note_id to reference prior step results.",
            "examples": [
                "$matches.items[0].note_id",
                "$events.items[0].event_id",
            ],
        },
        "output_format": {
            "reason": "string",
            "steps": [
                {
                    "tool_id": "int",
                    "purpose": "string",
                    "save_as": "string optional",
                    "payload": "JSON object with literal values or $alias.path string references",
                }
            ],
        },
        "rule": "Return one JSON object only. No markdown. Use 1-4 steps.",
    }
    obj = _call_model(
        prompt,
        (
            "You are a planning router for tool execution. Build the smallest valid sequential plan. "
            "If the user refers to an item semantically but the write/read tool needs an exact identifier, "
            "first use a search/list/find tool to resolve candidates, then reference the identifier in a later step. "
            "If a tool schema expects an absolute timestamp field, plan for a payload that contains a valid ISO-8601 time, "
            "not a relative phrase. Use the provided time_context for date resolution. "
            "Do not invent IDs. Prefer plans that can succeed with the available tool schemas. "
            "Respond with strict JSON only in the format "
            "{\"reason\":\"...\",\"steps\":[{\"tool_id\":1,\"purpose\":\"...\",\"save_as\":\"alias\",\"payload\":{}}]}."
        ),
        api_key,
        cfg,
    )
    if not isinstance(obj, dict):
        raise RuntimeError(f"plan builder returned non-object: {obj!r}")
    return obj


def build_execution_plan(
    user_text: str,
    apps: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    cfg: SelectorConfig,
) -> Dict[str, Any]:
    tools_by_id = _index_tools(tools)
    if not tools_by_id:
        raise RuntimeError("no valid tools discovered from mcpd")
    plan_obj = _call_plan_builder(user_text, apps, tools, _require_api_key(), cfg)
    reason, steps = normalize_plan(plan_obj, tools_by_id, max_plan_steps=MAX_PLAN_STEPS)
    return {"reason": reason, "steps": steps}


def execute_plan(
    user_text: str,
    agent_id: str,
    sock_path: str,
    cfg: SelectorConfig,
    apps: List[Dict[str, Any]] | None = None,
    tools: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    if apps is None or tools is None:
        apps, tools = load_catalog(sock_path)
    plan = build_execution_plan(user_text, apps, tools, cfg)

    results_by_alias: Dict[str, Any] = {}
    executed_steps: List[Dict[str, Any]] = []
    final_response: Dict[str, Any] = {}
    final_status = "ok"
    error_text = ""

    for step in plan["steps"]:
        tool = step.tool
        input_schema = tool.get("input_schema", {})
        if not isinstance(input_schema, dict):
            raise RuntimeError(f"tool {tool.get('name', 'unknown')} missing valid input_schema")

        payload_final = resolve_payload_refs(step.payload_raw, results_by_alias)
        validate_payload_against_schema(input_schema, payload_final)
        req_id = int(time.time_ns() & 0xFFFFFFFFFFFF)
        tool_hash_raw = tool.get("hash")
        tool_hash = tool_hash_raw if isinstance(tool_hash_raw, str) else ""
        response = mcpd_call(
            {
                "kind": "tool:exec",
                "req_id": req_id,
                "agent_id": agent_id,
                "app_id": step.app_id,
                "tool_id": step.tool_id,
                "tool_hash": tool_hash,
                "payload": payload_final,
            },
            sock_path=sock_path,
            timeout_s=20,
        )
        executed_steps.append(
            {
                "index": step.index,
                "tool": step.tool,
                "tool_id": step.tool_id,
                "app_id": step.app_id,
                "app_name": step.app_name,
                "tool_name": step.tool_name,
                "purpose": step.purpose,
                "save_as": step.save_as,
                "payload_raw": step.payload_raw,
                "payload_final": payload_final,
                "req_id": req_id,
                "response": response,
            }
        )
        final_response = response

        if response.get("status") != "ok":
            final_status = "error"
            error_text = str(response.get("error", "unknown error"))
            break

        results_by_alias[step.save_as] = response.get("result", {})

    return {
        "status": final_status,
        "error": error_text,
        "plan_reason": plan["reason"],
        "steps": executed_steps,
        "response": final_response,
        "apps": apps,
        "tools": tools,
    }
