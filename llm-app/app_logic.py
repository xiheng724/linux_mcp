#!/usr/bin/env python3
"""Shared model-based app/tool routing and payload formatting for llm-app."""

from __future__ import annotations

import dataclasses
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

from rpc import mcpd_call

DEFAULT_DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
DEFAULT_DEEPSEEK_MODEL = "deepseek-chat"


@dataclasses.dataclass(frozen=True)
class SelectorConfig:
    deepseek_url: str
    deepseek_model: str
    deepseek_timeout_sec: int


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


def _load_apps(sock_path: str) -> List[Dict[str, Any]]:
    resp = mcpd_call({"sys": "list_apps"}, sock_path=sock_path, timeout_s=5)
    if resp.get("status") != "ok":
        raise RuntimeError(resp.get("error", "list_apps failed"))
    raw_apps = resp.get("apps", [])
    if not isinstance(raw_apps, list):
        raise RuntimeError("list_apps response missing apps list")
    return [app for app in raw_apps if isinstance(app, dict)]


def _load_tools(sock_path: str, app_id: str) -> List[Dict[str, Any]]:
    resp = mcpd_call({"sys": "list_tools", "app_id": app_id}, sock_path=sock_path, timeout_s=5)
    if resp.get("status") != "ok":
        raise RuntimeError(resp.get("error", "list_tools failed"))
    raw_tools = resp.get("tools", [])
    if not isinstance(raw_tools, list):
        raise RuntimeError("list_tools response missing tools list")
    return [tool for tool in raw_tools if isinstance(tool, dict)]


def _index_apps(apps: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for app in apps:
        app_id = app.get("app_id")
        if isinstance(app_id, str) and app_id:
            out[app_id] = app
    return out


def _index_tools(tools: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    out: Dict[int, Dict[str, Any]] = {}
    for tool in tools:
        tool_id = tool.get("tool_id")
        if isinstance(tool_id, int):
            out[tool_id] = tool
    return out


def _call_app_selector(user_text: str, apps: List[Dict[str, Any]], api_key: str, cfg: SelectorConfig) -> Tuple[str, str]:
    prompt = {
        "user_input": user_text,
        "apps": [
            {
                "app_id": app.get("app_id", ""),
                "app_name": app.get("app_name", ""),
                "tool_names": app.get("tool_names", []),
            }
            for app in apps
            if isinstance(app.get("app_id"), str)
        ],
        "output_format": {"app_id": "string", "reason": "string"},
        "rule": "Return one JSON object only. No markdown.",
    }
    obj = _call_model(
        prompt,
        (
            "You are an app router. Choose exactly one app_id from the provided app catalog. "
            "Use the app name and tool names to infer user intent. "
            "Respond with strict JSON only: {\"app_id\":\"...\",\"reason\":\"...\"}."
        ),
        api_key,
        cfg,
    )
    app_id = obj.get("app_id")
    if not isinstance(app_id, str) or not app_id:
        raise RuntimeError(f"DeepSeek returned invalid app_id: {obj}")
    reason = obj.get("reason", "")
    if not isinstance(reason, str):
        reason = str(reason)
    return app_id, reason


def _call_tool_selector(user_text: str, tools: List[Dict[str, Any]], api_key: str, cfg: SelectorConfig) -> Tuple[int, str]:
    prompt = {
        "user_input": user_text,
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
        "output_format": {"tool_id": "int", "reason": "string"},
        "rule": "Return one JSON object only. No markdown.",
    }
    obj = _call_model(
        prompt,
        (
            "You are a tool router. Choose exactly one tool_id from the provided tool catalog. "
            "Use tool description, input schema, and examples to reason about intent. "
            "Respond with strict JSON only: {\"tool_id\":<int>,\"reason\":\"...\"}."
        ),
        api_key,
        cfg,
    )
    tool_id = obj.get("tool_id")
    if isinstance(tool_id, bool) or not isinstance(tool_id, int):
        raise RuntimeError(f"DeepSeek returned invalid tool_id: {obj}")
    reason = obj.get("reason", "")
    if not isinstance(reason, str):
        reason = str(reason)
    return tool_id, reason


def select_app_for_input(user_text: str, apps: List[Dict[str, Any]], cfg: SelectorConfig) -> Tuple[Dict[str, Any], str, str]:
    by_id = _index_apps(apps)
    if not by_id:
        raise RuntimeError("no valid apps discovered from mcpd")
    api_key = os.getenv("DEEPSEEK_API_KEY", "")
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY not set")
    app_id, reason = _call_app_selector(user_text, apps, api_key, cfg)
    selected = by_id.get(app_id)
    if selected is None:
        raise RuntimeError(f"DeepSeek selected unavailable app_id={app_id}; available={sorted(by_id.keys())}")
    return selected, "model", reason or "model-selected"


def select_tool_for_input(user_text: str, tools: List[Dict[str, Any]], cfg: SelectorConfig) -> Tuple[Dict[str, Any], str, str]:
    by_id = _index_tools(tools)
    if not by_id:
        raise RuntimeError("no valid tools discovered from mcpd")
    api_key = os.getenv("DEEPSEEK_API_KEY", "")
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY not set")
    tool_id, reason = _call_tool_selector(user_text, tools, api_key, cfg)
    selected = by_id.get(tool_id)
    if selected is None:
        raise RuntimeError(f"DeepSeek selected unavailable tool_id={tool_id}; available={sorted(by_id.keys())}")
    return selected, "model", reason or "model-selected"


def select_route_for_request(
    user_text: str,
    sock_path: str,
    cfg: SelectorConfig,
) -> Tuple[Dict[str, Any], Dict[str, Any], str, str, str, str, List[Dict[str, Any]], List[Dict[str, Any]]]:
    apps = _load_apps(sock_path)
    selected_app, app_source, app_reason = select_app_for_input(user_text, apps, cfg)
    app_id = selected_app.get("app_id", "")
    if not isinstance(app_id, str) or not app_id:
        raise RuntimeError("selected app missing app_id")
    tools = _load_tools(sock_path, app_id)
    selected_tool, tool_source, tool_reason = select_tool_for_input(user_text, tools, cfg)
    return selected_app, selected_tool, app_source, app_reason, tool_source, tool_reason, apps, tools


def _matches_primitive(expected: str, value: Any) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (isinstance(value, int) or isinstance(value, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "null":
        return value is None
    return True


def validate_payload_against_schema(input_schema: Dict[str, Any], payload: Any) -> None:
    schema_type = input_schema.get("type")
    if isinstance(schema_type, str) and not _matches_primitive(schema_type, payload):
        raise ValueError(f"payload type mismatch: expected {schema_type}")
    if schema_type != "object":
        return
    if not isinstance(payload, dict):
        raise ValueError("payload must be object")

    required = input_schema.get("required", [])
    if isinstance(required, list):
        for field in required:
            if isinstance(field, str) and field not in payload:
                raise ValueError(f"payload missing required field: {field}")

    properties = input_schema.get("properties", {})
    if not isinstance(properties, dict):
        return

    additional_properties = input_schema.get("additionalProperties", True)
    for key, value in payload.items():
        prop_schema = properties.get(key)
        if prop_schema is None:
            if additional_properties is False:
                raise ValueError(f"payload has unknown field: {key}")
            continue
        if not isinstance(prop_schema, dict):
            continue
        expected_type = prop_schema.get("type")
        if isinstance(expected_type, str) and not _matches_primitive(expected_type, value):
            raise ValueError(f"field '{key}' type mismatch: expected {expected_type}")


def _call_payload_builder(user_text: str, tool: Dict[str, Any], api_key: str, cfg: SelectorConfig) -> Dict[str, Any]:
    prompt = {
        "user_input": user_text,
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
    obj = _call_model(
        prompt,
        (
            "You format tool payloads. Given the selected tool description, input schema, and examples, "
            "return exactly one strict JSON object representing the payload to send. "
            "Do not use markdown. Do not wrap the payload in extra fields."
        ),
        api_key,
        cfg,
    )
    if not isinstance(obj, dict):
        raise RuntimeError(f"payload builder returned non-object: {obj!r}")
    return obj


def build_payload_for_tool(tool: Dict[str, Any], user_text: str, cfg: SelectorConfig) -> Dict[str, Any]:
    api_key = os.getenv("DEEPSEEK_API_KEY", "")
    input_schema = tool.get("input_schema", {})
    if not isinstance(input_schema, dict):
        raise RuntimeError("selected tool missing valid input_schema")
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY not set")
    payload = _call_payload_builder(user_text, tool, api_key, cfg)
    validate_payload_against_schema(input_schema, payload)
    return payload
