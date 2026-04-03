#!/usr/bin/env python3
"""Shared manifest loading for mcpd runtime and kernel reconciliation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

try:
    from schema_utils import ensure_int, ensure_non_empty_str
    from risk import normalize_risk_tags, risk_flags_from_tags
except ModuleNotFoundError:  # pragma: no cover - package import fallback
    from .schema_utils import ensure_int, ensure_non_empty_str
    from .risk import normalize_risk_tags, risk_flags_from_tags

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST_DIR = ROOT_DIR / "tool-app" / "manifests"
SEMANTIC_HASH_FIELDS = (
    "tool_id",
    "name",
    "app_id",
    "app_name",
    "risk_tags",
    "description",
    "input_schema",
    "examples",
    "path_semantics",
    "approval_policy",
)


@dataclass(frozen=True)
class ToolManifest:
    tool_id: int
    name: str
    app_id: str
    app_name: str
    risk_tags: List[str]
    risk_flags: int
    description: str
    input_schema: Dict[str, Any]
    examples: List[Any]
    path_semantics: Dict[str, str]
    approval_policy: Dict[str, Any]
    transport: str
    endpoint: str
    operation: str
    timeout_ms: int
    manifest_hash: str


@dataclass(frozen=True)
class AppManifest:
    app_id: str
    app_name: str
    transport: str
    endpoint: str
    tools: List[ToolManifest]
    source: str


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _semantic_hash(tool: Dict[str, Any], path: Path) -> str:
    semantic: Dict[str, Any] = {}
    for field in SEMANTIC_HASH_FIELDS:
        if field not in tool:
            raise ValueError(f"{path}: missing semantic hash field '{field}'")
        semantic[field] = tool[field]
    return hashlib.sha256(_canonical_json_bytes(semantic)).hexdigest()[:8]


def _ensure_non_empty_str_path(name: str, value: Any, path: Path) -> str:
    try:
        return ensure_non_empty_str(name, value)
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc


def _ensure_rel_tool_path(name: str, value: Any, path: Path) -> str:
    text = _ensure_non_empty_str_path(name, value, path)
    if text.startswith("/"):
        raise ValueError(f"{path}: {name} must be relative to repo root")
    return text


def _load_tool(
    raw: Dict[str, Any],
    *,
    app_id: str,
    app_name: str,
    transport: str,
    endpoint: str,
    path: Path,
) -> ToolManifest:
    required = (
        "tool_id",
        "name",
        "risk_tags",
        "operation",
        "description",
        "input_schema",
        "examples",
    )
    for field in required:
        if field not in raw:
            raise ValueError(f"{path}: tool missing field '{field}'")

    tool_id = ensure_int("tool_id", raw["tool_id"])
    timeout_ms = ensure_int("timeout_ms", raw.get("timeout_ms", 30_000))
    if timeout_ms <= 0:
        raise ValueError(f"{path}: timeout_ms must be positive")

    name = ensure_non_empty_str("name", raw["name"])
    risk_tags = normalize_risk_tags(raw["risk_tags"], source=str(path))
    operation = ensure_non_empty_str("operation", raw["operation"])
    description = ensure_non_empty_str("description", raw["description"])
    input_schema = raw["input_schema"]
    examples = raw["examples"]
    if not isinstance(input_schema, dict):
        raise ValueError(f"{path}: input_schema must be object")
    if not isinstance(examples, list):
        raise ValueError(f"{path}: examples must be list")
    path_semantics = raw.get("path_semantics", {})
    approval_policy = raw.get("approval_policy", {})
    if not isinstance(path_semantics, dict):
        raise ValueError(f"{path}: path_semantics must be object")
    if not isinstance(approval_policy, dict):
        raise ValueError(f"{path}: approval_policy must be object")
    normalized_path_semantics: Dict[str, str] = {}
    for field_name, field_mode in path_semantics.items():
        if not isinstance(field_name, str) or not field_name:
            raise ValueError(f"{path}: path_semantics field names must be non-empty strings")
        if not isinstance(field_mode, str) or not field_mode:
            raise ValueError(f"{path}: path_semantics values must be non-empty strings")
        normalized_path_semantics[field_name] = field_mode
    user_confirmation = approval_policy.get("user_confirmation", {})
    if user_confirmation not in ({}, None) and not isinstance(user_confirmation, dict):
        raise ValueError(f"{path}: approval_policy.user_confirmation must be object")
    normalized_approval_policy: Dict[str, Any] = {}
    if isinstance(user_confirmation, dict) and user_confirmation:
        when = ensure_non_empty_str("when", user_confirmation.get("when", ""))
        if when not in {"always", "path_outside_repo"}:
            raise ValueError(
                f"{path}: approval_policy.user_confirmation.when must be one of always,path_outside_repo"
            )
        path_fields = user_confirmation.get("path_fields", [])
        if not isinstance(path_fields, list) or not all(
            isinstance(item, str) and item for item in path_fields
        ):
            raise ValueError(
                f"{path}: approval_policy.user_confirmation.path_fields must be list[str]"
            )
        reason = ensure_non_empty_str("reason", user_confirmation.get("reason", ""))
        normalized_approval_policy = {
            "user_confirmation": {
                "when": when,
                "path_fields": path_fields,
                "reason": reason,
            }
        }

    semantic_raw: Dict[str, Any] = {
        "tool_id": tool_id,
        "name": name,
        "app_id": app_id,
        "app_name": app_name,
        "risk_tags": risk_tags,
        "description": description,
        "input_schema": input_schema,
        "examples": examples,
        "path_semantics": normalized_path_semantics,
        "approval_policy": normalized_approval_policy,
    }

    return ToolManifest(
        tool_id=tool_id,
        name=name,
        app_id=app_id,
        app_name=app_name,
        risk_tags=risk_tags,
        risk_flags=risk_flags_from_tags(risk_tags),
        description=description,
        input_schema=input_schema,
        examples=examples,
        path_semantics=normalized_path_semantics,
        approval_policy=normalized_approval_policy,
        transport=transport,
        endpoint=endpoint,
        operation=operation,
        timeout_ms=timeout_ms,
        manifest_hash=_semantic_hash(semantic_raw, path),
    )


def load_app_manifest(path: Path) -> AppManifest:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: manifest must be JSON object")

    required = ("app_id", "app_name", "transport", "endpoint", "tools")
    for field in required:
        if field not in raw:
            raise ValueError(f"{path}: missing field '{field}'")

    app_id = ensure_non_empty_str("app_id", raw["app_id"])
    app_name = ensure_non_empty_str("app_name", raw["app_name"])
    transport = ensure_non_empty_str("transport", raw["transport"])
    endpoint = ensure_non_empty_str("endpoint", raw["endpoint"])

    if transport != "uds_rpc":
        raise ValueError(f"{path}: unsupported transport {transport!r}")
    if not endpoint.startswith("/tmp/linux-mcp-apps/"):
        raise ValueError(f"{path}: endpoint must start with /tmp/linux-mcp-apps/")

    demo_entrypoint = raw.get("demo_entrypoint")
    if demo_entrypoint not in ("", None):
        _ensure_rel_tool_path("demo_entrypoint", demo_entrypoint, path)

    tools_raw = raw["tools"]
    if not isinstance(tools_raw, list) or not tools_raw:
        raise ValueError(f"{path}: tools must be non-empty list")

    tools: List[ToolManifest] = []
    seen_ids: set[int] = set()
    seen_names: set[str] = set()
    for item in tools_raw:
        if not isinstance(item, dict):
            raise ValueError(f"{path}: tool item must be object")
        tool = _load_tool(
            item,
            app_id=app_id,
            app_name=app_name,
            transport=transport,
            endpoint=endpoint,
            path=path,
        )
        if tool.tool_id in seen_ids:
            raise ValueError(f"{path}: duplicate tool_id {tool.tool_id}")
        if tool.name in seen_names:
            raise ValueError(f"{path}: duplicate tool name {tool.name!r}")
        seen_ids.add(tool.tool_id)
        seen_names.add(tool.name)
        tools.append(tool)

    return AppManifest(
        app_id=app_id,
        app_name=app_name,
        transport=transport,
        endpoint=endpoint,
        tools=tools,
        source=str(path),
    )


def load_all_manifests(manifest_dir: Path = DEFAULT_MANIFEST_DIR) -> List[AppManifest]:
    if not manifest_dir.is_dir():
        raise ValueError(f"manifest directory missing: {manifest_dir}")

    apps: List[AppManifest] = []
    seen_app_ids: set[str] = set()
    seen_tool_ids: set[int] = set()

    for path in sorted(manifest_dir.glob("*.json")):
        app = load_app_manifest(path)
        if app.app_id in seen_app_ids:
            raise ValueError(f"duplicate app_id in manifests: {app.app_id}")
        seen_app_ids.add(app.app_id)
        for tool in app.tools:
            if tool.tool_id in seen_tool_ids:
                raise ValueError(f"duplicate tool_id in manifests: {tool.tool_id}")
            seen_tool_ids.add(tool.tool_id)
        apps.append(app)

    if not apps:
        raise ValueError(f"no manifests found in {manifest_dir}")
    return apps


def load_all_tools(manifest_dir: Path = DEFAULT_MANIFEST_DIR) -> List[ToolManifest]:
    tools: List[ToolManifest] = []
    for app in load_all_manifests(manifest_dir):
        tools.extend(app.tools)
    return tools
