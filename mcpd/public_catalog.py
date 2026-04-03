#!/usr/bin/env python3
"""Public catalog rendering helpers for mcpd."""

from __future__ import annotations

from typing import Any, Dict, List

try:
    from manifest_loader import AppManifest, ToolManifest
except ModuleNotFoundError:  # pragma: no cover - package import fallback
    from .manifest_loader import AppManifest, ToolManifest


def tool_to_public(tool: ToolManifest) -> Dict[str, Any]:
    return {
        "tool_id": tool.tool_id,
        "name": tool.name,
        "app_id": tool.app_id,
        "app_name": tool.app_name,
        "description": tool.description,
        "input_schema": tool.input_schema,
        "examples": tool.examples,
        "path_semantics": tool.path_semantics,
        "approval_policy": tool.approval_policy,
        "risk_tags": tool.risk_tags,
        "risk_flags": tool.risk_flags,
        "hash": tool.manifest_hash,
    }


def app_to_public(app: AppManifest) -> Dict[str, Any]:
    ordered = sorted(app.tools, key=lambda item: item.tool_id)
    return {
        "app_id": app.app_id,
        "app_name": app.app_name,
        "tool_count": len(ordered),
        "tool_ids": [tool.tool_id for tool in ordered],
        "tool_names": [tool.name for tool in ordered],
    }


def list_apps_public(apps: List[AppManifest]) -> List[Dict[str, Any]]:
    return [app_to_public(app) for app in sorted(apps, key=lambda item: item.app_id)]


def list_tools_public(tools: List[ToolManifest]) -> List[Dict[str, Any]]:
    return [tool_to_public(tool) for tool in sorted(tools, key=lambda item: item.tool_id)]
