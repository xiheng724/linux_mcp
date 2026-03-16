#!/usr/bin/env python3
"""Structured explainability helpers for broker dispatch planning."""

from __future__ import annotations

from typing import Any, Dict, Mapping


def build_capability_selection_explain(
    capability_domain: str,
    *,
    selector_source: str,
    selector_reason: str,
    preferred_provider_id: str = "",
    compatibility_path: bool = False,
) -> Dict[str, Any]:
    return {
        "capability_domain": capability_domain,
        "selector_source": selector_source,
        "selector_reason": selector_reason,
        "preferred_provider_id": preferred_provider_id,
        "compatibility_path": compatibility_path,
    }


def build_payload_construction_explain(
    *,
    fill_mode: str,
    schema: Mapping[str, Any],
    arg_hints: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> Dict[str, Any]:
    properties = schema.get("properties", {})
    return {
        "fill_mode": fill_mode,
        "schema_type": str(schema.get("type", "object")),
        "schema_properties": sorted(list(properties.keys())) if isinstance(properties, dict) else [],
        "arg_hint_fields": sorted(list(arg_hints.keys())),
        "payload_fields": sorted(list(payload.keys())),
    }


def build_dispatch_explain(
    *,
    capability_request: Mapping[str, Any],
    capability_selection: Mapping[str, Any],
    action_resolution: Mapping[str, Any],
    executor_binding: Mapping[str, Any],
    payload_construction: Mapping[str, Any],
    compatibility_path: bool = False,
) -> Dict[str, Any]:
    return {
        "compatibility_path": compatibility_path,
        "capability_request": dict(capability_request),
        "capability_selection": dict(capability_selection),
        "action_resolution": dict(action_resolution),
        "executor_binding": dict(executor_binding),
        "payload_construction": dict(payload_construction),
    }
