#!/usr/bin/env python3
"""Small request/schema validation helpers for mcpd."""

from __future__ import annotations

from typing import Any


def ensure_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be int")
    return value


def ensure_non_empty_str(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty string")
    return value


def matches_primitive(expected: str, value: Any) -> bool:
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


def validate_payload(input_schema: dict[str, Any], payload: Any) -> None:
    schema_type = input_schema.get("type")
    if isinstance(schema_type, str) and not matches_primitive(schema_type, payload):
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
        if isinstance(expected_type, str) and not matches_primitive(expected_type, value):
            raise ValueError(f"field '{key}' type mismatch: expected {expected_type}")
