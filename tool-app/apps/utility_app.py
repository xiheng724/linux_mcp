#!/usr/bin/env python3
"""Utility App handlers."""

from __future__ import annotations

from typing import Any, Callable, Dict


def echo(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("echo payload must be object")
    return payload


HANDLERS: Dict[str, Callable[[Any], Dict[str, Any]]] = {
    "echo": echo,
}

