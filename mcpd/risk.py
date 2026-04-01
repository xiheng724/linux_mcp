#!/usr/bin/env python3
"""Shared static risk tag definitions for manifest loading and policy wiring."""

from __future__ import annotations

from typing import Final

RISK_TAG_TO_FLAG: Final[dict[str, int]] = {
    "filesystem_write": 1 << 0,
    "filesystem_delete": 1 << 1,
    "system_mutation": 1 << 2,
    "device_control": 1 << 3,
    "external_network": 1 << 4,
    "sensitive_read": 1 << 5,
    "resource_intensive": 1 << 6,
    "privileged": 1 << 7,
    "irreversible": 1 << 8,
}


def normalize_risk_tags(raw_tags: object, *, source: str) -> list[str]:
    if not isinstance(raw_tags, list):
        raise ValueError(f"{source}: risk_tags must be list[str]")

    normalized: list[str] = []
    seen: set[str] = set()
    for item in raw_tags:
        if not isinstance(item, str) or not item:
            raise ValueError(f"{source}: risk_tags entries must be non-empty strings")
        tag = item.strip()
        if tag not in RISK_TAG_TO_FLAG:
            raise ValueError(
                f"{source}: unsupported risk tag {tag!r}; allowed={sorted(RISK_TAG_TO_FLAG.keys())}"
            )
        if tag in seen:
            raise ValueError(f"{source}: duplicate risk tag {tag!r}")
        seen.add(tag)
        normalized.append(tag)
    return sorted(normalized)


def risk_flags_from_tags(tags: list[str]) -> int:
    flags = 0
    for tag in tags:
        flags |= RISK_TAG_TO_FLAG[tag]
    return flags
