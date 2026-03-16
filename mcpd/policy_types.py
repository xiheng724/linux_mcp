#!/usr/bin/env python3
"""Structured policy decision types for broker-side governance."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    require_approval: bool
    decision: str
    deny_reason: Optional[str] = None
    reason_codes: Tuple[str, ...] = ()
    audit_markers: Tuple[str, ...] = ()
    required_executor_constraints: Dict[str, Any] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "require_approval": self.require_approval,
            "decision": self.decision,
            "deny_reason": self.deny_reason,
            "reason_codes": list(self.reason_codes),
            "audit_markers": list(self.audit_markers),
            "required_executor_constraints": dict(self.required_executor_constraints),
            "details": dict(self.details),
        }
