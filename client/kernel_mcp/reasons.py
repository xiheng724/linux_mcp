"""Shared decision-reason taxonomy.

Mirrors kernel-mcp/include/uapi/linux/kernel_mcp_reasons.h byte-for-byte.
scripts/verify_schema_sync.py cross-checks the two files so kernel and
userspace can never drift on reason strings.

Reason strings are load-bearing (experiment-results/*.json, acceptance and
smoke scripts grep for exact literals) — they must stay byte-equal across
renames. This module centralizes the *definition* so free-form literals
disappear from mcpd and llm-app, but does not change the wire format.

Categories:
    ALLOW     — the arbitration allowed the request.
    ADMISSION — agent/ticket availability at the gate.
    IDENTITY  — manifest-hash or backend-binary identity checks.
    BINDING   — session binding (hash/epoch) or catalog epoch staleness.
    TICKET    — approval-ticket lifecycle errors past the admission step.
    OPERATOR  — operator-initiated denial.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


class ReasonCategory(str, enum.Enum):
    ALLOW = "allow"
    ADMISSION = "admission"
    IDENTITY = "identity"
    BINDING = "binding"
    TICKET = "ticket"
    OPERATOR = "operator"


# Numeric codes for machine classification and paper tables; NOT on the wire.
CATEGORY_CODE: Dict[ReasonCategory, int] = {
    ReasonCategory.ALLOW: 1,
    ReasonCategory.ADMISSION: 2,
    ReasonCategory.IDENTITY: 3,
    ReasonCategory.BINDING: 4,
    ReasonCategory.TICKET: 5,
    ReasonCategory.OPERATOR: 6,
}


@dataclass(frozen=True)
class Reason:
    name: str
    category: ReasonCategory

    def __str__(self) -> str:  # behave transparently as the wire string
        return self.name


# --- ALLOW -------------------------------------------------------------------
ALLOW = Reason("allow", ReasonCategory.ALLOW)
ALLOW_APPROVED = Reason("allow_approved", ReasonCategory.ALLOW)

# --- ADMISSION ---------------------------------------------------------------
AGENT_UNKNOWN = Reason("deny_unknown_agent", ReasonCategory.ADMISSION)
APPROVAL_MISSING = Reason("approval_missing", ReasonCategory.ADMISSION)
APPROVAL_REQUIRED = Reason("require_approval", ReasonCategory.ADMISSION)
APPROVAL_UNAVAILABLE = Reason("approval_unavailable", ReasonCategory.ADMISSION)

# --- IDENTITY ----------------------------------------------------------------
HASH_MISMATCH = Reason("hash_mismatch", ReasonCategory.IDENTITY)
BINARY_MISMATCH = Reason("binary_mismatch", ReasonCategory.IDENTITY)
PROBE_FAILED = Reason("probe_failed", ReasonCategory.IDENTITY)

# --- BINDING -----------------------------------------------------------------
BINDING_MISMATCH = Reason("binding_mismatch", ReasonCategory.BINDING)
CATALOG_STALE = Reason("catalog_stale_rebind_required", ReasonCategory.BINDING)

# --- TICKET ------------------------------------------------------------------
TICKET_PENDING = Reason("approval_pending", ReasonCategory.TICKET)
TICKET_DENIED = Reason("approval_denied", ReasonCategory.TICKET)
TICKET_UNKNOWN = Reason("approval_ticket_unknown", ReasonCategory.TICKET)
TICKET_CONSUMED = Reason("approval_ticket_consumed", ReasonCategory.TICKET)
TICKET_SCOPE_MISMATCH = Reason("approval_ticket_scope_mismatch", ReasonCategory.TICKET)
TICKET_BINDING_MISMATCH = Reason("approval_ticket_binding_mismatch", ReasonCategory.TICKET)
TICKET_HASH_MISMATCH = Reason("approval_ticket_hash_mismatch", ReasonCategory.TICKET)

# --- OPERATOR ----------------------------------------------------------------
USER_DECLINED = Reason("user_declined", ReasonCategory.OPERATOR)


_ALL_REASONS: Tuple[Reason, ...] = (
    ALLOW, ALLOW_APPROVED,
    AGENT_UNKNOWN, APPROVAL_MISSING, APPROVAL_REQUIRED, APPROVAL_UNAVAILABLE,
    HASH_MISMATCH, BINARY_MISMATCH, PROBE_FAILED,
    BINDING_MISMATCH, CATALOG_STALE,
    TICKET_PENDING, TICKET_DENIED, TICKET_UNKNOWN, TICKET_CONSUMED,
    TICKET_SCOPE_MISMATCH, TICKET_BINDING_MISMATCH, TICKET_HASH_MISMATCH,
    USER_DECLINED,
)

BY_NAME: Dict[str, Reason] = {r.name: r for r in _ALL_REASONS}


def classify(reason_str: Optional[str]) -> Optional[ReasonCategory]:
    """Look up the category for a wire reason string. Returns None for
    unknown strings so that kernel<->userspace mismatch surfaces as a log
    warning instead of a crash — callers that want strict enforcement
    should assert the return value is not None.
    """
    if not reason_str:
        return None
    reason = BY_NAME.get(reason_str)
    return reason.category if reason else None


__all__ = [
    "Reason",
    "ReasonCategory",
    "CATEGORY_CODE",
    "BY_NAME",
    "classify",
    "ALLOW", "ALLOW_APPROVED",
    "AGENT_UNKNOWN", "APPROVAL_MISSING", "APPROVAL_REQUIRED", "APPROVAL_UNAVAILABLE",
    "HASH_MISMATCH", "BINARY_MISMATCH", "PROBE_FAILED",
    "BINDING_MISMATCH", "CATALOG_STALE",
    "TICKET_PENDING", "TICKET_DENIED", "TICKET_UNKNOWN", "TICKET_CONSUMED",
    "TICKET_SCOPE_MISMATCH", "TICKET_BINDING_MISMATCH", "TICKET_HASH_MISMATCH",
    "USER_DECLINED",
]
