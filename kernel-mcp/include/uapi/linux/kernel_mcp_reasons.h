#ifndef _UAPI_LINUX_KERNEL_MCP_REASONS_H
#define _UAPI_LINUX_KERNEL_MCP_REASONS_H

/*
 * Single source of truth for decision-reason strings traveling through the
 * KERNEL_MCP_ATTR_MESSAGE attribute and surfacing in sysfs last_reason /
 * agent call_log. Mirrored verbatim by client/kernel_mcp/reasons.py;
 * scripts/verify_schema_sync.py enforces that the two stay byte-equal.
 *
 * Rules:
 *   - Append-only. Existing strings are load-bearing for acceptance scripts
 *     and experiment-results/*.json snapshots — they must not change.
 *   - Every reason belongs to exactly one category (below).
 *   - Numeric codes are for machine classification and paper tables; they do
 *     NOT travel on the wire. Wire still carries the string.
 *
 * Categories (KERNEL_MCP_REASON_CAT_*):
 *   ALLOW     — the arbitration allowed the request.
 *   ADMISSION — agent/ticket availability at the gate.
 *   IDENTITY  — manifest-hash or backend-binary identity checks.
 *   BINDING   — session binding (hash/epoch) or catalog epoch staleness.
 *   TICKET    — approval-ticket lifecycle errors past the admission step.
 *   OPERATOR  — operator-initiated denial.
 */

#define KERNEL_MCP_REASON_CAT_ALLOW     1
#define KERNEL_MCP_REASON_CAT_ADMISSION 2
#define KERNEL_MCP_REASON_CAT_IDENTITY  3
#define KERNEL_MCP_REASON_CAT_BINDING   4
#define KERNEL_MCP_REASON_CAT_TICKET    5
#define KERNEL_MCP_REASON_CAT_OPERATOR  6

/* ALLOW */
#define KERNEL_MCP_REASON_ALLOW                    "allow"
#define KERNEL_MCP_REASON_ALLOW_APPROVED           "allow_approved"

/* ADMISSION */
#define KERNEL_MCP_REASON_AGENT_UNKNOWN            "deny_unknown_agent"
#define KERNEL_MCP_REASON_APPROVAL_MISSING         "approval_missing"
#define KERNEL_MCP_REASON_APPROVAL_REQUIRED        "require_approval"
#define KERNEL_MCP_REASON_APPROVAL_UNAVAILABLE     "approval_unavailable"

/* IDENTITY */
#define KERNEL_MCP_REASON_HASH_MISMATCH            "hash_mismatch"
#define KERNEL_MCP_REASON_BINARY_MISMATCH          "binary_mismatch"
#define KERNEL_MCP_REASON_PROBE_FAILED             "probe_failed"

/* BINDING */
#define KERNEL_MCP_REASON_BINDING_MISMATCH         "binding_mismatch"
#define KERNEL_MCP_REASON_CATALOG_STALE            "catalog_stale_rebind_required"
#define KERNEL_MCP_REASON_PEER_CRED_MISMATCH       "peer_cred_mismatch"

/* TICKET */
#define KERNEL_MCP_REASON_TICKET_PENDING           "approval_pending"
#define KERNEL_MCP_REASON_TICKET_DENIED            "approval_denied"
#define KERNEL_MCP_REASON_TICKET_UNKNOWN           "approval_ticket_unknown"
#define KERNEL_MCP_REASON_TICKET_CONSUMED          "approval_ticket_consumed"
#define KERNEL_MCP_REASON_TICKET_SCOPE_MISMATCH    "approval_ticket_scope_mismatch"
#define KERNEL_MCP_REASON_TICKET_BINDING_MISMATCH  "approval_ticket_binding_mismatch"
#define KERNEL_MCP_REASON_TICKET_HASH_MISMATCH     "approval_ticket_hash_mismatch"

/* OPERATOR */
#define KERNEL_MCP_REASON_USER_DECLINED            "user_declined"

#endif /* _UAPI_LINUX_KERNEL_MCP_REASONS_H */
