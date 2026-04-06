"""Shared Generic Netlink schema constants for Kernel MCP."""

from __future__ import annotations

from typing import Final

FAMILY_NAME: Final[str] = "KERNEL_MCP"
FAMILY_VERSION: Final[int] = 1

CMD: Final[dict[str, int]] = {
    "UNSPEC": 0,
    "TOOL_REGISTER": 3,
    "LIST_TOOLS": 8,
    "AGENT_REGISTER": 9,
    "TOOL_REQUEST": 10,
    "TOOL_DECISION": 11,
    "TOOL_COMPLETE": 12,
    "APPROVAL_DECIDE": 13,
    "RESET_TOOLS": 14,
}

ATTR: Final[dict[str, int]] = {
    "UNSPEC": 0,
    "REQ_ID": 1,
    "TOOL_ID": 2,
    "TOOL_NAME": 3,
    "AGENT_ID": 4,
    "STATUS": 7,
    "MESSAGE": 8,
    "PID": 15,
    "UID": 16,
    "DECISION": 17,
    "TOOL_HASH": 19,
    "EXEC_MS": 20,
    "TOOL_RISK_FLAGS": 21,
    "TICKET_ID": 22,
    "APPROVAL_DECISION": 23,
    "APPROVER": 24,
    "APPROVAL_REASON": 25,
    "APPROVAL_TTL_MS": 26,
    "POLICY_ID": 27,
    "AGENT_BINDING": 28,
    "AGENT_EPOCH": 29,
    "EXPERIMENT_FLAGS": 30,
}
