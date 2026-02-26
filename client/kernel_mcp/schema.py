"""Shared Generic Netlink schema constants for Kernel MCP."""

from __future__ import annotations

from typing import Final

FAMILY_NAME: Final[str] = "KERNEL_MCP"
FAMILY_VERSION: Final[int] = 1

CMD: Final[dict[str, int]] = {
    "UNSPEC": 0,
    "PING": 1,
    "PONG": 2,
    "TOOL_REGISTER": 3,
    "TOOL_UNREGISTER": 4,
    "TOKEN_ACQUIRE": 5,
    "TOKEN_RELEASE": 6,
    "AUDIT_QUERY": 7,
    "LIST_TOOLS": 8,
    "AGENT_REGISTER": 9,
    "TOOL_REQUEST": 10,
    "TOOL_DECISION": 11,
    "TOOL_COMPLETE": 12,
}

ATTR: Final[dict[str, int]] = {
    "UNSPEC": 0,
    "REQ_ID": 1,
    "TOOL_ID": 2,
    "TOOL_NAME": 3,
    "AGENT_ID": 4,
    "TOKEN_COST": 5,
    "TOKENS_LEFT": 6,
    "STATUS": 7,
    "MESSAGE": 8,
    "UNIX_SOCK_PATH": 9,
    "PAYLOAD_LEN": 10,
    "AUDIT_SEQ": 11,
    "TS_NS": 12,
    "TOOL_PERM": 13,
    "TOOL_COST": 14,
    "PID": 15,
    "UID": 16,
    "DECISION": 17,
    "WAIT_MS": 18,
    "TOOL_HASH": 19,
    "EXEC_MS": 20,
}
