# Kernel MCP Generic Netlink Schema (Stable Contract)

This document defines the stable Generic Netlink command/attribute IDs shared by:

- C (kernel module and daemon headers)
- Python (client library)

Rules:

1. IDs are append-only.
2. Existing numeric IDs MUST NEVER be renumbered.
3. Gaps are allowed; reuse is forbidden.
4. Netlink is control-plane only. Large data must go over Unix Domain Socket.
5. Kernel never parses JSON.

## Family

- Family name: `KERNEL_MCP`
- Family version: `1`

## Commands

| Name | ID | Direction | Notes |
|---|---:|---|---|
| `KERNEL_MCP_CMD_UNSPEC` | 0 | n/a | Reserved |
| `KERNEL_MCP_CMD_PING` | 1 | user -> kernel | Liveness probe |
| `KERNEL_MCP_CMD_PONG` | 2 | kernel -> user | Optional reply event |
| `KERNEL_MCP_CMD_TOOL_REGISTER` | 3 | user -> kernel | Register tool metadata |
| `KERNEL_MCP_CMD_TOOL_UNREGISTER` | 4 | user -> kernel | Unregister tool |
| `KERNEL_MCP_CMD_TOKEN_ACQUIRE` | 5 | user -> kernel | Request tokens |
| `KERNEL_MCP_CMD_TOKEN_RELEASE` | 6 | user -> kernel | Return tokens |
| `KERNEL_MCP_CMD_AUDIT_QUERY` | 7 | user -> kernel | Query audit metadata |
| `KERNEL_MCP_CMD_LIST_TOOLS` | 8 | user -> kernel | Dump registered tools |
| `KERNEL_MCP_CMD_AGENT_REGISTER` | 9 | user -> kernel | Register agent identity |
| `KERNEL_MCP_CMD_TOOL_REQUEST` | 10 | user -> kernel | Request tool arbitration |
| `KERNEL_MCP_CMD_TOOL_DECISION` | 11 | kernel -> user | Arbitration result |
| `KERNEL_MCP_CMD_TOOL_COMPLETE` | 12 | user -> kernel | Report tool execution completion |

## Attributes

| Name | ID | Type | Notes |
|---|---:|---|---|
| `KERNEL_MCP_ATTR_UNSPEC` | 0 | n/a | Reserved |
| `KERNEL_MCP_ATTR_REQ_ID` | 1 | `u64` | Request correlation ID |
| `KERNEL_MCP_ATTR_TOOL_ID` | 2 | `u32` | Internal tool ID |
| `KERNEL_MCP_ATTR_TOOL_NAME` | 3 | string | Tool name |
| `KERNEL_MCP_ATTR_AGENT_ID` | 4 | string | Agent identity |
| `KERNEL_MCP_ATTR_TOKEN_COST` | 5 | `u32` | Requested/used tokens |
| `KERNEL_MCP_ATTR_TOKENS_LEFT` | 6 | `u32` | Remaining bucket tokens |
| `KERNEL_MCP_ATTR_STATUS` | 7 | `u32` | Status code |
| `KERNEL_MCP_ATTR_MESSAGE` | 8 | string | Status text or Phase 1 ping/pong payload |
| `KERNEL_MCP_ATTR_UNIX_SOCK_PATH` | 9 | string | Data-plane UDS path |
| `KERNEL_MCP_ATTR_PAYLOAD_LEN` | 10 | `u32` | Optional payload byte length |
| `KERNEL_MCP_ATTR_AUDIT_SEQ` | 11 | `u64` | Audit sequence number |
| `KERNEL_MCP_ATTR_TS_NS` | 12 | `u64` | Timestamp in ns |
| `KERNEL_MCP_ATTR_TOOL_PERM` | 13 | `u32` | Tool permission bitmask |
| `KERNEL_MCP_ATTR_TOOL_COST` | 14 | `u32` | Tool token cost |
| `KERNEL_MCP_ATTR_PID` | 15 | `u32` | Agent process id |
| `KERNEL_MCP_ATTR_UID` | 16 | `u32` | Agent user id |
| `KERNEL_MCP_ATTR_DECISION` | 17 | `u32` | Decision enum (`ALLOW=1`,`DENY=2`,`DEFER=3`) |
| `KERNEL_MCP_ATTR_WAIT_MS` | 18 | `u32` | Suggested wait in ms for deferred request |
| `KERNEL_MCP_ATTR_TOOL_HASH` | 19 | string | Tool semantic hash (up to 16 bytes) |
| `KERNEL_MCP_ATTR_EXEC_MS` | 20 | `u32` | Tool execution elapsed time in ms |

## Reserved Ranges

- Commands `128-255`: reserved for future private extensions.
- Attributes `128-255`: reserved for future private extensions.

## Phase 1 Ping/Pong Behavior

- Request: `KERNEL_MCP_CMD_PING`
  - Optional `KERNEL_MCP_ATTR_REQ_ID` (`u64`)
  - Optional `KERNEL_MCP_ATTR_MESSAGE` (string payload)
- Response: `KERNEL_MCP_CMD_PONG`
  - `KERNEL_MCP_ATTR_STATUS` (`u32`, `0` on success)
  - Echoed `KERNEL_MCP_ATTR_REQ_ID` when present
  - Echoed `KERNEL_MCP_ATTR_MESSAGE` payload
  - `KERNEL_MCP_ATTR_PAYLOAD_LEN` (`u32`) = payload length in bytes (without trailing `\0`)

## Phase 2 Tool Registration Behavior

- Request: `KERNEL_MCP_CMD_TOOL_REGISTER`
  - Required `KERNEL_MCP_ATTR_TOOL_ID` (`u32`)
  - Required `KERNEL_MCP_ATTR_TOOL_NAME` (string)
  - Required `KERNEL_MCP_ATTR_TOOL_PERM` (`u32`)
  - Required `KERNEL_MCP_ATTR_TOOL_COST` (`u32`)
  - Optional `KERNEL_MCP_ATTR_TOOL_HASH` (string, semantic hash)
- Duplicate register on same `TOOL_ID`: update existing record in place.
- Dump: `KERNEL_MCP_CMD_LIST_TOOLS` (NLM_F_DUMP)
  - Per entry returns: `TOOL_ID`, `TOOL_NAME`, `TOOL_PERM`, `TOOL_COST`, `STATUS`, optional `TOOL_HASH`.

## Phase 3 Agent + Arbitration Behavior

- Request: `KERNEL_MCP_CMD_AGENT_REGISTER`
  - Required: `AGENT_ID`, `PID`
  - Optional: `UID`, `REQ_ID`
- Request: `KERNEL_MCP_CMD_TOOL_REQUEST`
  - Required: `AGENT_ID`, `TOOL_ID`, `REQ_ID`
  - Optional: `TOOL_HASH` (when provided, kernel may verify semantic hash against tool registry)
- Response: `KERNEL_MCP_CMD_TOOL_DECISION`
  - `DECISION` (`ALLOW=1`,`DENY=2`,`DEFER=3`)
  - `WAIT_MS` (used when `DEFER`)
  - `MESSAGE` reason string
- Request: `KERNEL_MCP_CMD_TOOL_COMPLETE`
  - Required: `REQ_ID`, `AGENT_ID`, `TOOL_ID`, `STATUS`, `EXEC_MS`
  - Reports user-space tool execution result back to kernel audit counters.
- Tool `2` (`cpu_burn`) uses per-agent token bucket:
  - `max_tokens=2`
  - lazy refill `+1` token per `5s` based on `jiffies` delta on each request
  - no timer_list / kernel thread
