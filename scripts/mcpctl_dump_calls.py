#!/usr/bin/env python3
"""Decode /sys/kernel/mcp/agents/<agent>/call_log into readable rows.

The kernel module writes fixed-size binary records whose layout is defined in
kernel-mcp/include/uapi/linux/kernel_mcp_schema.h and mirrored by the
CALL_* constants in client/kernel_mcp/schema.py. This tool reads that blob,
parses it, and prints one row per record in chronological order.

Typical use: after mcpd has crashed or been stopped, invoke

    sudo scripts/mcpctl_dump_calls.py <agent_id>

to inspect the last few arbitrations/executions the kernel observed.
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.kernel_mcp.schema import (
    CALL_ERR_HEAD_MAX,
    CALL_HASH_PREFIX,
    CALL_LOG_SIZE,
    CALL_STATUS_DEFER,
    CALL_STATUS_DENY,
    CALL_STATUS_ERR,
    CALL_STATUS_OK,
    TOOL_STATUS_LABELS,
)

# struct kernel_mcp_call_record layout (little-endian on all supported arches).
# u64 seq; u64 timestamp_ns; u64 req_id; u32 tool_id; u32 status; u32 exec_ms;
# u32 tool_status_code; u8 payload_hash[8]; u8 response_hash[8]; u8 err_head[48];
# Note: the last u32 was named "reserved" before the tool_status_code rename.
# Binary layout is identical; older decoders read it as 0 (= UNSPECIFIED).
RECORD_FMT = f"<QQQIIII{CALL_HASH_PREFIX}s{CALL_HASH_PREFIX}s{CALL_ERR_HEAD_MAX}s"
RECORD_SIZE = struct.calcsize(RECORD_FMT)

_STATUS_LABELS = {
    CALL_STATUS_OK: "OK",
    CALL_STATUS_ERR: "ERR",
    CALL_STATUS_DENY: "DENY",
    CALL_STATUS_DEFER: "DEFER",
}


def _format_err_head(raw: bytes) -> str:
    text = raw.rstrip(b"\x00").decode("utf-8", errors="replace")
    return text.replace("\n", "\\n").replace("\t", "\\t")


def _format_record(rec: tuple) -> str:
    seq, ts_ns, req_id, tool_id, status, exec_ms, tsc, ph, rh, err = rec
    status_label = _STATUS_LABELS.get(status, f"?{status}")
    tsc_label = TOOL_STATUS_LABELS.get(tsc, f"?{tsc}")
    ts_ms = ts_ns // 1_000_000
    return (
        f"seq={seq:>5} ts_ms={ts_ms:<16} req={req_id:<20} tool={tool_id:<5} "
        f"status={status_label:<5} tsc={tsc_label:<13} exec_ms={exec_ms:<6} "
        f"payload={ph.hex()} response={rh.hex()} err=\"{_format_err_head(err)}\""
    )


def _sysfs_path(agent_id: str) -> Path:
    return Path(f"/sys/kernel/mcp/agents/{agent_id}/call_log")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent_id", help="agent id as shown in /sys/kernel/mcp/agents/")
    parser.add_argument(
        "--raw",
        action="store_true",
        help="emit records as hex instead of the parsed view",
    )
    args = parser.parse_args(argv)

    path = _sysfs_path(args.agent_id)
    try:
        blob = path.read_bytes()
    except FileNotFoundError:
        print(f"call_log not found: {path}", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"permission denied reading {path}; try sudo", file=sys.stderr)
        return 1

    expected_full = RECORD_SIZE * CALL_LOG_SIZE
    if len(blob) > expected_full:
        print(
            f"warning: call_log is larger than expected ({len(blob)} > {expected_full});"
            " truncating to the expected window",
            file=sys.stderr,
        )
        blob = blob[:expected_full]

    if len(blob) % RECORD_SIZE != 0:
        print(
            f"call_log size {len(blob)} is not a multiple of record size {RECORD_SIZE};"
            " schema drift?",
            file=sys.stderr,
        )
        return 2

    count = len(blob) // RECORD_SIZE
    if count == 0:
        print("(empty call_log)")
        return 0

    for i in range(count):
        chunk = blob[i * RECORD_SIZE:(i + 1) * RECORD_SIZE]
        if args.raw:
            print(chunk.hex())
            continue
        rec = struct.unpack(RECORD_FMT, chunk)
        print(_format_record(rec))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
