#!/usr/bin/env python3
"""Live kernel_mcp observability dashboard.

Reads /sys/kernel/mcp/{agents,tools}/* on a refresh loop and renders a
human-friendly summary of: tool pin state, per-agent counters, and a
tail of the in-kernel call_log. Intended for demos — left terminal
runs the CLI, right terminal runs this and watches the kernel react.

Usage:
    sudo python3 scripts/mcpctl_dashboard.py            # 1s refresh, loop
    sudo python3 scripts/mcpctl_dashboard.py --once     # one snapshot
    sudo python3 scripts/mcpctl_dashboard.py --interval 2

sudo is required because call_log is a binary sysfs attr root reads.
"""
from __future__ import annotations

import argparse
import struct
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.kernel_mcp.schema import (
    CALL_ERR_HEAD_MAX,
    CALL_HASH_PREFIX,
    CALL_STATUS_DEFER,
    CALL_STATUS_DENY,
    CALL_STATUS_ERR,
    CALL_STATUS_OK,
)

SYSFS = Path("/sys/kernel/mcp")
RECORD_FMT = (
    f"<QQQIIII{CALL_HASH_PREFIX}s{CALL_HASH_PREFIX}s{CALL_ERR_HEAD_MAX}s"
)
RECORD_SIZE = struct.calcsize(RECORD_FMT)
STATUS_LABELS = {
    CALL_STATUS_OK: "OK",
    CALL_STATUS_ERR: "ERR",
    CALL_STATUS_DENY: "DENY",
    CALL_STATUS_DEFER: "DEFER",
}

# ANSI palette — keep small, only used when stdout is a TTY.
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"


def _color(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled else text


def _read(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return default


def _read_int(path: Path) -> int:
    raw = _read(path, "")
    try:
        return int(raw)
    except ValueError:
        return 0


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""


def _gather_tools() -> Dict[str, Any]:
    pinned, unpinned, total = 0, 0, 0
    name_by_id: Dict[int, str] = {}
    tools_dir = SYSFS / "tools"
    if tools_dir.is_dir():
        for tdir in tools_dir.iterdir():
            if not tdir.is_dir():
                continue
            try:
                tid = int(tdir.name)
            except ValueError:
                continue
            total += 1
            name_by_id[tid] = _read(tdir / "name") or f"tool#{tid}"
            if _read(tdir / "binary_hash_state") == "live_pinned":
                pinned += 1
            else:
                unpinned += 1
    epoch = _read(SYSFS / "tool_catalog_epoch", "?")
    return {"total": total, "pinned": pinned, "unpinned": unpinned, "epoch": epoch, "names": name_by_id}


def _gather_agents() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    adir = SYSFS / "agents"
    if not adir.is_dir():
        return out
    for ag in sorted(adir.iterdir(), key=lambda p: p.name):
        if not ag.is_dir():
            continue
        out.append(
            {
                "id": ag.name,
                "allow": _read_int(ag / "allow"),
                "deny": _read_int(ag / "deny"),
                "defer": _read_int(ag / "defer"),
                "ok": _read_int(ag / "completed_ok"),
                "err": _read_int(ag / "completed_err"),
                "last_ms": _read_int(ag / "last_exec_ms"),
                "log_count": _read_int(ag / "call_log_count"),
                "path": ag,
            }
        )
    return out


def _parse_call_log(blob: bytes) -> List[Tuple[int, int, int, int, int]]:
    if len(blob) < RECORD_SIZE:
        return []
    n = len(blob) // RECORD_SIZE
    out: List[Tuple[int, int, int, int, int]] = []
    for i in range(n):
        rec = struct.unpack(RECORD_FMT, blob[i * RECORD_SIZE:(i + 1) * RECORD_SIZE])
        seq, ts_ns, _req_id, tool_id, status, exec_ms, _tsc, _ph, _rh, _err = rec
        if seq == 0:
            continue
        out.append((seq, ts_ns, tool_id, status, exec_ms))
    return out


def _gather_recent(agents: List[Dict[str, Any]], names: Dict[int, str], tail: int) -> List[Tuple[int, str, int, str, str, int]]:
    rows: List[Tuple[int, str, int, str, str, int]] = []
    for ag in agents:
        for _seq, ts_ns, tid, status, exec_ms in _parse_call_log(_read_bytes(ag["path"] / "call_log")):
            rows.append(
                (
                    ts_ns // 1_000_000,
                    ag["id"],
                    tid,
                    names.get(tid, f"tool#{tid}"),
                    STATUS_LABELS.get(status, f"?{status}"),
                    exec_ms,
                )
            )
    rows.sort(key=lambda r: r[0])
    return rows[-tail:]


def _format_dashboard(state: Dict[str, Any], color: bool) -> str:
    lines: List[str] = []
    rule = "─" * 78
    lines.append(_color(rule, CYAN, color))
    lines.append(_color(f"  kernel_mcp live  •  {state['refresh_at']}  •  Ctrl+C to exit", BOLD + CYAN, color))
    lines.append(_color(rule, CYAN, color))

    t = state["tools"]
    summary = (
        f"  tools: {t['total']:>3} registered    "
        f"{_color(f'pinned: {t['pinned']:>3}', GREEN, color)}    "
        f"{_color(f'unpinned: {t['unpinned']:>3}', YELLOW, color)}    "
        f"epoch: {t['epoch']}"
    )
    lines.append(summary)
    lines.append("")

    agents = state["agents"]
    lines.append(_color(f"  agents ({len(agents)} known, recent {min(8, len(agents))}):", BOLD, color))
    lines.append(_color(f"    {'id':<32} {'allow':>5} {'deny':>4} {'defer':>5} {'ok':>4} {'err':>3} {'last':>7}", DIM, color))
    for ag in agents[-8:]:
        deny_str = _color(f"{ag['deny']:>4}", RED if ag["deny"] else "", color and ag["deny"] > 0)
        defer_str = _color(f"{ag['defer']:>5}", YELLOW if ag["defer"] else "", color and ag["defer"] > 0)
        lines.append(
            f"    {ag['id'][:32]:<32} {ag['allow']:>5} {deny_str} {defer_str} "
            f"{ag['ok']:>4} {ag['err']:>3} {ag['last_ms']:>5}ms"
        )
    lines.append("")

    lines.append(_color(f"  recent decisions (tail {len(state['recent'])}):", BOLD, color))
    lines.append(_color(f"    {'time':<12}  {'agent':<22}  {'tool':<5} {'name':<28} {'status':<6} {'exec':>5}", DIM, color))
    for ts_ms, agent_id, tid, tname, status, exec_ms in state["recent"]:
        ts_local = time.strftime("%H:%M:%S", time.localtime(ts_ms / 1000.0))
        ts_label = f"{ts_local}.{ts_ms % 1000:03d}"
        if status == "OK":
            sc = GREEN
        elif status == "DEFER":
            sc = YELLOW
        elif status in ("DENY", "ERR"):
            sc = RED
        else:
            sc = ""
        status_str = _color(f"{status:<6}", sc, color and bool(sc))
        lines.append(
            f"    {ts_label:<12}  {agent_id[:22]:<22}  #{tid:<4} {tname[:28]:<28} {status_str} {exec_ms:>4}ms"
        )
    if not state["recent"]:
        lines.append(_color("    (no calls in kernel call_log yet)", DIM, color))

    return "\n".join(lines)


def gather() -> Dict[str, Any]:
    tools = _gather_tools()
    agents = _gather_agents()
    recent = _gather_recent(agents, tools["names"], tail=12)
    return {
        "tools": tools,
        "agents": agents,
        "recent": recent,
        "refresh_at": time.strftime("%H:%M:%S"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval", type=float, default=1.0, help="refresh seconds (default 1.0)")
    parser.add_argument("--once", action="store_true", help="print one snapshot and exit")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color")
    args = parser.parse_args()

    if not SYSFS.is_dir():
        print(f"kernel_mcp module not loaded ({SYSFS} missing)", file=sys.stderr)
        return 1

    color = sys.stdout.isatty() and not args.no_color

    try:
        while True:
            state = gather()
            if not args.once and color:
                # Clear screen + home cursor
                sys.stdout.write("\033[2J\033[H")
            print(_format_dashboard(state, color), flush=True)
            if args.once:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
