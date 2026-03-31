#!/usr/bin/env python3
"""Demo Settings App exposed over UDS RPC."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve

MAX_BURN_MS = 10_000
MIN_LEVEL = 0
MAX_LEVEL = 100


def cpu_burn(payload: Dict[str, Any]) -> Dict[str, Any]:
    ms_raw = payload.get("ms")
    if isinstance(ms_raw, bool) or not isinstance(ms_raw, int):
        raise ValueError("cpu_burn payload.ms must be integer")
    ms = max(0, min(MAX_BURN_MS, ms_raw))
    start = time.perf_counter()
    target = start + (ms / 1000.0)
    x = 0
    while time.perf_counter() < target:
        x = (x * 1664525 + 1013904223) & 0xFFFFFFFF
    _ = x
    actual_ms = int((time.perf_counter() - start) * 1000)
    return {"burned_ms": ms, "actual_ms": actual_ms}


def _read_uptime_seconds() -> float:
    try:
        raw = Path("/proc/uptime").read_text(encoding="utf-8").strip()
        return float(raw.split()[0])
    except Exception:
        return 0.0


def _read_meminfo_mb() -> Dict[str, float]:
    out = {"total_mb": 0.0, "available_mb": 0.0}
    try:
        lines = Path("/proc/meminfo").read_text(encoding="utf-8").splitlines()
        kv: Dict[str, int] = {}
        for line in lines:
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                kv[parts[0].rstrip(":")] = int(parts[1])
        out["total_mb"] = round(kv.get("MemTotal", 0) / 1024.0, 2)
        out["available_mb"] = round(kv.get("MemAvailable", 0) / 1024.0, 2)
    except Exception:
        return out
    return out


def sys_info(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw_path = payload.get("path", "")
    if raw_path in ("", None):
        target = Path.cwd()
    elif isinstance(raw_path, str):
        target = Path(raw_path).expanduser()
    else:
        raise ValueError("sys_info payload.path must be string when provided")
    if target.is_file():
        target = target.parent
    target = target.resolve()
    if not target.exists():
        raise ValueError(f"path does not exist: {target}")

    disk = shutil.disk_usage(target)
    mem = _read_meminfo_mb()
    try:
        load_avg = os.getloadavg()
    except Exception:
        load_avg = (0.0, 0.0, 0.0)
    return {
        "hostname": platform.node(),
        "kernel": platform.release(),
        "platform": platform.platform(),
        "cwd": str(Path.cwd()),
        "target_path": str(target),
        "cpu_count_logical": os.cpu_count(),
        "loadavg_1m": round(load_avg[0], 3),
        "loadavg_5m": round(load_avg[1], 3),
        "loadavg_15m": round(load_avg[2], 3),
        "mem_total_mb": mem["total_mb"],
        "mem_available_mb": mem["available_mb"],
        "disk_total_gb": round(disk.total / (1024.0**3), 3),
        "disk_used_gb": round(disk.used / (1024.0**3), 3),
        "disk_free_gb": round(disk.free / (1024.0**3), 3),
        "uptime_sec": round(_read_uptime_seconds(), 2),
        "epoch_s": int(time.time()),
    }


def time_now(payload: Dict[str, Any]) -> Dict[str, Any]:
    timezone_hint = payload.get("timezone", "local")
    if not isinstance(timezone_hint, str):
        raise ValueError("time_now payload.timezone must be string")
    timezone_hint = timezone_hint.lower().strip()
    if timezone_hint not in {"local", "utc"}:
        raise ValueError("timezone must be one of: local, utc")
    now_local = datetime.now().astimezone()
    now_utc = datetime.now(timezone.utc)
    selected = now_local if timezone_hint == "local" else now_utc
    return {
        "requested_timezone": timezone_hint,
        "now_iso": selected.isoformat(),
        "local_iso": now_local.isoformat(),
        "utc_iso": now_utc.isoformat(),
        "weekday": selected.strftime("%A"),
        "epoch_s": int(time.time()),
    }


def _run_cmd(args: list[str]) -> str:
    proc = subprocess.run(args, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise ValueError(
            f"command failed: {' '.join(args)} stderr={proc.stderr.strip() or '<empty>'}"
        )
    return proc.stdout


def _parse_percent(text: str) -> int:
    match = re.search(r"(\d{1,3})%", text)
    if not match:
        raise ValueError(f"unable to parse volume percentage from: {text!r}")
    return max(MIN_LEVEL, min(MAX_LEVEL, int(match.group(1))))


def _backend() -> str:
    if shutil.which("pactl"):
        return "pactl"
    if shutil.which("amixer"):
        return "amixer"
    raise ValueError("no supported audio backend found (need pactl or amixer)")


def _get_volume(backend: str) -> int:
    if backend == "pactl":
        return _parse_percent(_run_cmd(["pactl", "get-sink-volume", "@DEFAULT_SINK@"]))
    return _parse_percent(_run_cmd(["amixer", "sget", "Master"]))


def _set_volume(backend: str, level: int) -> None:
    pct = f"{level}%"
    if backend == "pactl":
        _run_cmd(["pactl", "set-sink-volume", "@DEFAULT_SINK@", pct])
        return
    _run_cmd(["amixer", "sset", "Master", pct])


def _change_volume(backend: str, step: int) -> None:
    token = f"{abs(step)}%{'+' if step >= 0 else '-'}"
    if backend == "pactl":
        _run_cmd(["pactl", "set-sink-volume", "@DEFAULT_SINK@", token])
        return
    _run_cmd(["amixer", "sset", "Master", token])


def _set_mute(backend: str, mute: bool) -> None:
    state = "1" if mute else "0"
    if backend == "pactl":
        _run_cmd(["pactl", "set-sink-mute", "@DEFAULT_SINK@", state])
        return
    _run_cmd(["amixer", "set", "Master", "mute" if mute else "unmute"])


def _normalize_volume(payload: Dict[str, Any]) -> Tuple[str, int, int]:
    action = payload.get("action", "get")
    if not isinstance(action, str):
        raise ValueError("volume_control payload.action must be string")
    action = action.lower().strip()
    if action not in {"get", "set", "change", "mute", "unmute"}:
        raise ValueError("action must be one of: get,set,change,mute,unmute")
    level = payload.get("level", 50)
    step = payload.get("step", 10)
    if isinstance(level, bool) or not isinstance(level, int):
        raise ValueError("volume_control payload.level must be integer")
    if isinstance(step, bool) or not isinstance(step, int):
        raise ValueError("volume_control payload.step must be integer")
    return action, max(MIN_LEVEL, min(MAX_LEVEL, level)), max(-100, min(100, step))


def volume_control(payload: Dict[str, Any]) -> Dict[str, Any]:
    action, level, step = _normalize_volume(payload)
    backend = _backend()
    if action == "set":
        _set_volume(backend, level)
    elif action == "change":
        _change_volume(backend, step)
    elif action == "mute":
        _set_mute(backend, True)
    elif action == "unmute":
        _set_mute(backend, False)
    return {"backend": backend, "action": action, "current_level": _get_volume(backend)}


OPERATIONS = {
    "cpu_burn": cpu_burn,
    "sys_info": sys_info,
    "time_now": time_now,
    "volume_control": volume_control,
}


def main() -> int:
    args = parse_args()
    return serve(args.manifest, OPERATIONS)


if __name__ == "__main__":
    raise SystemExit(main())
