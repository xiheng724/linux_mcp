#!/usr/bin/env python3
"""System information tool app."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict


def _read_uptime_seconds() -> float:
    try:
        raw = Path("/proc/uptime").read_text(encoding="utf-8").strip()
        first = raw.split()[0]
        return float(first)
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
                key = parts[0].rstrip(":")
                kv[key] = int(parts[1])
        out["total_mb"] = round(kv.get("MemTotal", 0) / 1024.0, 2)
        out["available_mb"] = round(kv.get("MemAvailable", 0) / 1024.0, 2)
        return out
    except Exception:
        return out


def run(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("sys_info payload must be object")

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
    load_avg = (0.0, 0.0, 0.0)
    try:
        load_avg = os.getloadavg()
    except Exception:
        pass

    return {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "kernel_release": platform.release(),
        "python": platform.python_version(),
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
        "epoch_ms": int(time.time() * 1000),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdin-json", action="store_true")
    args = parser.parse_args()

    try:
        if args.stdin_json:
            payload = json.loads(sys.stdin.read())
        else:
            payload = {}
        print(json.dumps(run(payload), ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
