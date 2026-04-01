#!/usr/bin/env python3
"""Demo Desktop App exposed over UDS RPC."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve


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


def desktop_snapshot(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw_path = payload.get("path", "")
    if raw_path in ("", None):
        target = Path.cwd()
    elif isinstance(raw_path, str):
        target = Path(raw_path).expanduser()
    else:
        raise ValueError("desktop_snapshot payload.path must be string when provided")
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
    now_local = datetime.now().astimezone()
    now_utc = datetime.now(timezone.utc)
    return {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "cwd": str(Path.cwd()),
        "target_path": str(target),
        "local_time": now_local.isoformat(),
        "utc_time": now_utc.isoformat(),
        "loadavg_1m": round(load_avg[0], 3),
        "loadavg_5m": round(load_avg[1], 3),
        "loadavg_15m": round(load_avg[2], 3),
        "mem_total_mb": mem["total_mb"],
        "mem_available_mb": mem["available_mb"],
        "disk_total_gb": round(disk.total / (1024.0**3), 3),
        "disk_free_gb": round(disk.free / (1024.0**3), 3),
        "uptime_sec": round(_read_uptime_seconds(), 2),
        "epoch_s": int(time.time()),
    }


def _run_cmd(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)


def open_url(payload: Dict[str, Any]) -> Dict[str, Any]:
    url = payload.get("url", "")
    if not isinstance(url, str) or not url.strip():
        raise ValueError("open_url payload.url must be non-empty string")
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("open_url only supports absolute http/https URLs")

    candidates = [["xdg-open", url.strip()], ["gio", "open", url.strip()]]
    for args in candidates:
        if shutil.which(args[0]) is None:
            continue
        proc = _run_cmd(args)
        if proc.returncode == 0:
            return {"opened": True, "url": url.strip(), "backend": args[0]}
    raise ValueError("no supported URL opener succeeded (need xdg-open or gio)")


def show_notification(payload: Dict[str, Any]) -> Dict[str, Any]:
    title = payload.get("title", "")
    body = payload.get("body", "")
    if not isinstance(title, str) or not title.strip():
        raise ValueError("show_notification payload.title must be non-empty string")
    if not isinstance(body, str):
        raise ValueError("show_notification payload.body must be string")
    if shutil.which("notify-send") is None:
        raise ValueError("notify-send not found on host")
    proc = _run_cmd(["notify-send", title.strip(), body])
    if proc.returncode != 0:
        raise ValueError(f"notify-send failed: {proc.stderr.strip() or '<empty>'}")
    return {"shown": True, "title": title.strip(), "body": body, "backend": "notify-send"}


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "desktop_snapshot": desktop_snapshot,
            "open_url": open_url,
            "show_notification": show_notification,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
