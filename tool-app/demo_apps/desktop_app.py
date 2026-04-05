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
from real_app_support import resolve_host_path
from sandbox import deny_subprocess_if_sandboxed, simple_sandbox_enabled

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
MAX_CONTENT_BYTES = 1024 * 1024


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
    deny_subprocess_if_sandboxed(args)
    return subprocess.run(args, text=True, capture_output=True, check=False)


def _has_gui_session() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _spawn_cmd(args: list[str]) -> subprocess.Popen[str]:
    deny_subprocess_if_sandboxed(args)
    return subprocess.Popen(  # noqa: S603
        args,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )


def open_url(payload: Dict[str, Any]) -> Dict[str, Any]:
    url = payload.get("url", "")
    if not isinstance(url, str) or not url.strip():
        raise ValueError("open_url payload.url must be non-empty string")
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("open_url only supports absolute http/https URLs")
    if not _has_gui_session():
        raise ValueError("no GUI session available (DISPLAY/WAYLAND_DISPLAY unset)")

    firefox = shutil.which("firefox")
    if firefox is not None:
        proc = _spawn_cmd([firefox, "--new-tab", url.strip()])
        return {"opened": True, "url": url.strip(), "backend": "firefox", "pid": proc.pid}

    candidates = [["xdg-open", url.strip()], ["gio", "open", url.strip()]]
    for args in candidates:
        if shutil.which(args[0]) is None:
            continue
        proc = _spawn_cmd(args)
        return {"opened": True, "url": url.strip(), "backend": args[0], "pid": proc.pid}
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


def write_host_text_file(payload: Dict[str, Any]) -> Dict[str, Any]:
    raw_path = payload.get("path", "")
    content = payload.get("content", "")
    overwrite = payload.get("overwrite", False)
    create_parents = payload.get("create_parents", True)
    if not isinstance(content, str):
        raise ValueError("write_host_text_file payload.content must be string")
    if len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise ValueError(f"content too large (max {MAX_CONTENT_BYTES} bytes)")
    if not isinstance(overwrite, bool) or not isinstance(create_parents, bool):
        raise ValueError("overwrite/create_parents must be boolean")

    target = resolve_host_path(str(raw_path), allow_missing=True)
    if simple_sandbox_enabled():
        try:
            target.relative_to(ROOT_DIR)
        except ValueError as exc:
            raise ValueError(f"simple sandbox blocked host write outside repo: {target}") from exc
    existed = target.exists()
    if existed and target.is_dir():
        raise ValueError(f"path is a directory: {target}")
    if existed and not overwrite:
        raise ValueError(f"file already exists: {target}")
    if create_parents:
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    outside_repo = True
    try:
        target.relative_to(ROOT_DIR)
        outside_repo = False
    except ValueError:
        outside_repo = True
    return {
        "path": str(target),
        "created": not existed,
        "overwritten": existed,
        "size_bytes": target.stat().st_size,
        "outside_repo": outside_repo,
    }


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "desktop_snapshot": desktop_snapshot,
            "open_url": open_url,
            "show_notification": show_notification,
            "write_host_text_file": write_host_text_file,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
