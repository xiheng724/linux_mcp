#!/usr/bin/env python3
"""Optional lightweight sandbox helpers for demo tool services."""

from __future__ import annotations

import ctypes
import os
import resource
from typing import Sequence

PR_SET_NO_NEW_PRIVS = 38


def simple_sandbox_enabled() -> bool:
    raw = os.getenv("LINUX_MCP_SIMPLE_SANDBOX", "").strip().lower()
    return raw in {"1", "true", "yes", "on", "simple"}


def sandbox_fsize_limit_bytes() -> int:
    raw = os.getenv("LINUX_MCP_SANDBOX_FSIZE_BYTES", "").strip()
    if not raw:
        return 1024 * 1024
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("LINUX_MCP_SANDBOX_FSIZE_BYTES must be an integer") from exc
    if value <= 0:
        raise ValueError("LINUX_MCP_SANDBOX_FSIZE_BYTES must be positive")
    return value


def apply_process_sandbox() -> None:
    if not simple_sandbox_enabled():
        return
    limit_bytes = sandbox_fsize_limit_bytes()
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit_bytes, limit_bytes))
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if result != 0:
            errno_value = ctypes.get_errno()
            raise OSError(errno_value, os.strerror(errno_value))
    except Exception:
        # Keep the sandbox best-effort so experiments still run on hosts where
        # prctl is unavailable or blocked.
        return


def deny_subprocess_if_sandboxed(args: Sequence[str]) -> None:
    if not simple_sandbox_enabled():
        return
    rendered = " ".join(str(item) for item in args)
    raise ValueError(f"simple sandbox blocked subprocess launch: {rendered}")
