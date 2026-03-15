#!/usr/bin/env python3
"""Minimal isolated executor runtime for broker-managed provider dispatch."""

from __future__ import annotations

import ctypes
import json
import math
import os
import resource
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

MAX_MSG_SIZE = 16 * 1024 * 1024
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_STRICT = 1


def _error(message: str, *, timings: Mapping[str, Any] | None = None, sandbox: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    return {
        "status": "error",
        "result": {},
        "error": message,
        "t_ms": 0,
        "executor_timing": dict(timings or {}),
        "sandbox": dict(sandbox or {}),
    }


def _read_exact(fd: int, n: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < n:
        chunk = os.read(fd, n - len(chunks))
        if not chunk:
            raise ConnectionError("peer closed")
        chunks.extend(chunk)
    return bytes(chunks)


def _recv_frame_fd(fd: int) -> bytes:
    header = _read_exact(fd, 4)
    (length,) = struct.unpack(">I", header)
    if length <= 0 or length > MAX_MSG_SIZE:
        raise ValueError(f"invalid frame length: {length}")
    return _read_exact(fd, length)


def _write_all(fd: int, payload: bytes) -> None:
    sent = 0
    while sent < len(payload):
        sent += os.write(fd, payload[sent:])


def _send_frame_fd(fd: int, payload: bytes) -> None:
    if len(payload) > MAX_MSG_SIZE:
        raise ValueError("payload too large")
    _write_all(fd, struct.pack(">I", len(payload)))
    _write_all(fd, payload)


def _require_object(name: str, value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be object")
    return dict(value)


def _prctl(option: int, arg2: int, arg3: int = 0, arg4: int = 0, arg5: int = 0) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(
        ctypes.c_int(option),
        ctypes.c_ulong(arg2),
        ctypes.c_ulong(arg3),
        ctypes.c_ulong(arg4),
        ctypes.c_ulong(arg5),
    )
    if result != 0:
        errno_value = ctypes.get_errno()
        raise OSError(errno_value, os.strerror(errno_value))
    return result


def _restrict_environment(allowed_keys: Iterable[str]) -> Dict[str, str]:
    allowed = tuple(key for key in allowed_keys if isinstance(key, str) and key)
    kept = {key: os.environ[key] for key in allowed if key in os.environ}
    kept.setdefault("PATH", os.environ.get("PATH", "/usr/bin:/bin"))
    os.environ.clear()
    os.environ.update(kept)
    return kept


def _enforce_workdir(path: str, allowed_root: str) -> Dict[str, Any]:
    workdir = Path(path).resolve()
    root = Path(allowed_root).resolve()
    try:
        workdir.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"working_directory escapes allowed root: {workdir}") from exc
    workdir.mkdir(parents=True, exist_ok=True)
    os.chdir(workdir)
    return {"working_directory": str(workdir), "allowed_workdir_root": str(root)}


def _apply_resource_limits(resource_limits: Mapping[str, Any]) -> Dict[str, int]:
    applied: Dict[str, int] = {}

    cpu_ms = resource_limits.get("cpu_ms")
    if isinstance(cpu_ms, int) and not isinstance(cpu_ms, bool) and cpu_ms > 0:
        cpu_seconds = max(1, int(math.ceil(cpu_ms / 1000.0)))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        applied["cpu_s"] = cpu_seconds

    memory_kb = resource_limits.get("memory_kb")
    if isinstance(memory_kb, int) and not isinstance(memory_kb, bool) and memory_kb > 0:
        memory_bytes = int(memory_kb) * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        applied["memory_bytes"] = memory_bytes

    nofile = resource_limits.get("nofile")
    if isinstance(nofile, int) and not isinstance(nofile, bool) and nofile > 0:
        resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
        applied["nofile"] = nofile

    return applied


def _apply_no_new_privs(markers: List[str]) -> None:
    try:
        _prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        markers.append("no_new_privs")
    except Exception:
        markers.append("no_new_privs_unavailable")


def _maybe_unshare(sandbox_profile: str, markers: List[str]) -> None:
    if sandbox_profile not in {"sandbox-broker-isolated", "sandbox-high-risk"}:
        return
    if os.getenv("MCPD_EXECUTOR_ENABLE_UNSHARE", "").lower() not in {"1", "true", "yes"}:
        markers.append("namespace_hook_disabled")
        return
    unshare_fn = getattr(os, "unshare", None)
    if unshare_fn is None:
        markers.append("namespace_hook_unavailable")
        return

    flags = 0
    for name in ("CLONE_NEWNS", "CLONE_NEWIPC", "CLONE_NEWUTS"):
        flags |= int(getattr(os, name, 0))
    if flags == 0:
        markers.append("namespace_hook_unavailable")
        return
    try:
        unshare_fn(flags)
        markers.append("namespace_hook_applied")
    except OSError as exc:
        markers.append(f"namespace_hook_failed:{exc.errno}")


def _maybe_join_cgroup(markers: List[str]) -> None:
    path = os.getenv("MCPD_EXECUTOR_CGROUP_PROCS", "").strip()
    if not path:
        return
    try:
        Path(path).write_text(f"{os.getpid()}\n", encoding="utf-8")
        markers.append("cgroup_hook_applied")
    except OSError as exc:
        markers.append(f"cgroup_hook_failed:{exc.errno}")


def _maybe_enable_seccomp_strict(sandbox_profile: str, markers: List[str]) -> None:
    if sandbox_profile != "sandbox-high-risk":
        return
    if os.getenv("MCPD_EXECUTOR_ENABLE_SECCOMP_STRICT", "").lower() not in {"1", "true", "yes"}:
        return
    try:
        _prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0)
        markers.append("seccomp_strict")
    except Exception:
        markers.append("seccomp_strict_failed")


def _connect_provider(endpoint: str, timeout_s: float) -> socket.socket:
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout_s)
    conn.connect(endpoint)
    conn.settimeout(None)
    return conn


def _execute_once(job: Mapping[str, Any]) -> Dict[str, Any]:
    t0 = time.perf_counter()
    request = _require_object("request", job.get("request"))
    executor = _require_object("executor", job.get("executor"))
    provider_endpoint = str(job.get("provider_endpoint", "") or "")
    if not provider_endpoint:
        raise ValueError("provider_endpoint must be non-empty string")

    sandbox_markers: List[str] = []
    sandbox_report: Dict[str, Any] = {
        "sandbox_profile": str(executor.get("sandbox_profile", "")),
        "executor_type": str(executor.get("executor_type", "")),
        "network_policy": str(executor.get("network_policy", "")),
        "structured_payload_only": bool(executor.get("structured_payload_only", False)),
        "sandbox_markers": sandbox_markers,
    }
    timings: Dict[str, int] = {}

    setup_start = time.perf_counter()
    kept_env = _restrict_environment(executor.get("inherited_env_keys", ()))
    sandbox_report["inherited_env_keys"] = sorted(kept_env.keys())
    sandbox_report.update(
        _enforce_workdir(
            str(executor.get("working_directory", "")),
            str(job.get("allowed_workdir_root", "/tmp/linux-mcp-executors")),
        )
    )
    sandbox_report["resource_limits"] = _apply_resource_limits(
        _require_object("resource_limits", executor.get("resource_limits", {}))
    )
    os.umask(0o077)
    _apply_no_new_privs(sandbox_markers)
    _maybe_unshare(sandbox_report["sandbox_profile"], sandbox_markers)
    _maybe_join_cgroup(sandbox_markers)
    timings["sandbox_setup_ms"] = int((time.perf_counter() - setup_start) * 1000)

    connect_start = time.perf_counter()
    conn = _connect_provider(provider_endpoint, float(job.get("provider_timeout_s", 30.0) or 30.0))
    timings["provider_connect_ms"] = int((time.perf_counter() - connect_start) * 1000)

    provider_start = time.perf_counter()
    encoded = json.dumps(request, ensure_ascii=True).encode("utf-8")
    _maybe_enable_seccomp_strict(sandbox_report["sandbox_profile"], sandbox_markers)
    _send_frame_fd(conn.fileno(), encoded)
    raw = _recv_frame_fd(conn.fileno())
    timings["provider_roundtrip_ms"] = int((time.perf_counter() - provider_start) * 1000)

    resp = json.loads(raw.decode("utf-8"))
    if not isinstance(resp, dict):
        raise ValueError("provider returned non-object response")

    timings["executor_total_ms"] = int((time.perf_counter() - t0) * 1000)
    timings["executor_startup_ms"] = timings["sandbox_setup_ms"] + timings["provider_connect_ms"]
    if "t_ms" not in resp or not isinstance(resp.get("t_ms"), int):
        resp["t_ms"] = timings["provider_roundtrip_ms"]
    resp["executor_timing"] = timings
    resp["sandbox"] = sandbox_report
    return resp


def main() -> int:
    try:
        raw = sys.stdin.buffer.read()
        if not raw:
            raise ValueError("missing executor job payload")
        job = json.loads(raw.decode("utf-8"))
        if not isinstance(job, dict):
            raise ValueError("executor job payload must be object")
        result = _execute_once(job)
    except Exception as exc:  # noqa: BLE001
        result = _error(str(exc))

    os.write(1, json.dumps(result, ensure_ascii=True).encode("utf-8"))
    return 0 if result.get("status") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
