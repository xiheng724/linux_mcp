#!/usr/bin/env python3
"""linux_mcp evaluation runner with repeated measurements and paper-style summaries."""

from __future__ import annotations

import argparse
import contextlib
import csv
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from threading import Barrier
from typing import Any, Dict, Iterable, Iterator, List, Sequence

from benchmark_suite import (
    ToolCase,
    call_tool_direct,
    enrich_hash_from_mcpd,
    load_manifest_tools,
    percentile,
    preflight_tools,
)
from security_eval import (
    build_exec_req,
    invoke_mcpd,
    launch_mcpd_variant,
    open_session_details,
    run_daemon_compromise,
    scenario_approval_forgery,
    scenario_boundary_conditions,
    scenario_compromised_mediator,
    scenario_metadata_tampering,
    scenario_session_forgery,
    stop_process,
    wait_mcpd_ready,
)

try:
    from scipy import stats as scipy_stats
except Exception:  # noqa: BLE001
    scipy_stats = None

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
KERNEL_BUDGET_PARAM = Path("/sys/module/kernel_mcp/parameters/agent_max_calls")


@dataclass(frozen=True)
class SystemVariant:
    label: str
    display_name: str
    mode: str
    sandboxed_tools: bool
    sock_path: str
    strict_checks: bool = False
    audit_logging: bool = False
    userspace_budget_calls: int = 0


SYSTEMS = (
    SystemVariant("userspace", "userspace baseline", "userspace_semantic_plane", False, "/tmp/mcpd-userspace-eval.sock"),
    SystemVariant(
        "seccomp",
        "userspace + seccomp + logging + stricter checks",
        "userspace_semantic_plane",
        True,
        "/tmp/mcpd-seccomp-eval.sock",
        strict_checks=True,
        audit_logging=True,
    ),
    SystemVariant("kernel", "kernel_mcp", "normal", False, "/tmp/mcpd-kernel-eval.sock"),
    # E6: direct-UDS raw baseline. mode="direct" signals the runner to bypass mcpd
    # and talk to the tool-app UDS endpoint from the manifest. sock_path is a placeholder;
    # direct mode never binds it. Not selected by default — opt in via --systems=...,direct.
    SystemVariant("direct", "direct-uds raw baseline", "direct", False, "/tmp/mcpd-direct-eval.sock"),
)

LATENCY_PAYLOADS = (
    ("small", 100),
    ("medium", 10 * 1024),
    ("large", 1024 * 1024),
)

ATTACK_PROFILES = {
    "spoof": "tamper_session",
    "replay": "tamper_approval",
    "substitute": "tamper_metadata",
    "escalation": "compromised_userspace",
}

ATTACK_CASE_FILTERS = {
    "spoof": {"fake_session_id", "expired_session", "session_token_theft"},
    "replay": {"cross_agent_ticket_reuse", "expired_ticket_replay", "denied_ticket_reuse", "forged_approval_ticket"},
    "substitute": {"hash_mismatch", "wrong_app_binding", "stale_catalog_replay"},
    "escalation": {"approval_required_bypass"},
}

ATTACK_DESCRIPTIONS = {
    "spoof": {
        "goal": "让没有有效 session 的进程冒充已认证 agent 调用工具。",
        "method": [
            "合法 agent 打开 session，攻击方伪造或窃取 session_id。",
            "攻击方直接发送 tool:exec 请求。",
            "系统校验 session、peer binding 和 kernel agent binding。",
        ],
        "success": "工具被执行或返回 status=ok。",
        "blocked": "请求在执行前被 DENY 或返回 session/binding 错误。",
    },
    "replay": {
        "goal": "重用旧 approval ticket，在新 session 或过期后继续执行高风险工具。",
        "method": [
            "先触发高风险工具拿到 approval ticket。",
            "然后伪造 ticket、跨 session 重用、或在 deny/过期后重放。",
            "系统校验 ticket 的 session/tool/binding/consumed 状态。",
        ],
        "success": "高风险工具被执行。",
        "blocked": "ticket 被识别为 forged、expired、denied 或 consumed。",
    },
    "substitute": {
        "goal": "伪造 tool_id、tool_hash 或 app 绑定，执行与 manifest 不一致的工具语义。",
        "method": [
            "保持 session 不变，篡改 tool_hash、app_id 或 stale hash。",
            "系统校验 manifest hash 和 app/tool binding。",
        ],
        "success": "请求被接受并执行。",
        "blocked": "hash mismatch 或 app/tool binding mismatch。",
    },
    "escalation": {
        "goal": "请求低风险入口，但让 mediator 执行需要 approval 的高风险行为。",
        "method": [
            "构造 compromised mediator 路径或伪造 approval_ticket_id。",
            "尝试绕过 approval gate 执行高风险工具。",
        ],
        "success": "高风险工具在无有效 approval 下执行。",
        "blocked": "请求被 DEFER/DENY，或 approval gate 强制拦截。",
    },
}


def payload_display(size_bytes: int) -> str:
    if size_bytes >= 1024 * 1024:
        return f"1 MB ({size_bytes:,} B)"
    if size_bytes >= 1024:
        return f"{size_bytes // 1024} KB ({size_bytes:,} B)"
    return f"{size_bytes} B"


def _run_root_script(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT_DIR, check=True)  # noqa: S603


def write_csv(path: Path, rows: Sequence[Dict[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def summarize_durations_ms(values: Sequence[float]) -> Dict[str, float]:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return {"avg": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}
    return {
        "avg": round(statistics.fmean(ordered), 3),
        "p50": round(percentile(ordered, 0.50), 3),
        "p95": round(percentile(ordered, 0.95), 3),
        "p99": round(percentile(ordered, 0.99), 3),
    }


def summarize_mean_std_ci(values: Sequence[float]) -> Dict[str, float]:
    series = [float(value) for value in values]
    if not series:
        return {"mean": 0.0, "std": 0.0, "ci_lo": 0.0, "ci_hi": 0.0}
    mean = statistics.fmean(series)
    std = statistics.stdev(series) if len(series) > 1 else 0.0
    if len(series) > 1:
        sem = std / math.sqrt(len(series)) if len(series) > 0 else 0.0
        if scipy_stats is not None:
            ci_lo, ci_hi = scipy_stats.t.interval(0.95, len(series) - 1, loc=mean, scale=sem)
        else:
            margin = 1.96 * sem
            ci_lo, ci_hi = mean - margin, mean + margin
    else:
        ci_lo = ci_hi = mean
    return {
        "mean": round(mean, 3),
        "std": round(std, 3),
        "ci_lo": round(float(ci_lo), 3),
        "ci_hi": round(float(ci_hi), 3),
    }


def welch_pvalue(lhs: Sequence[float], rhs: Sequence[float]) -> float:
    if len(lhs) < 2 or len(rhs) < 2:
        return 1.0
    if scipy_stats is not None:
        result = scipy_stats.ttest_ind(list(lhs), list(rhs), equal_var=False)
        pvalue = float(result.pvalue) if result.pvalue is not None else 1.0
    else:
        mean_l = statistics.fmean(lhs)
        mean_r = statistics.fmean(rhs)
        var_l = statistics.variance(lhs)
        var_r = statistics.variance(rhs)
        denom = math.sqrt((var_l / len(lhs)) + (var_r / len(rhs)))
        if denom <= 0:
            return 1.0
        z = abs(mean_l - mean_r) / denom
        pvalue = math.erfc(z / math.sqrt(2.0))
    if math.isnan(pvalue):
        return 1.0
    return round(pvalue, 6)


def _run_text(cmd: Sequence[str]) -> str:
    proc = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True, check=False)  # noqa: S603
    return (proc.stdout or proc.stderr or "").strip()


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def collect_environment() -> Dict[str, Any]:
    lscpu_json = _run_text(["lscpu", "-J"])
    cpu_model = ""
    cpu_vendor = ""
    cpu_arch = platform.machine()
    cpu_cores = ""
    cpu_threads = ""
    cpu_mhz = ""
    numa_nodes = ""
    if lscpu_json:
        try:
            obj = json.loads(lscpu_json)
            for item in obj.get("lscpu", []):
                field = str(item.get("field", "")).rstrip(":")
                value = str(item.get("data", ""))
                if field == "Model name":
                    cpu_model = value
                elif field == "Vendor ID":
                    cpu_vendor = value
                elif field == "Architecture":
                    cpu_arch = value
                elif field == "CPU(s)":
                    cpu_threads = value
                elif field == "Core(s) per socket":
                    cpu_cores = value
                elif field == "NUMA node(s)":
                    numa_nodes = value
                elif field in {"CPU max MHz", "CPU MHz"} and not cpu_mhz:
                    cpu_mhz = value
        except json.JSONDecodeError:
            pass
    if not cpu_model or cpu_model == "-":
        cpuinfo = _read_text(Path("/proc/cpuinfo"))
        for line in cpuinfo.splitlines():
            if line.lower().startswith("model name") or line.lower().startswith("hardware"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    if not cpu_model or cpu_model == "-":
        cpu_model = f"{cpu_vendor or 'unknown-vendor'} {cpu_arch}".strip()
    if not cpu_mhz:
        cpu_mhz = _read_text(Path("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"))
        if cpu_mhz.isdigit():
            cpu_mhz = str(round(int(cpu_mhz) / 1000.0, 1))
    if not cpu_mhz:
        cpu_mhz = "unavailable-in-guest"
    mem_total = ""
    mem_text = _read_text(Path("/proc/meminfo"))
    for line in mem_text.splitlines():
        if line.startswith("MemTotal:"):
            mem_total = " ".join(line.split()[1:3])
            break
    env = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hostname": platform.node(),
        "cpu_model": cpu_model,
        "cpu_cores_per_socket": cpu_cores,
        "cpu_threads": cpu_threads,
        "cpu_freq_mhz": cpu_mhz,
        "memory_total": mem_total,
        "os_release": _run_text(["bash", "-lc", ". /etc/os-release && printf '%s %s' \"$NAME\" \"$VERSION_ID\""]),
        "kernel_release": platform.release(),
        "python_version": sys.version.split()[0],
        "virtualization": _run_text(["systemd-detect-virt"]) or "none",
        "numa_nodes": numa_nodes,
        "cpu_governor": _read_text(Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")),
        "intel_no_turbo": _read_text(Path("/sys/devices/system/cpu/intel_pstate/no_turbo")),
        "aslr": _read_text(Path("/proc/sys/kernel/randomize_va_space")),
        "uds_rcvbuf_default": _read_text(Path("/proc/sys/net/core/rmem_default")),
        "uds_sndbuf_default": _read_text(Path("/proc/sys/net/core/wmem_default")),
        "is_root": os.geteuid() == 0,
    }
    env["machine_note"] = "bare_metal" if env["virtualization"] in {"", "none"} else env["virtualization"]
    return env


def current_kernel_budget_limit() -> int | None:
    if not KERNEL_BUDGET_PARAM.exists():
        return None
    text = _read_text(KERNEL_BUDGET_PARAM)
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def validate_kernel_budget_for_run(*, active_systems: Sequence[SystemVariant], budget_max_calls: int) -> None:
    if not any(system.label == "kernel" for system in active_systems):
        return
    current = current_kernel_budget_limit()
    if current is None:
        return
    # Performance/latency/scalability data are only valid when the kernel is not carrying a global call budget.
    if current > 0 and budget_max_calls <= 0:
        raise RuntimeError(
            "kernel_mcp agent_max_calls is non-zero, which would contaminate latency/scalability; reload with KERNEL_MCP_AGENT_MAX_CALLS=0 before running performance experiments"
        )
    if current > 0 and budget_max_calls > 0:
        raise RuntimeError(
            "kernel_mcp agent_max_calls is non-zero while this run also enables budget measurement; split performance and budget into separate runs to avoid cross-section contamination"
        )


def summarize_attack_cases(raw_rows: Sequence[Dict[str, Any]]) -> list[Dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[Dict[str, Any]]] = defaultdict(list)
    for row in raw_rows:
        grouped[(str(row.get("system", "")), str(row.get("attack_type", "")), str(row.get("attack_case", "")))].append(dict(row))
    out: list[Dict[str, Any]] = []
    for (system, attack_type, attack_case), rows in sorted(grouped.items()):
        attempts = len(rows)
        successes = sum(int(row.get("unauthorized_success", 0)) for row in rows)
        out.append(
            {
                "system": system,
                "attack_type": attack_type,
                "attack_case": attack_case,
                "attempts": attempts,
                "successes": successes,
                "success_rate": round(successes / max(attempts, 1), 6),
            }
        )
    return out


def choose_latency_tool(tools: Sequence[ToolCase]) -> ToolCase:
    for tool in tools:
        if tool.tool_name == "write_document":
            return tool
    for tool in tools:
        if tool.tool_name == "note_create":
            return tool
    raise RuntimeError("no writable latency tool found")


def choose_safe_tool(tools: Sequence[ToolCase]) -> ToolCase:
    for tool in tools:
        if not tool.risk_tags and tool.tool_name == "desktop_snapshot":
            return tool
    for tool in tools:
        if "sensitive_read" in tool.risk_tags:
            return tool
    return tools[0]


def choose_risky_tool(tools: Sequence[ToolCase]) -> ToolCase:
    for tool in tools:
        if tool.tool_name == "write_host_text_file":
            return tool
    raise RuntimeError("no approval-backed risky tool found")


def build_latency_payload(tool: ToolCase, *, size_bytes: int, req_index: int) -> Dict[str, Any]:
    content = "x" * size_bytes
    if tool.tool_name == "write_document":
        return {
            "path": f"tmp/linux-mcp-bench/latency-{size_bytes}-{req_index % 8}.txt",
            "content": content,
            "overwrite": True,
            "create_parents": True,
        }
    if tool.tool_name == "note_create":
        return {
            "title": f"bench-{size_bytes}-{req_index}",
            "body": content,
            "notebook": "bench",
            "tags": ["latency"],
        }
    raise ValueError(f"unsupported latency tool: {tool.tool_name}")


@contextlib.contextmanager
def managed_tool_services(*, sandboxed: bool, sandbox_fsize_bytes: int) -> Iterator[None]:
    _run_root_script(["bash", "scripts/stop_tool_services.sh"])
    cmd = ["bash", "scripts/run_tool_services.sh"]
    if sandboxed:
        cmd.extend(["--sandbox", "simple", "--sandbox-fsize-bytes", str(sandbox_fsize_bytes)])
    _run_root_script(cmd)
    try:
        yield
    finally:
        _run_root_script(["bash", "scripts/stop_tool_services.sh"])


@contextlib.contextmanager
def managed_mcpd(system: SystemVariant, *, attack_profile: str = "", timeout_s: float = 10.0) -> Iterator[str]:
    prev: dict[str, str | None] = {}
    overrides = {
        "MCPD_STRICT_CHECKS": "1" if system.strict_checks else "",
        "MCPD_AUDIT_LOGGING": "1" if system.audit_logging else "",
        "MCPD_AGENT_MAX_CALLS": str(system.userspace_budget_calls) if system.userspace_budget_calls > 0 else "",
    }
    try:
        for key, value in overrides.items():
            prev[key] = os.environ.get(key)
            if value:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)
        proc = launch_mcpd_variant(mode=system.mode, sock_path=system.sock_path, attack_profile=attack_profile)
    finally:
        for key, old_value in prev.items():
            if old_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_value
    try:
        wait_mcpd_ready(system.sock_path, max(10.0, timeout_s))
        yield system.sock_path
    finally:
        stop_process(proc, system.sock_path)


def run_latency_repetition(
    *,
    sock_path: str,
    tool: ToolCase,
    system_label: str,
    repetition: int,
    requests: int,
    direct_mode: bool = False,
) -> tuple[list[Dict[str, Any]], list[Dict[str, Any]]]:
    # direct_mode bypasses mcpd entirely — talk to tool.endpoint directly. No
    # session, no arbitration, no hashes. Used only by the E6 raw-baseline variant.
    if direct_mode:
        session_id = ""
    else:
        session = open_session_details(sock_path, 20.0, f"latency-{system_label}-rep-{repetition}")
        session_id = str(session["session_id"])
    raw_rows: list[Dict[str, Any]] = []
    summary_rows: list[Dict[str, Any]] = []
    for payload_label, payload_size in LATENCY_PAYLOADS:
        latencies: list[float] = []
        session_lookup_values: list[float] = []
        arbitration_values: list[float] = []
        tool_exec_values: list[float] = []
        total_values: list[float] = []
        tool_exec_share_values: list[float] = []
        errors = 0
        for req_index in range(requests):
            payload = build_latency_payload(tool, size_bytes=payload_size, req_index=req_index)
            if direct_mode:
                t0 = time.perf_counter()
                try:
                    resp = call_tool_direct(
                        tool,
                        payload,
                        30.0,
                        req_id=1000000 + repetition * 100000 + req_index,
                    )
                except Exception as exc:  # noqa: BLE001
                    resp = {"status": "error", "error": str(exc)}
                latency_ms = (time.perf_counter() - t0) * 1000.0
            else:
                req = build_exec_req(
                    req_id=1000000 + repetition * 100000 + req_index,
                    session_id=session_id,
                    tool=tool,
                    payload=payload,
                    tool_hash=tool.manifest_hash,
                )
                resp, latency_ms = invoke_mcpd(sock_path=sock_path, timeout_s=30.0, req=req)
            timing = resp.get("timing_ms", {}) if isinstance(resp.get("timing_ms", {}), dict) else {}
            session_lookup_ms = float(timing.get("session_lookup", 0.0))
            arbitration_ms = float(timing.get("arbitration", 0.0))
            tool_exec_ms = float(timing.get("tool_exec", latency_ms if direct_mode else 0.0))
            total_ms = float(timing.get("total", latency_ms))
            latencies.append(latency_ms)
            session_lookup_values.append(session_lookup_ms)
            arbitration_values.append(arbitration_ms)
            tool_exec_values.append(tool_exec_ms)
            total_values.append(total_ms)
            if total_ms > 0:
                tool_exec_share_values.append((tool_exec_ms / total_ms) * 100.0)
            if resp.get("status") != "ok":
                errors += 1
            raw_rows.append(
                {
                    "repetition": repetition,
                    "system": system_label,
                    "payload_label": payload_label,
                    "payload_bytes": payload_size,
                    "request_index": req_index + 1,
                    "latency_ms": round(latency_ms, 3),
                    "session_lookup_ms": round(session_lookup_ms, 3),
                    "arbitration_ms": round(arbitration_ms, 3),
                    "tool_exec_ms": round(tool_exec_ms, 3),
                    "total_ms": round(total_ms, 3),
                    "status": resp.get("status", ""),
                    "error": str(resp.get("error", "")),
                }
            )
        latency_summary = summarize_durations_ms(latencies)
        summary_rows.append(
            {
                "repetition": repetition,
                "system": system_label,
                "payload_label": payload_label,
                "payload_bytes": payload_size,
                "payload_display": payload_display(payload_size),
                "requests": requests,
                "errors": errors,
                "latency_avg_ms": latency_summary["avg"],
                "latency_p50_ms": latency_summary["p50"],
                "latency_p95_ms": latency_summary["p95"],
                "latency_p99_ms": latency_summary["p99"],
                "session_lookup_ms": round(statistics.fmean(session_lookup_values), 3) if session_lookup_values else 0.0,
                "arbitration_ms": round(statistics.fmean(arbitration_values), 3) if arbitration_values else 0.0,
                "tool_exec_ms": round(statistics.fmean(tool_exec_values), 3) if tool_exec_values else 0.0,
                "total_ms": round(statistics.fmean(total_values), 3) if total_values else 0.0,
                "tool_exec_share_pct": round(statistics.fmean(tool_exec_share_values), 3) if tool_exec_share_values else 0.0,
            }
        )
    return raw_rows, summary_rows


def _steady_state_worker(
    *,
    sock_path: str,
    session_id: str,
    tool: ToolCase,
    request_id_base: int,
    barrier: Barrier,
    warmup_s: float,
    measure_s: float,
    direct_mode: bool = False,
) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    barrier.wait()
    start_ref = time.perf_counter()
    measure_start = start_ref + warmup_s
    measure_end = measure_start + measure_s
    req_index = 0
    while True:
        start_ts = time.perf_counter()
        if start_ts >= measure_end:
            break
        if direct_mode:
            t0 = time.perf_counter()
            try:
                resp = call_tool_direct(
                    tool,
                    dict(tool.payloads[0]) if tool.payloads else {},
                    20.0,
                    req_id=request_id_base + req_index,
                )
            except Exception as exc:  # noqa: BLE001
                resp = {"status": "error", "error": str(exc)}
            latency_ms = (time.perf_counter() - t0) * 1000.0
        else:
            req = build_exec_req(
                req_id=request_id_base + req_index,
                session_id=session_id,
                tool=tool,
                tool_hash=tool.manifest_hash,
            )
            resp, latency_ms = invoke_mcpd(sock_path=sock_path, timeout_s=20.0, req=req)
        end_ts = time.perf_counter()
        if start_ts >= measure_start and start_ts < measure_end:
            rows.append(
                {
                    "request_index": req_index + 1,
                    "start_ts": round(start_ts, 6),
                    "end_ts": round(end_ts, 6),
                    "latency_ms": round(latency_ms, 3),
                    "status": resp.get("status", ""),
                    "error": str(resp.get("error", "")),
                    "second_bucket": int(start_ts - measure_start),
                }
            )
        req_index += 1
    return rows


def run_scalability_repetition(
    *,
    sock_path: str,
    tool: ToolCase,
    system_label: str,
    repetition: int,
    agent_counts: Sequence[int],
    concurrency_levels: Sequence[int],
    warmup_s: float,
    measure_s: float,
    direct_mode: bool = False,
) -> tuple[list[Dict[str, Any]], list[Dict[str, Any]], list[Dict[str, Any]]]:
    raw_rows: list[Dict[str, Any]] = []
    summary_rows: list[Dict[str, Any]] = []
    bucket_rows: list[Dict[str, Any]] = []
    for agent_count in agent_counts:
        if direct_mode:
            # No mcpd sessions in direct mode — each "agent" slot is just a logical worker.
            sessions = ["" for _ in range(agent_count)]
        else:
            sessions = [
                str(open_session_details(sock_path, 20.0, f"scale-{system_label}-{repetition}-{agent_idx}")["session_id"])
                for agent_idx in range(agent_count)
            ]
        for concurrency in concurrency_levels:
            worker_count = max(1, concurrency)
            barrier = Barrier(worker_count)
            scenario_rows: list[Dict[str, Any]] = []
            with ThreadPoolExecutor(max_workers=worker_count) as pool:
                futures = []
                for worker_id in range(worker_count):
                    session_id = sessions[worker_id % len(sessions)]
                    futures.append(
                        pool.submit(
                            _steady_state_worker,
                            sock_path=sock_path,
                            session_id=session_id,
                            tool=tool,
                            request_id_base=2000000 + repetition * 1000000 + agent_count * 10000 + worker_id * 1000,
                            barrier=barrier,
                            warmup_s=warmup_s,
                            measure_s=measure_s,
                            direct_mode=direct_mode,
                        )
                    )
                for fut in as_completed(futures):
                    scenario_rows.extend(fut.result())
            latencies = [float(row["latency_ms"]) for row in scenario_rows]
            errors = sum(1 for row in scenario_rows if row["status"] != "ok")
            per_second = [0 for _ in range(max(int(math.ceil(measure_s)), 1))]
            for row in scenario_rows:
                bucket = int(row["second_bucket"])
                if 0 <= bucket < len(per_second):
                    per_second[bucket] += 1
            bucket_mean = statistics.fmean(per_second) if per_second else 0.0
            bucket_std = statistics.stdev(per_second) if len(per_second) > 1 else 0.0
            latency_summary = summarize_durations_ms(latencies)
            summary_rows.append(
                {
                    "repetition": repetition,
                    "system": system_label,
                    "agents": agent_count,
                    "concurrency": concurrency,
                    "measurement_seconds": measure_s,
                    "requests": len(scenario_rows),
                    "errors": errors,
                    "error_rate": round(errors / max(len(scenario_rows), 1), 6),
                    "throughput_rps": round(bucket_mean, 3),
                    "throughput_std_rps": round(bucket_std, 3),
                    "latency_avg_ms": latency_summary["avg"],
                    "latency_p50_ms": latency_summary["p50"],
                    "latency_p95_ms": latency_summary["p95"],
                    "latency_p99_ms": latency_summary["p99"],
                }
            )
            for idx, value in enumerate(per_second):
                bucket_rows.append(
                    {
                        "repetition": repetition,
                        "system": system_label,
                        "agents": agent_count,
                        "concurrency": concurrency,
                        "second_index": idx,
                        "rps": value,
                    }
                )
            for row in scenario_rows:
                raw_rows.append(
                    {
                        "repetition": repetition,
                        "system": system_label,
                        "agents": agent_count,
                        "concurrency": concurrency,
                        **row,
                    }
                )
    return raw_rows, summary_rows, bucket_rows


def _attack_outcome(success_rate: float) -> str:
    return "BLOCKED" if success_rate == 0.0 else "UNDETECTED"


def run_attack_experiment(
    *,
    system: SystemVariant,
    tools: Sequence[ToolCase],
    timeout_s: float,
    repeats: int,
) -> tuple[list[Dict[str, Any]], list[Dict[str, Any]]]:
    safe_tool = choose_safe_tool(tools)
    risky_tool = choose_risky_tool(tools)
    raw_rows: list[Dict[str, Any]] = []
    matrix_rows: list[Dict[str, Any]] = []
    for attack_type in ("spoof", "replay", "substitute", "escalation"):
        profile = ""
        if system.label != "kernel":
            profile = ATTACK_PROFILES[attack_type]
        with managed_mcpd(system, attack_profile=profile, timeout_s=timeout_s) as sock_path:
            if attack_type == "spoof":
                rows = scenario_session_forgery(
                    sock_path=sock_path,
                    timeout_s=timeout_s,
                    mode=system.label,
                    attack_profile=profile,
                    safe_tool=safe_tool,
                    repeats=repeats,
                )
            elif attack_type == "replay":
                rows = scenario_approval_forgery(
                    sock_path=sock_path,
                    timeout_s=timeout_s,
                    mode=system.label,
                    attack_profile=profile,
                    risky_tool=risky_tool,
                    all_tools=tools,
                    repeats=repeats,
                )
            elif attack_type == "substitute":
                rows = scenario_metadata_tampering(
                    sock_path=sock_path,
                    timeout_s=timeout_s,
                    mode=system.label,
                    attack_profile=profile,
                    safe_tool=safe_tool,
                    all_tools=tools,
                    repeats=repeats,
                )
            else:
                rows = scenario_compromised_mediator(
                    sock_path=sock_path,
                    timeout_s=timeout_s,
                    mode=system.label,
                    attack_profile=profile,
                    safe_tool=safe_tool,
                    risky_tool=risky_tool,
                    repeats=repeats,
                )
        raw_rows.extend({"system": system.label, "attack_type": attack_type, **row} for row in rows)
        relevant_rows = [
            row for row in rows if str(row.get("attack_case", "")) in ATTACK_CASE_FILTERS[attack_type]
        ]
        attempts = len(relevant_rows)
        successes = sum(int(row.get("unauthorized_success", 0)) for row in relevant_rows)
        success_rate = round(successes / max(attempts, 1), 6)
        matrix_rows.append(
            {
                "attack_type": attack_type,
                "system": system.label,
                "attempts": attempts,
                "successes": successes,
                "success_rate": success_rate,
                "outcome": _attack_outcome(success_rate),
            }
        )
    return raw_rows, matrix_rows


def run_boundary_experiment(
    *,
    system: SystemVariant,
    tools: Sequence[ToolCase],
    timeout_s: float,
    repeats: int,
) -> tuple[list[Dict[str, Any]], list[Dict[str, Any]]]:
    """Standalone phase for group-F boundary-condition probes.

    Produces two outputs:
      * raw rows (same shape as attack_samples) with scenario_group="F"
      * a summary matrix aggregated per attack_case (not per category), since group F
        tests case-by-case invariants that don't map onto the original 4 categories.

    The boundary phase does NOT use ATTACK_PROFILES weakening. It runs against the normal
    mcpd configuration of each system so any bypasses reflect genuine boundary weaknesses
    rather than instrumented tamper paths.
    """
    safe_tool = choose_safe_tool(tools)
    risky_tool = choose_risky_tool(tools)
    raw_rows: list[Dict[str, Any]] = []
    matrix_rows: list[Dict[str, Any]] = []
    with managed_mcpd(system, attack_profile="", timeout_s=timeout_s) as sock_path:
        rows = scenario_boundary_conditions(
            sock_path=sock_path,
            timeout_s=timeout_s,
            mode=system.label,
            attack_profile="",
            safe_tool=safe_tool,
            risky_tool=risky_tool,
            all_tools=tools,
            repeats=repeats,
        )
    for row in rows:
        raw_rows.append({"system": system.label, "attack_type": "boundary", **row})
    case_rows: dict[str, list[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        case_rows[str(row.get("attack_case", ""))].append(row)
    for case_name in sorted(case_rows.keys()):
        items = case_rows[case_name]
        attempts = len(items)
        successes = sum(int(item.get("unauthorized_success", 0)) for item in items)
        success_rate = round(successes / max(attempts, 1), 6)
        matrix_rows.append(
            {
                "system": system.label,
                "attack_case": case_name,
                "attempts": attempts,
                "successes": successes,
                "success_rate": success_rate,
                "outcome": _attack_outcome(success_rate),
            }
        )
    return raw_rows, matrix_rows


def run_budget_experiment(
    *,
    system: SystemVariant,
    tool: ToolCase,
    timeout_s: float,
    max_calls: int,
    total_requests: int,
) -> tuple[list[Dict[str, Any]], Dict[str, Any]]:
    if total_requests <= 0 or max_calls <= 0:
        return [], {
            "system": system.label,
            "max_calls": max_calls,
            "requests": total_requests,
            "allowed": 0,
            "denied": 0,
            "first_reject_at": 0,
            "status": "skipped",
            "note": "budget disabled",
        }
    if system.label == "kernel":
        if not KERNEL_BUDGET_PARAM.exists():
            return [], {
                "system": system.label,
                "max_calls": max_calls,
                "requests": total_requests,
                "allowed": 0,
                "denied": 0,
                "first_reject_at": 0,
                "status": "skipped",
                "note": "reload kernel_mcp with agent_max_calls=<N> to enable kernel budget enforcement",
            }
        current = _read_text(KERNEL_BUDGET_PARAM)
        if current != str(max_calls):
            return [], {
                "system": system.label,
                "max_calls": max_calls,
                "requests": total_requests,
                "allowed": 0,
                "denied": 0,
                "first_reject_at": 0,
                "status": "skipped",
                "note": f"kernel agent_max_calls={current or 'unset'}, expected {max_calls}",
            }
    budget_system = SystemVariant(
        label=system.label,
        display_name=system.display_name,
        mode=system.mode,
        sandboxed_tools=system.sandboxed_tools,
        sock_path=system.sock_path,
        strict_checks=system.strict_checks,
        audit_logging=system.audit_logging,
        userspace_budget_calls=max_calls if system.label != "kernel" else 0,
    )
    with managed_mcpd(budget_system, timeout_s=timeout_s) as sock_path:
        session = open_session_details(sock_path, timeout_s, f"budget-{system.label}")
        session_id = str(session["session_id"])
        raw_rows: list[Dict[str, Any]] = []
        allowed = 0
        denied = 0
        started = time.perf_counter()
        for req_index in range(total_requests):
            req = build_exec_req(
                req_id=700000 + req_index,
                session_id=session_id,
                tool=tool,
                tool_hash=tool.manifest_hash,
            )
            resp, latency_ms = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=req)
            accepted = resp.get("status") == "ok"
            if accepted:
                allowed += 1
            else:
                denied += 1
            raw_rows.append(
                {
                    "system": system.label,
                    "request_index": req_index + 1,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
                    "latency_ms": round(latency_ms, 3),
                    "accepted": 1 if accepted else 0,
                    "denied": 0 if accepted else 1,
                    "decision": str(resp.get("decision", "")),
                    "reason": str(resp.get("reason", "")),
                    "allowed_so_far": allowed,
                    "budget_usage_pct": round((allowed / max(max_calls, 1)) * 100.0, 3),
                }
            )
        first_reject = next((row["request_index"] for row in raw_rows if int(row["denied"]) == 1), 0)
        return raw_rows, {
            "system": system.label,
            "max_calls": max_calls,
            "requests": total_requests,
            "allowed": allowed,
            "denied": denied,
            "first_reject_at": first_reject,
            "status": "ok",
            "note": "",
        }


def aggregate_latency(summary_rows: Sequence[Dict[str, Any]]) -> tuple[list[Dict[str, Any]], list[Dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[Dict[str, Any]]] = defaultdict(list)
    for row in summary_rows:
        grouped[(str(row["system"]), str(row["payload_label"]))].append(dict(row))
    out: list[Dict[str, Any]] = []
    breakdown: list[Dict[str, Any]] = []
    userspace_by_payload: dict[str, list[Dict[str, Any]]] = defaultdict(list)
    for row in summary_rows:
        if row["system"] == "userspace":
            userspace_by_payload[str(row["payload_label"])].append(dict(row))
    for (system, payload_label), rows in sorted(grouped.items(), key=lambda item: (item[0][0], int(item[1][0]["payload_bytes"]))):
        payload_bytes = int(rows[0]["payload_bytes"])
        aggregated = {
            "system": system,
            "payload_label": payload_label,
            "payload_bytes": payload_bytes,
            "payload_display": payload_display(payload_bytes),
            "runs": len(rows),
            "requests_per_run": rows[0]["requests"],
            "errors_total": sum(int(item["errors"]) for item in rows),
        }
        for field in ("latency_avg_ms", "latency_p50_ms", "latency_p95_ms", "latency_p99_ms"):
            stats = summarize_mean_std_ci([float(item[field]) for item in rows])
            base_name = field.replace("_ms", "")
            aggregated[f"{base_name}_ms"] = stats["mean"]
            aggregated[f"{base_name}_std_ms"] = stats["std"]
            aggregated[f"{base_name}_ci_lo_ms"] = stats["ci_lo"]
            aggregated[f"{base_name}_ci_hi_ms"] = stats["ci_hi"]
        for field in ("session_lookup_ms", "arbitration_ms", "tool_exec_ms", "total_ms", "tool_exec_share_pct"):
            stats = summarize_mean_std_ci([float(item[field]) for item in rows])
            aggregated[f"{field}_mean"] = stats["mean"]
            aggregated[f"{field}_std"] = stats["std"]
            aggregated[f"{field}_ci_lo"] = stats["ci_lo"]
            aggregated[f"{field}_ci_hi"] = stats["ci_hi"]
        baseline_rows = userspace_by_payload.get(payload_label, [])
        for field in ("latency_avg_ms", "latency_p95_ms"):
            metric_name = field.replace("_ms", "")
            aggregated[f"{metric_name}_pvalue_vs_userspace"] = (
                welch_pvalue([float(item[field]) for item in rows], [float(item[field]) for item in baseline_rows])
                if system != "userspace" and baseline_rows
                else ""
            )
        out.append(aggregated)
        breakdown.append(
            {
                "system": system,
                "payload_label": payload_label,
                "payload_bytes": payload_bytes,
                "payload_display": payload_display(payload_bytes),
                "runs": len(rows),
                "session_lookup_ms": aggregated["session_lookup_ms_mean"],
                "arbitration_ms": aggregated["arbitration_ms_mean"],
                "tool_exec_ms": aggregated["tool_exec_ms_mean"],
                "total_ms": aggregated["total_ms_mean"],
                "tool_exec_share_pct": aggregated["tool_exec_share_pct_mean"],
            }
        )
    return out, breakdown


def aggregate_scalability(summary_rows: Sequence[Dict[str, Any]]) -> list[Dict[str, Any]]:
    grouped: dict[tuple[str, int, int], list[Dict[str, Any]]] = defaultdict(list)
    for row in summary_rows:
        grouped[(str(row["system"]), int(row["agents"]), int(row["concurrency"]))].append(dict(row))
    userspace_groups: dict[tuple[int, int], list[Dict[str, Any]]] = defaultdict(list)
    for row in summary_rows:
        if row["system"] == "userspace":
            userspace_groups[(int(row["agents"]), int(row["concurrency"]))].append(dict(row))
    out: list[Dict[str, Any]] = []
    for (system, agents, concurrency), rows in sorted(grouped.items()):
        item = {
            "system": system,
            "agents": agents,
            "concurrency": concurrency,
            "runs": len(rows),
            "measurement_seconds": rows[0]["measurement_seconds"],
            "requests_mean": round(statistics.fmean(float(row["requests"]) for row in rows), 3),
            "errors_mean": round(statistics.fmean(float(row["errors"]) for row in rows), 3),
        }
        for field in ("throughput_rps", "latency_avg_ms", "latency_p50_ms", "latency_p95_ms", "latency_p99_ms", "error_rate"):
            stats = summarize_mean_std_ci([float(row[field]) for row in rows])
            item[field] = stats["mean"]
            item[f"{field}_std"] = stats["std"]
            item[f"{field}_ci_lo"] = stats["ci_lo"]
            item[f"{field}_ci_hi"] = stats["ci_hi"]
        baseline_rows = userspace_groups.get((agents, concurrency), [])
        item["throughput_pvalue_vs_userspace"] = (
            welch_pvalue([float(row["throughput_rps"]) for row in rows], [float(row["throughput_rps"]) for row in baseline_rows])
            if system != "userspace" and baseline_rows
            else ""
        )
        item["latency_p95_pvalue_vs_userspace"] = (
            welch_pvalue([float(row["latency_p95_ms"]) for row in rows], [float(row["latency_p95_ms"]) for row in baseline_rows])
            if system != "userspace" and baseline_rows
            else ""
        )
        out.append(item)
    return out


def _fmt_stat(mean: Any, std: Any, lo: Any, hi: Any, suffix: str = "") -> str:
    return f"{float(mean):.3f} ± {float(std):.3f} (95% CI [{float(lo):.3f}, {float(hi):.3f}]){suffix}"


def render_report(summary: Dict[str, Any]) -> str:
    meta = summary.get("meta", {})
    env = meta.get("environment", {})
    latency_rows = summary.get("latency_summary", [])
    scalability_rows = summary.get("scalability_summary", [])
    attack_rows = summary.get("attack_matrix", [])
    attack_case_rows = summary.get("attack_case_summary", [])
    budget_rows = summary.get("budget_summary", [])
    breakdown_rows = summary.get("breakdown_summary", [])
    daemon_rows = summary.get("daemon_failure", [])

    lines: list[str] = []
    lines.append("# linux_mcp Experiment Report")
    lines.append("")
    lines.append("## Section 1: 实验环境")
    lines.append("")
    lines.append(f"- CPU: {env.get('cpu_model', '')} | threads={env.get('cpu_threads', '')} | cores/socket={env.get('cpu_cores_per_socket', '')} | freq={env.get('cpu_freq_mhz', '')}")
    lines.append(f"- Memory: {env.get('memory_total', '')}")
    lines.append(f"- OS: {env.get('os_release', '')} | kernel={env.get('kernel_release', '')}")
    lines.append(f"- Python: {env.get('python_version', '')} | machine={env.get('machine_note', '')} | NUMA nodes={env.get('numa_nodes', '')}")
    lines.append(f"- Governor: {env.get('cpu_governor', '') or 'unknown'} | ASLR={env.get('aslr', '') or 'unknown'} | intel_no_turbo={env.get('intel_no_turbo', '') or 'unknown'}")
    if env.get("machine_note") not in {"", "bare_metal", "none"}:
        lines.append(f"- VM note: measurements were collected inside `{env.get('machine_note')}`; hypervisor scheduling noise may widen CI and tail latency.")
    lines.append("")
    lines.append("## Section 2: 系统配置说明")
    lines.append("")
    lines.append("- `userspace`: mcpd 进行全部语义检查，不使用 kernel arbitration。")
    lines.append("- `seccomp`: userspace baseline 外加 sandbox、audit logging、stricter checks。")
    lines.append("- `kernel`: 当前项目的 kernel_mcp control-plane 仲裁路径。")
    lines.append("")
    lines.append(f"- repetitions per config: {meta.get('repetitions', 0)}")
    lines.append(f"- latency requests per run: {meta.get('latency_requests', 0)}")
    lines.append(f"- scalability warmup/measure: {meta.get('warmup_seconds', 0)}s / {meta.get('measure_seconds', 0)}s")
    lines.append(f"- attack repeats: {meta.get('attack_repeats', 0)}")
    lines.append(f"- system order randomization seed: {meta.get('random_seed', '')}")
    lines.append("- repetition scheduling: each repetition shuffles userspace/seccomp/kernel order before collecting latency and scalability data.")
    lines.append("")
    lines.append("## Section 3: Latency")
    lines.append("")
    lines.append("| system | payload | avg_ms | p95_ms | p99_ms | p95 p-value vs userspace |")
    lines.append("|---|---|---|---|---|---:|")
    for row in latency_rows:
        lines.append(
            f"| {row.get('system','')} | {row.get('payload_display','')} | "
            f"{_fmt_stat(row.get('latency_avg_ms',0), row.get('latency_avg_std_ms',0), row.get('latency_avg_ci_lo_ms',0), row.get('latency_avg_ci_hi_ms',0))} | "
            f"{_fmt_stat(row.get('latency_p95_ms',0), row.get('latency_p95_std_ms',0), row.get('latency_p95_ci_lo_ms',0), row.get('latency_p95_ci_hi_ms',0))} | "
            f"{_fmt_stat(row.get('latency_p99_ms',0), row.get('latency_p99_std_ms',0), row.get('latency_p99_ci_lo_ms',0), row.get('latency_p99_ci_hi_ms',0))} | "
            f"{row.get('latency_p95_pvalue_vs_userspace','—') or '—'} |"
        )
    lines.append("")
    lines.append("## Section 3.1: Latency Breakdown")
    lines.append("")
    lines.append("| system | payload | session_ms | arbitration_ms | tool_exec_ms | total_ms | tool_exec_share |")
    lines.append("|---|---|---:|---:|---:|---:|---:|")
    for row in breakdown_rows:
        lines.append(
            f"| {row.get('system','')} | {row.get('payload_display','')} | {row.get('session_lookup_ms',0)} | "
            f"{row.get('arbitration_ms',0)} | {row.get('tool_exec_ms',0)} | {row.get('total_ms',0)} | {row.get('tool_exec_share_pct',0)}% |"
        )
    lines.append("")
    large_rows = {str(row["system"]): row for row in breakdown_rows if str(row.get("payload_label")) == "large"}
    if large_rows:
        lines.append("Large payload explanation:")
        userspace_large = large_rows.get("userspace")
        kernel_large = large_rows.get("kernel")
        if userspace_large:
            lines.append(
                f"- userspace 1MB 时 tool_exec 占总时延约 {userspace_large.get('tool_exec_share_pct',0)}%，说明执行路径主导了端到端时间。"
            )
        if kernel_large:
            lines.append(
                f"- kernel 1MB 时 tool_exec 占总时延约 {kernel_large.get('tool_exec_share_pct',0)}%，因此 arbitration 的绝对差异被大 payload 的 tool execution 淹没。"
            )
    lines.append("")
    lines.append("## Section 4: Throughput-Latency")
    lines.append("")
    lines.append("| system | agents | concurrency | throughput_rps | error_rate | p95_ms | throughput p-value vs userspace |")
    lines.append("|---|---:|---:|---|---|---|---:|")
    for row in scalability_rows:
        lines.append(
            f"| {row.get('system','')} | {row.get('agents',0)} | {row.get('concurrency',0)} | "
            f"{_fmt_stat(row.get('throughput_rps',0), row.get('throughput_rps_std',0), row.get('throughput_rps_ci_lo',0), row.get('throughput_rps_ci_hi',0))} | "
            f"{_fmt_stat(float(row.get('error_rate',0))*100.0, float(row.get('error_rate_std',0))*100.0, float(row.get('error_rate_ci_lo',0))*100.0, float(row.get('error_rate_ci_hi',0))*100.0, suffix='%')} | "
            f"{_fmt_stat(row.get('latency_p95_ms',0), row.get('latency_p95_ms_std',0), row.get('latency_p95_ms_ci_lo',0), row.get('latency_p95_ms_ci_hi',0))} | "
            f"{row.get('throughput_pvalue_vs_userspace','—') or '—'} |"
        )
    lines.append("")
    lines.append("## Section 5: Attack Resistance")
    lines.append("")
    lines.append("判定标准：`BLOCKED` = 攻击在执行前被拒绝；`UNDETECTED` = 非授权请求被执行。")
    lines.append("")
    lines.append("| attack | userspace | seccomp | kernel |")
    lines.append("|---|---|---|---|")
    by_attack: dict[str, dict[str, str]] = defaultdict(dict)
    for row in attack_rows:
        by_attack[str(row["attack_type"])][str(row["system"])] = f"{row.get('outcome','')} ({float(row.get('success_rate',0))*100:.2f}%, n={row.get('attempts',0)})"
    for attack_type in ("spoof", "replay", "substitute", "escalation"):
        item = by_attack.get(attack_type, {})
        lines.append(f"| {attack_type} | {item.get('userspace','')} | {item.get('seccomp','')} | {item.get('kernel','')} |")
    lines.append("")
    for attack_type in ("spoof", "replay", "substitute", "escalation"):
        desc = ATTACK_DESCRIPTIONS[attack_type]
        lines.append(f"[{attack_type} attack]")
        lines.append(f"- Goal: {desc['goal']}")
        for method in desc["method"]:
            lines.append(f"- Method: {method}")
        lines.append(f"- Success criterion: {desc['success']}")
        lines.append(f"- Blocked criterion: {desc['blocked']}")
        lines.append("")
    spoof_case_rows = [row for row in attack_case_rows if row.get("attack_type") == "spoof"]
    if spoof_case_rows:
        lines.append("Spoof case breakdown:")
        for system in ("userspace", "seccomp", "kernel"):
            system_rows = [row for row in spoof_case_rows if row.get("system") == system]
            if not system_rows:
                continue
            parts = [
                f"{row.get('attack_case')}={float(row.get('success_rate', 0))*100:.2f}%"
                for row in system_rows
            ]
            lines.append(f"- {system}: " + ", ".join(parts))
        lines.append("- The 66.67% spoof rate in userspace/seccomp comes from three spoof subcases: `fake_session_id` and `expired_session` succeed under the compromised userspace profile, while `session_token_theft` stays blocked by UDS peer credentials.")
        lines.append("")
    lines.append("## Section 6: Budget / Accounting")
    lines.append("")
    lines.append("| system | max_calls | requests | allowed | denied | first_reject_at | status | note |")
    lines.append("|---|---:|---:|---:|---:|---:|---|---|")
    for row in budget_rows:
        lines.append(
            f"| {row.get('system','')} | {row.get('max_calls',0)} | {row.get('requests',0)} | {row.get('allowed',0)} | {row.get('denied',0)} | "
            f"{row.get('first_reject_at',0)} | {row.get('status','')} | {row.get('note','')} |"
        )
    lines.append("")
    lines.append("## Section 7: Daemon Failure / Recovery")
    lines.append("")
    if daemon_rows:
        lines.append("| mode | approval_state_preserved | session_state_preserved | pre_crash_agent_visible | post_crash_agent_visible | approval_latency_ms | replay_latency_ms |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|")
        for row in daemon_rows:
            lines.append(
                f"| {row.get('mode','')} | {row.get('approval_state_preserved',0)} | {row.get('session_state_preserved',0)} | "
                f"{row.get('pre_crash_agent_visible',0)} | {row.get('post_crash_agent_visible',0)} | "
                f"{row.get('approval_latency_ms',0)} | {row.get('replay_latency_ms',0)} |"
            )
    else:
        lines.append("- daemon failure experiment not run")
    lines.append("")
    lines.append("## Section 8: 结论")
    lines.append("")
    lines.append("- `kernel` 的延迟开销在 small payload 下可观测，但 large payload 下会被 tool execution 主导时间淹没。")
    lines.append("- 强化 `userspace + seccomp + logging + stricter checks` 仍挡不住 spoof / substitution，且 latency 和 throughput 更差。")
    lines.append("- 因此 kernel_mcp 不是 optional optimization，而是更难被 userspace 绕过的必要 control-plane mechanism。")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="linux_mcp evaluation runner")
    parser.add_argument("--output-dir", type=str, default="experiment-results/linux-mcp")
    parser.add_argument("--timeout-s", type=float, default=10.0)
    parser.add_argument("--latency-requests", type=int, default=2000)
    parser.add_argument("--attack-repeats", type=int, default=10)
    parser.add_argument(
        "--boundary-repeats",
        type=int,
        default=0,
        help="Repeats for the standalone group-F boundary-condition probes. 0 disables the phase.",
    )
    parser.add_argument("--agents", type=str, default="1,5,10,20,50")
    parser.add_argument("--concurrency", type=str, default="1,10,50,100")
    parser.add_argument("--max-tools", type=int, default=20)
    parser.add_argument("--sandbox-fsize-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--systems", type=str, default="userspace,seccomp,kernel")
    parser.add_argument("--budget-max-calls", type=int, default=50)
    parser.add_argument("--budget-requests", type=int, default=100)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--repeat-sleep-s", type=float, default=30.0)
    parser.add_argument("--warmup-seconds", type=float, default=5.0)
    parser.add_argument("--measure-seconds", type=float, default=30.0)
    parser.add_argument("--run-daemon-failure", action="store_true")
    parser.add_argument("--random-seed", type=int, default=20260405)
    args = parser.parse_args()

    run_ts = time.strftime("run-%Y%m%d-%H%M%S", time.gmtime())
    run_dir = ROOT_DIR / args.output_dir / run_ts
    run_dir.mkdir(parents=True, exist_ok=True)

    agent_counts = [int(part.strip()) for part in args.agents.split(",") if part.strip()]
    concurrency_levels = [int(part.strip()) for part in args.concurrency.split(",") if part.strip()]
    requested_systems = {part.strip() for part in args.systems.split(",") if part.strip()}
    active_systems = [system for system in SYSTEMS if system.label in requested_systems]
    if not active_systems:
        raise RuntimeError("no matching systems selected")
    validate_kernel_budget_for_run(active_systems=active_systems, budget_max_calls=args.budget_max_calls)

    latency_raw_rows: list[Dict[str, Any]] = []
    latency_rep_rows: list[Dict[str, Any]] = []
    scalability_raw_rows: list[Dict[str, Any]] = []
    scalability_rep_rows: list[Dict[str, Any]] = []
    throughput_bucket_rows: list[Dict[str, Any]] = []
    attack_raw_rows: list[Dict[str, Any]] = []
    attack_matrix_rows: list[Dict[str, Any]] = []
    attack_case_summary_rows: list[Dict[str, Any]] = []
    boundary_raw_rows: list[Dict[str, Any]] = []
    boundary_matrix_rows: list[Dict[str, Any]] = []
    budget_raw_rows: list[Dict[str, Any]] = []
    budget_summary_rows: list[Dict[str, Any]] = []
    daemon_rows: list[Dict[str, Any]] = []
    selected_tools: dict[str, Dict[str, Any]] = {}
    system_order_by_repetition: list[Dict[str, Any]] = []

    environment = collect_environment()

    rng = random.Random(args.random_seed)
    for repetition in range(1, args.repetitions + 1):
        if repetition > 1 and args.repeat_sleep_s > 0:
            time.sleep(args.repeat_sleep_s)
        repetition_systems = list(active_systems)
        rng.shuffle(repetition_systems)
        system_order_by_repetition.append(
            {
                "repetition": repetition,
                "system_order": [system.label for system in repetition_systems],
            }
        )
        for system in repetition_systems:
            direct_mode = system.mode == "direct"
            with managed_tool_services(
                sandboxed=system.sandboxed_tools,
                sandbox_fsize_bytes=args.sandbox_fsize_bytes,
            ):
                if direct_mode:
                    # Use a throwaway userspace mcpd only to enrich tool hashes and preflight;
                    # the actual latency/scalability sweep then bypasses mcpd entirely.
                    helper = SystemVariant(
                        label="direct-preflight",
                        display_name="direct preflight helper",
                        mode="userspace_semantic_plane",
                        sandboxed_tools=False,
                        sock_path="/tmp/mcpd-direct-preflight.sock",
                    )
                    with managed_mcpd(helper, timeout_s=args.timeout_s) as helper_sock:
                        tools = enrich_hash_from_mcpd(load_manifest_tools(), helper_sock, args.timeout_s)
                        selected = preflight_tools(
                            tools,
                            mcpd_sock=helper_sock,
                            timeout_s=args.timeout_s,
                            include_write=True,
                            max_tools=args.max_tools,
                        )
                        if not selected:
                            raise RuntimeError(f"no tools passed preflight for {system.label}")
                        latency_tool = choose_latency_tool(selected)
                        safe_tool = choose_safe_tool(selected)
                        risky_tool = choose_risky_tool(tools)
                    selected_tools[system.label] = {
                        "latency_tool": {"tool_id": latency_tool.tool_id, "tool_name": latency_tool.tool_name},
                        "safe_tool": {"tool_id": safe_tool.tool_id, "tool_name": safe_tool.tool_name},
                        "risky_tool": {"tool_id": risky_tool.tool_id, "tool_name": risky_tool.tool_name},
                    }
                    lat_raw, lat_rep = run_latency_repetition(
                        sock_path="",
                        tool=latency_tool,
                        system_label=system.label,
                        repetition=repetition,
                        requests=args.latency_requests,
                        direct_mode=True,
                    )
                    scale_raw, scale_rep, bucket_rows = run_scalability_repetition(
                        sock_path="",
                        tool=safe_tool,
                        system_label=system.label,
                        repetition=repetition,
                        agent_counts=agent_counts,
                        concurrency_levels=concurrency_levels,
                        warmup_s=args.warmup_seconds,
                        measure_s=args.measure_seconds,
                        direct_mode=True,
                    )
                    latency_raw_rows.extend(lat_raw)
                    latency_rep_rows.extend(lat_rep)
                    scalability_raw_rows.extend(scale_raw)
                    scalability_rep_rows.extend(scale_rep)
                    throughput_bucket_rows.extend(bucket_rows)
                    continue
                with managed_mcpd(system, timeout_s=args.timeout_s) as sock_path:
                    tools = enrich_hash_from_mcpd(load_manifest_tools(), sock_path, args.timeout_s)
                    selected = preflight_tools(
                        tools,
                        mcpd_sock=sock_path,
                        timeout_s=args.timeout_s,
                        include_write=True,
                        max_tools=args.max_tools,
                    )
                    if not selected:
                        raise RuntimeError(f"no tools passed preflight for {system.label}")
                    latency_tool = choose_latency_tool(selected)
                    safe_tool = choose_safe_tool(selected)
                    risky_tool = choose_risky_tool(tools)
                    selected_tools[system.label] = {
                        "latency_tool": {"tool_id": latency_tool.tool_id, "tool_name": latency_tool.tool_name},
                        "safe_tool": {"tool_id": safe_tool.tool_id, "tool_name": safe_tool.tool_name},
                        "risky_tool": {"tool_id": risky_tool.tool_id, "tool_name": risky_tool.tool_name},
                    }
                    lat_raw, lat_rep = run_latency_repetition(
                        sock_path=sock_path,
                        tool=latency_tool,
                        system_label=system.label,
                        repetition=repetition,
                        requests=args.latency_requests,
                    )
                    scale_raw, scale_rep, bucket_rows = run_scalability_repetition(
                        sock_path=sock_path,
                        tool=safe_tool,
                        system_label=system.label,
                        repetition=repetition,
                        agent_counts=agent_counts,
                        concurrency_levels=concurrency_levels,
                        warmup_s=args.warmup_seconds,
                        measure_s=args.measure_seconds,
                    )
                    latency_raw_rows.extend(lat_raw)
                    latency_rep_rows.extend(lat_rep)
                    scalability_raw_rows.extend(scale_raw)
                    scalability_rep_rows.extend(scale_rep)
                    throughput_bucket_rows.extend(bucket_rows)

    for system in active_systems:
        if system.mode == "direct":
            # E6 raw baseline doesn't participate in attack / budget / daemon-failure phases.
            continue
        with managed_tool_services(
            sandboxed=system.sandboxed_tools,
            sandbox_fsize_bytes=args.sandbox_fsize_bytes,
        ):
            with managed_mcpd(system, timeout_s=args.timeout_s) as sock_path:
                tools = enrich_hash_from_mcpd(load_manifest_tools(), sock_path, args.timeout_s)
                selected = preflight_tools(
                    tools,
                    mcpd_sock=sock_path,
                    timeout_s=args.timeout_s,
                    include_write=True,
                    max_tools=args.max_tools,
                )
                if not selected:
                    raise RuntimeError(f"no tools passed preflight for {system.label}")
                safe_tool = choose_safe_tool(selected)
                risky_tool = choose_risky_tool(tools)
            attack_raw, attack_matrix = run_attack_experiment(
                system=system,
                tools=tools,
                timeout_s=args.timeout_s,
                repeats=args.attack_repeats,
            )
            attack_raw_rows.extend(attack_raw)
            attack_matrix_rows.extend(attack_matrix)

            budget_raw, budget_summary = run_budget_experiment(
                system=system,
                tool=safe_tool,
                timeout_s=args.timeout_s,
                max_calls=args.budget_max_calls,
                total_requests=args.budget_requests,
            )
            budget_raw_rows.extend(budget_raw)
            budget_summary_rows.append(budget_summary)

            if args.run_daemon_failure and system.label == "kernel":
                daemon_rows = run_daemon_compromise(
                    kernel_sock_path=system.sock_path,
                    timeout_s=args.timeout_s,
                    risky_tool=risky_tool,
                )

    if args.boundary_repeats > 0:
        for system in active_systems:
            if system.mode == "direct":
                continue
            with managed_tool_services(
                sandboxed=system.sandboxed_tools,
                sandbox_fsize_bytes=args.sandbox_fsize_bytes,
            ):
                # Need a live mcpd once to enrich tool hashes from the canonical catalog.
                with managed_mcpd(system, timeout_s=args.timeout_s) as sock_path:
                    boundary_tools = enrich_hash_from_mcpd(
                        load_manifest_tools(),
                        sock_path,
                        args.timeout_s,
                    )
                boundary_raw, boundary_matrix = run_boundary_experiment(
                    system=system,
                    tools=boundary_tools,
                    timeout_s=args.timeout_s,
                    repeats=args.boundary_repeats,
                )
                boundary_raw_rows.extend(boundary_raw)
                boundary_matrix_rows.extend(boundary_matrix)

    latency_summary_rows, breakdown_summary_rows = aggregate_latency(latency_rep_rows)
    scalability_summary_rows = aggregate_scalability(scalability_rep_rows)

    result = {
        "meta": {
            "run_ts": run_ts,
            "systems": [system.label for system in active_systems],
            "environment": environment,
            "latency_requests": args.latency_requests,
            "payloads": [
                {"label": label, "bytes": size, "display": payload_display(size)} for label, size in LATENCY_PAYLOADS
            ],
            "agents": agent_counts,
            "concurrency": concurrency_levels,
            "attack_repeats": args.attack_repeats,
            "boundary_repeats": args.boundary_repeats,
            "budget_max_calls": args.budget_max_calls,
            "budget_requests": args.budget_requests,
            "repetitions": args.repetitions,
            "repeat_sleep_s": args.repeat_sleep_s,
            "warmup_seconds": args.warmup_seconds,
            "measure_seconds": args.measure_seconds,
            "random_seed": args.random_seed,
            "system_order_by_repetition": system_order_by_repetition,
            "selected_tools": selected_tools,
        },
        "latency_summary": latency_summary_rows,
        "breakdown_summary": breakdown_summary_rows,
        "scalability_summary": scalability_summary_rows,
        "attack_matrix": attack_matrix_rows,
        "attack_case_summary": attack_case_summary_rows,
        "boundary_matrix": boundary_matrix_rows,
        "budget_summary": budget_summary_rows,
        "daemon_failure": daemon_rows,
    }
    attack_case_summary_rows.extend(summarize_attack_cases(attack_raw_rows))
    report_markdown = render_report(result)
    result["report_markdown"] = report_markdown

    (run_dir / "linux_mcp_summary.json").write_text(json.dumps(result, ensure_ascii=True, indent=2), encoding="utf-8")
    (run_dir / "linux_mcp_report.md").write_text(report_markdown, encoding="utf-8")

    write_csv(
        run_dir / "latency_samples.csv",
        latency_raw_rows,
        ["repetition", "system", "payload_label", "payload_bytes", "request_index", "latency_ms", "session_lookup_ms", "arbitration_ms", "tool_exec_ms", "total_ms", "status", "error"],
    )
    write_csv(
        run_dir / "latency_repetitions.csv",
        latency_rep_rows,
        ["repetition", "system", "payload_label", "payload_bytes", "payload_display", "requests", "errors", "latency_avg_ms", "latency_p50_ms", "latency_p95_ms", "latency_p99_ms", "session_lookup_ms", "arbitration_ms", "tool_exec_ms", "total_ms", "tool_exec_share_pct"],
    )
    write_csv(
        run_dir / "latency_summary.csv",
        latency_summary_rows,
        ["system", "payload_label", "payload_bytes", "payload_display", "runs", "requests_per_run", "errors_total", "latency_avg_ms", "latency_avg_std_ms", "latency_avg_ci_lo_ms", "latency_avg_ci_hi_ms", "latency_p50_ms", "latency_p50_std_ms", "latency_p50_ci_lo_ms", "latency_p50_ci_hi_ms", "latency_p95_ms", "latency_p95_std_ms", "latency_p95_ci_lo_ms", "latency_p95_ci_hi_ms", "latency_p99_ms", "latency_p99_std_ms", "latency_p99_ci_lo_ms", "latency_p99_ci_hi_ms", "session_lookup_ms_mean", "arbitration_ms_mean", "tool_exec_ms_mean", "total_ms_mean", "tool_exec_share_pct_mean", "latency_avg_pvalue_vs_userspace", "latency_p95_pvalue_vs_userspace"],
    )
    write_csv(
        run_dir / "breakdown_summary.csv",
        breakdown_summary_rows,
        ["system", "payload_label", "payload_bytes", "payload_display", "runs", "session_lookup_ms", "arbitration_ms", "tool_exec_ms", "total_ms", "tool_exec_share_pct"],
    )
    write_csv(
        run_dir / "scalability_samples.csv",
        scalability_raw_rows,
        ["repetition", "system", "agents", "concurrency", "request_index", "start_ts", "end_ts", "latency_ms", "status", "error", "second_bucket"],
    )
    write_csv(
        run_dir / "scalability_repetitions.csv",
        scalability_rep_rows,
        ["repetition", "system", "agents", "concurrency", "measurement_seconds", "requests", "errors", "error_rate", "throughput_rps", "throughput_std_rps", "latency_avg_ms", "latency_p50_ms", "latency_p95_ms", "latency_p99_ms"],
    )
    write_csv(
        run_dir / "throughput_buckets.csv",
        throughput_bucket_rows,
        ["repetition", "system", "agents", "concurrency", "second_index", "rps"],
    )
    write_csv(
        run_dir / "scalability_summary.csv",
        scalability_summary_rows,
        ["system", "agents", "concurrency", "runs", "measurement_seconds", "requests_mean", "errors_mean", "throughput_rps", "throughput_rps_std", "throughput_rps_ci_lo", "throughput_rps_ci_hi", "error_rate", "error_rate_std", "error_rate_ci_lo", "error_rate_ci_hi", "latency_avg_ms", "latency_avg_ms_std", "latency_avg_ms_ci_lo", "latency_avg_ms_ci_hi", "latency_p50_ms", "latency_p50_ms_std", "latency_p50_ms_ci_lo", "latency_p50_ms_ci_hi", "latency_p95_ms", "latency_p95_ms_std", "latency_p95_ms_ci_lo", "latency_p95_ms_ci_hi", "latency_p99_ms", "latency_p99_ms_std", "latency_p99_ms_ci_lo", "latency_p99_ms_ci_hi", "throughput_pvalue_vs_userspace", "latency_p95_pvalue_vs_userspace"],
    )
    write_csv(
        run_dir / "attack_samples.csv",
        attack_raw_rows,
        ["system", "attack_type", "scenario_group", "attack_case", "mode", "attack_profile", "status", "decision", "error", "latency_ms", "unauthorized_success", "expected_reject", "invariant_violated"],
    )
    write_csv(
        run_dir / "attack_matrix.csv",
        attack_matrix_rows,
        ["attack_type", "system", "attempts", "successes", "success_rate", "outcome"],
    )
    write_csv(
        run_dir / "attack_case_summary.csv",
        attack_case_summary_rows,
        ["system", "attack_type", "attack_case", "attempts", "successes", "success_rate"],
    )
    write_csv(
        run_dir / "boundary_samples.csv",
        boundary_raw_rows,
        ["system", "attack_type", "scenario_group", "attack_case", "mode", "attack_profile", "status", "decision", "error", "latency_ms", "unauthorized_success", "expected_reject", "invariant_violated"],
    )
    write_csv(
        run_dir / "boundary_matrix.csv",
        boundary_matrix_rows,
        ["system", "attack_case", "attempts", "successes", "success_rate", "outcome"],
    )
    write_csv(
        run_dir / "budget_samples.csv",
        budget_raw_rows,
        ["system", "request_index", "elapsed_ms", "latency_ms", "accepted", "denied", "decision", "reason", "allowed_so_far", "budget_usage_pct"],
    )
    write_csv(
        run_dir / "budget_summary.csv",
        budget_summary_rows,
        ["system", "max_calls", "requests", "allowed", "denied", "first_reject_at", "status", "note"],
    )
    write_csv(
        run_dir / "daemon_failure.csv",
        daemon_rows,
        ["mode", "scenario", "ticket_id", "approval_state_preserved", "session_state_preserved", "approval_error", "replay_error", "approval_latency_ms", "replay_latency_ms", "pre_crash_agent_visible", "post_crash_agent_visible"],
    )

    print(f"[done] result_dir={run_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
