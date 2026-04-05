#!/usr/bin/env python3
"""linux_mcp evaluation runner focused on overhead, enforcement, and scale."""

from __future__ import annotations

import argparse
import contextlib
import csv
import json
import os
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Sequence

from benchmark_suite import (
    DEFAULT_MCPD_SOCK,
    ToolCase,
    enrich_hash_from_mcpd,
    load_manifest_tools,
    percentile,
    preflight_tools,
)
from security_eval import (
    build_exec_req,
    invoke_mcpd,
    scenario_approval_forgery,
    scenario_compromised_mediator,
    scenario_metadata_tampering,
    scenario_session_forgery,
    wait_mcpd_ready,
    launch_mcpd_variant,
    stop_process,
)

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


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


def write_csv(path: Path, rows: Sequence[Dict[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def _run_root_script(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT_DIR, check=True)  # noqa: S603


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


def run_latency_experiment(
    *,
    sock_path: str,
    tool: ToolCase,
    system_label: str,
    requests: int,
) -> tuple[list[Dict[str, Any]], list[Dict[str, Any]]]:
    session_resp, _ = invoke_mcpd(
        sock_path=sock_path,
        timeout_s=10.0,
        req={"sys": "open_session", "client_name": f"latency-{system_label}", "ttl_ms": 10 * 60 * 1000},
    )
    if session_resp.get("status") != "ok":
        raise RuntimeError(f"open_session failed for {system_label}: {session_resp}")
    session_id = str(session_resp["session_id"])
    raw_rows: list[Dict[str, Any]] = []
    summary_rows: list[Dict[str, Any]] = []
    for payload_label, payload_size in LATENCY_PAYLOADS:
        latencies: list[float] = []
        errors = 0
        for req_index in range(requests):
            payload = build_latency_payload(tool, size_bytes=payload_size, req_index=req_index)
            req = build_exec_req(
                req_id=100000 + req_index,
                session_id=session_id,
                tool=tool,
                payload=payload,
                tool_hash=tool.manifest_hash,
            )
            resp, latency_ms = invoke_mcpd(sock_path=sock_path, timeout_s=20.0, req=req)
            ok = resp.get("status") == "ok"
            if not ok:
                errors += 1
            latencies.append(latency_ms)
            raw_rows.append(
                {
                    "system": system_label,
                    "payload_label": payload_label,
                    "payload_bytes": payload_size,
                    "request_index": req_index,
                    "latency_ms": round(latency_ms, 3),
                    "status": resp.get("status", ""),
                    "error": str(resp.get("error", "")),
                }
            )
        summary = summarize_durations_ms(latencies)
        summary_rows.append(
            {
                "system": system_label,
                "payload_label": payload_label,
                "payload_bytes": payload_size,
                "requests": requests,
                "errors": errors,
                "latency_avg_ms": summary["avg"],
                "latency_p50_ms": summary["p50"],
                "latency_p95_ms": summary["p95"],
                "latency_p99_ms": summary["p99"],
            }
        )
    return raw_rows, summary_rows


def _scalability_worker(
    *,
    sock_path: str,
    session_id: str,
    tool: ToolCase,
    request_count: int,
    worker_id: int,
) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for req_index in range(request_count):
        req = build_exec_req(
            req_id=200000 + worker_id * 10000 + req_index,
            session_id=session_id,
            tool=tool,
            tool_hash=tool.manifest_hash,
        )
        start_ts = time.time()
        resp, latency_ms = invoke_mcpd(sock_path=sock_path, timeout_s=10.0, req=req)
        rows.append(
            {
                "worker_id": worker_id,
                "request_index": req_index,
                "latency_ms": round(latency_ms, 3),
                "status": resp.get("status", ""),
                "error": str(resp.get("error", "")),
                "start_ts": round(start_ts, 6),
                "end_ts": round(time.time(), 6),
            }
        )
    return rows


def run_scalability_experiment(
    *,
    sock_path: str,
    tool: ToolCase,
    system_label: str,
    agent_counts: Sequence[int],
    concurrency_levels: Sequence[int],
    calls_per_agent: int,
) -> tuple[list[Dict[str, Any]], list[Dict[str, Any]]]:
    raw_rows: list[Dict[str, Any]] = []
    summary_rows: list[Dict[str, Any]] = []
    for agent_count in agent_counts:
        sessions: list[str] = []
        for agent_idx in range(agent_count):
            session_resp, _ = invoke_mcpd(
                sock_path=sock_path,
                timeout_s=10.0,
                req={
                    "sys": "open_session",
                    "client_name": f"scale-{system_label}-{agent_idx}",
                    "ttl_ms": 10 * 60 * 1000,
                },
            )
            if session_resp.get("status") != "ok":
                raise RuntimeError(f"open_session failed for {system_label}: {session_resp}")
            sessions.append(str(session_resp["session_id"]))
        total_requests = agent_count * calls_per_agent
        for concurrency in concurrency_levels:
            worker_count = min(concurrency, total_requests)
            base = total_requests // worker_count
            rem = total_requests % worker_count
            started = time.perf_counter()
            scenario_rows: list[Dict[str, Any]] = []
            with ThreadPoolExecutor(max_workers=worker_count) as pool:
                futures = []
                for worker_id in range(worker_count):
                    count = base + (1 if worker_id < rem else 0)
                    if count <= 0:
                        continue
                    session_id = sessions[worker_id % len(sessions)]
                    futures.append(
                        pool.submit(
                            _scalability_worker,
                            sock_path=sock_path,
                            session_id=session_id,
                            tool=tool,
                            request_count=count,
                            worker_id=worker_id,
                        )
                    )
                for fut in as_completed(futures):
                    scenario_rows.extend(fut.result())
            elapsed_s = max(time.perf_counter() - started, 1e-9)
            latencies = [float(row["latency_ms"]) for row in scenario_rows]
            errors = sum(1 for row in scenario_rows if row["status"] != "ok")
            summary = summarize_durations_ms(latencies)
            summary_rows.append(
                {
                    "system": system_label,
                    "agents": agent_count,
                    "concurrency": concurrency,
                    "requests": total_requests,
                    "errors": errors,
                    "error_rate": round(errors / max(total_requests, 1), 6),
                    "throughput_rps": round(total_requests / elapsed_s, 3),
                    "latency_avg_ms": summary["avg"],
                    "latency_p50_ms": summary["p50"],
                    "latency_p95_ms": summary["p95"],
                    "latency_p99_ms": summary["p99"],
                }
            )
            for row in scenario_rows:
                raw_rows.append(
                    {
                        "system": system_label,
                        "agents": agent_count,
                        "concurrency": concurrency,
                        **row,
                    }
                )
    return raw_rows, summary_rows


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
        raw_rows.extend(
            {
                "system": system.label,
                "attack_type": attack_type,
                **row,
            }
            for row in rows
        )
        relevant_rows = [
            row for row in rows if str(row.get("attack_case", "")) in ATTACK_CASE_FILTERS[attack_type]
        ]
        attempts = len(relevant_rows)
        successes = sum(int(row.get("unauthorized_success", 0)) for row in relevant_rows)
        matrix_rows.append(
            {
                "attack_type": attack_type,
                "system": system.label,
                "attempts": attempts,
                "successes": successes,
                "success_rate": round(successes / max(attempts, 1), 6),
                "outcome": "success" if successes > 0 else "fail",
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
        return (
            [],
            {
                "system": system.label,
                "max_calls": max_calls,
                "requests": total_requests,
                "allowed": 0,
                "denied": 0,
                "first_reject_at": 0,
            },
        )
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
        session_resp, _ = invoke_mcpd(
            sock_path=sock_path,
            timeout_s=timeout_s,
            req={"sys": "open_session", "client_name": f"budget-{system.label}", "ttl_ms": 10 * 60 * 1000},
        )
        if session_resp.get("status") != "ok":
            raise RuntimeError(f"open_session failed for budget experiment {system.label}: {session_resp}")
        session_id = str(session_resp["session_id"])
        raw_rows: list[Dict[str, Any]] = []
        allowed = 0
        denied = 0
        start = time.perf_counter()
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
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            raw_rows.append(
                {
                    "system": system.label,
                    "request_index": req_index + 1,
                    "elapsed_ms": round(elapsed_ms, 3),
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
        summary = {
            "system": system.label,
            "max_calls": max_calls,
            "requests": total_requests,
            "allowed": allowed,
            "denied": denied,
            "first_reject_at": first_reject,
        }
        return raw_rows, summary


def render_report(summary: Dict[str, Any]) -> str:
    latency_rows = summary.get("latency_summary", [])
    scalability_rows = summary.get("scalability_summary", [])
    attack_rows = summary.get("attack_matrix", [])
    budget_rows = summary.get("budget_summary", [])
    lines: list[str] = []
    lines.append("# linux_mcp Experiment Report")
    lines.append("")
    lines.append("## Latency")
    lines.append("")
    lines.append("| system | payload | requests | errors | avg_ms | p50_ms | p95_ms | p99_ms |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|")
    for row in latency_rows:
        lines.append(
            f"| {row.get('system','')} | {row.get('payload_label','')} | {row.get('requests',0)} | {row.get('errors',0)} | "
            f"{row.get('latency_avg_ms',0.0)} | {row.get('latency_p50_ms',0.0)} | {row.get('latency_p95_ms',0.0)} | {row.get('latency_p99_ms',0.0)} |"
        )
    lines.append("")
    lines.append("## Scalability")
    lines.append("")
    lines.append("| system | agents | concurrency | requests | throughput_rps | error_rate | p95_ms | p99_ms |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for row in scalability_rows:
        lines.append(
            f"| {row.get('system','')} | {row.get('agents',0)} | {row.get('concurrency',0)} | {row.get('requests',0)} | "
            f"{row.get('throughput_rps',0.0)} | {float(row.get('error_rate',0.0))*100:.2f}% | "
            f"{row.get('latency_p95_ms',0.0)} | {row.get('latency_p99_ms',0.0)} |"
        )
    lines.append("")
    lines.append("## Attack Matrix")
    lines.append("")
    lines.append("| attack_type | userspace | seccomp | kernel |")
    lines.append("|---|---|---|---|")
    by_attack: dict[str, dict[str, str]] = {}
    for row in attack_rows:
        by_attack.setdefault(str(row["attack_type"]), {})[str(row["system"])] = str(row["outcome"])
    for attack_type in ("spoof", "replay", "substitute", "escalation"):
        item = by_attack.get(attack_type, {})
        lines.append(
            f"| {attack_type} | {item.get('userspace','')} | {item.get('seccomp','')} | {item.get('kernel','')} |"
        )
    lines.append("")
    lines.append("## Budget")
    lines.append("")
    lines.append("| system | max_calls | requests | allowed | denied | first_reject_at |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for row in budget_rows:
        lines.append(
            f"| {row.get('system','')} | {row.get('max_calls',0)} | {row.get('requests',0)} | {row.get('allowed',0)} | "
            f"{row.get('denied',0)} | {row.get('first_reject_at',0)} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="linux_mcp evaluation runner")
    parser.add_argument("--output-dir", type=str, default="experiment-results/linux-mcp")
    parser.add_argument("--timeout-s", type=float, default=10.0)
    parser.add_argument("--latency-requests", type=int, default=1000)
    parser.add_argument("--attack-repeats", type=int, default=5)
    parser.add_argument("--agents", type=str, default="1,5,10,20,50")
    parser.add_argument("--concurrency", type=str, default="1,10,50,100")
    parser.add_argument("--calls-per-agent", type=int, default=100)
    parser.add_argument("--max-tools", type=int, default=20)
    parser.add_argument("--sandbox-fsize-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--systems", type=str, default="userspace,seccomp,kernel")
    parser.add_argument("--budget-max-calls", type=int, default=50)
    parser.add_argument("--budget-requests", type=int, default=100)
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

    latency_raw_rows: list[Dict[str, Any]] = []
    latency_summary_rows: list[Dict[str, Any]] = []
    scalability_raw_rows: list[Dict[str, Any]] = []
    scalability_summary_rows: list[Dict[str, Any]] = []
    attack_raw_rows: list[Dict[str, Any]] = []
    attack_matrix_rows: list[Dict[str, Any]] = []
    budget_raw_rows: list[Dict[str, Any]] = []
    budget_summary_rows: list[Dict[str, Any]] = []
    selected_tools: dict[str, Dict[str, Any]] = {}

    for system in active_systems:
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
                latency_tool = choose_latency_tool(selected)
                safe_tool = choose_safe_tool(selected)
                risky_tool = choose_risky_tool(tools)
                selected_tools[system.label] = {
                    "latency_tool": {"tool_id": latency_tool.tool_id, "tool_name": latency_tool.tool_name},
                    "safe_tool": {"tool_id": safe_tool.tool_id, "tool_name": safe_tool.tool_name},
                    "risky_tool": {"tool_id": risky_tool.tool_id, "tool_name": risky_tool.tool_name},
                }

                lat_raw, lat_summary = run_latency_experiment(
                    sock_path=sock_path,
                    tool=latency_tool,
                    system_label=system.label,
                    requests=args.latency_requests,
                )
                latency_raw_rows.extend(lat_raw)
                latency_summary_rows.extend(lat_summary)

                scale_raw, scale_summary = run_scalability_experiment(
                    sock_path=sock_path,
                    tool=safe_tool,
                    system_label=system.label,
                    agent_counts=agent_counts,
                    concurrency_levels=concurrency_levels,
                    calls_per_agent=args.calls_per_agent,
                )
                scalability_raw_rows.extend(scale_raw)
                scalability_summary_rows.extend(scale_summary)

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

    result = {
        "meta": {
            "run_ts": run_ts,
            "systems": [system.label for system in active_systems],
            "latency_requests": args.latency_requests,
            "payloads": [{"label": label, "bytes": size} for label, size in LATENCY_PAYLOADS],
            "agents": agent_counts,
            "concurrency": concurrency_levels,
            "calls_per_agent": args.calls_per_agent,
            "attack_repeats": args.attack_repeats,
            "budget_max_calls": args.budget_max_calls,
            "budget_requests": args.budget_requests,
            "selected_tools": selected_tools,
        },
        "latency_summary": latency_summary_rows,
        "scalability_summary": scalability_summary_rows,
        "attack_matrix": attack_matrix_rows,
        "budget_summary": budget_summary_rows,
    }
    (run_dir / "linux_mcp_summary.json").write_text(
        json.dumps(result, ensure_ascii=True, indent=2),
        encoding="utf-8",
    )
    (run_dir / "linux_mcp_report.md").write_text(render_report(result), encoding="utf-8")

    write_csv(
        run_dir / "latency_samples.csv",
        latency_raw_rows,
        ["system", "payload_label", "payload_bytes", "request_index", "latency_ms", "status", "error"],
    )
    write_csv(
        run_dir / "latency_summary.csv",
        latency_summary_rows,
        ["system", "payload_label", "payload_bytes", "requests", "errors", "latency_avg_ms", "latency_p50_ms", "latency_p95_ms", "latency_p99_ms"],
    )
    write_csv(
        run_dir / "scalability_samples.csv",
        scalability_raw_rows,
        ["system", "agents", "concurrency", "worker_id", "request_index", "latency_ms", "status", "error", "start_ts", "end_ts"],
    )
    write_csv(
        run_dir / "scalability_summary.csv",
        scalability_summary_rows,
        ["system", "agents", "concurrency", "requests", "errors", "error_rate", "throughput_rps", "latency_avg_ms", "latency_p50_ms", "latency_p95_ms", "latency_p99_ms"],
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
        run_dir / "budget_samples.csv",
        budget_raw_rows,
        ["system", "request_index", "elapsed_ms", "latency_ms", "accepted", "denied", "decision", "reason", "allowed_so_far", "budget_usage_pct"],
    )
    write_csv(
        run_dir / "budget_summary.csv",
        budget_summary_rows,
        ["system", "max_calls", "requests", "allowed", "denied", "first_reject_at"],
    )

    print(f"[done] result_dir={run_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
