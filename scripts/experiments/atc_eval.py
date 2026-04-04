#!/usr/bin/env python3
"""ATC-oriented evaluation runner for linux-mcp.

This script complements the raw benchmark suite with experiments that map more
directly to a systems-paper evaluation:
- E2E overhead of the mediated path vs direct RPC
- control-plane RPC costs
- safety/correctness controls, including approval-path behavior
- control-plane scaling with synthetic manifest growth
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import json
import os
import statistics
import subprocess
import threading
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Sequence

from benchmark_suite import (
    DEFAULT_MCPD_SOCK,
    ToolCase,
    call_tool_direct,
    call_tool_via_mcpd,
    enrich_hash_from_mcpd,
    ensure_prerequisites,
    load_manifest_tools,
    open_session,
    parse_concurrency,
    percentile,
    preflight_tools,
    rpc_call,
    run_negative_controls,
    run_scenario,
    summarize_rows,
)

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
HIGH_RISK_TAGS = {
    "filesystem_delete",
    "device_control",
    "external_network",
    "privileged",
    "irreversible",
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
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def flatten_summary_rows(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in items:
        lat = item.get("latency_ms", {})
        rows.append(
            {
                "scenario": item.get("scenario", ""),
                "mode": item.get("mode", ""),
                "concurrency": item.get("concurrency", 0),
                "requests": item.get("requests", 0),
                "ok": item.get("ok", ""),
                "error": item.get("error", ""),
                "success_rate": item.get("success_rate", 0.0),
                "throughput_rps": item.get("throughput_rps", 0.0),
                "latency_avg_ms": lat.get("avg", 0.0),
                "latency_p50_ms": lat.get("p50", 0.0),
                "latency_p95_ms": lat.get("p95", 0.0),
                "latency_p99_ms": lat.get("p99", 0.0),
            }
        )
    return rows


def flatten_trace_rows(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in items:
        lat = item.get("latency_ms", {})
        rows.append(
            {
                "label": item.get("label", ""),
                "mode": item.get("mode", ""),
                "requests": item.get("requests", 0),
                "success_rate": item.get("success_rate", 0.0),
                "latency_avg_ms": lat.get("avg", 0.0),
                "latency_p50_ms": lat.get("p50", 0.0),
                "latency_p95_ms": lat.get("p95", 0.0),
                "latency_p99_ms": lat.get("p99", 0.0),
            }
        )
    return rows


def flatten_control_plane_rows(items: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for name, item in items.items():
        if not isinstance(item, dict):
            continue
        lat = item.get("latency_ms", {})
        rows.append(
            {
                "rpc": name,
                "repeats": item.get("repeats", 0),
                "ok": item.get("ok", 0),
                "error": item.get("error", 0),
                "success_rate": item.get("success_rate", 0.0),
                "sample_error": item.get("sample_error", ""),
                "latency_avg_ms": lat.get("avg", 0.0),
                "latency_p50_ms": lat.get("p50", 0.0),
                "latency_p95_ms": lat.get("p95", 0.0),
                "latency_p99_ms": lat.get("p99", 0.0),
            }
        )
    return rows


def flatten_negative_rows(items: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for name, item in items.items():
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "case": name,
                "repeats": item.get("repeats", 0),
                "error_rate": item.get("error_rate", 0.0),
                "deny_rate": item.get("deny_rate", 0.0),
                "defer_rate": item.get("defer_rate", 0.0),
                "latency_avg_ms": item.get("latency_ms_avg", 0.0),
                "latency_p95_ms": item.get("latency_ms_p95", 0.0),
            }
        )
    return rows


def flatten_policy_mix_rows(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in items:
        lat = item.get("latency_ms", {})
        rows.append(
            {
                "risky_pct": item.get("risky_pct", 0),
                "requests": item.get("requests", 0),
                "success_rate": item.get("success_rate", 0.0),
                "defer_rate": item.get("defer_rate", 0.0),
                "deny_rate": item.get("deny_rate", 0.0),
                "latency_avg_ms": lat.get("avg", 0.0),
                "latency_p50_ms": lat.get("p50", 0.0),
                "latency_p95_ms": lat.get("p95", 0.0),
                "latency_p99_ms": lat.get("p99", 0.0),
            }
        )
    return rows


def flatten_manifest_scale_rows(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in items:
        rows.append(
            {
                "scale": item.get("scale", 0),
                "apps": item.get("apps", 0),
                "tools": item.get("tools", 0),
                "catalog_bytes": item.get("catalog_bytes", 0),
                "load_manifests_avg_ms": item.get("load_manifests_ms", {}).get("avg", 0.0),
                "load_manifests_p95_ms": item.get("load_manifests_ms", {}).get("p95", 0.0),
                "load_tools_avg_ms": item.get("load_tools_ms", {}).get("avg", 0.0),
                "load_tools_p95_ms": item.get("load_tools_ms", {}).get("p95", 0.0),
                "render_catalog_avg_ms": item.get("render_catalog_ms", {}).get("avg", 0.0),
                "render_catalog_p95_ms": item.get("render_catalog_ms", {}).get("p95", 0.0),
            }
        )
    return rows


def flatten_approval_rows(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(item, dict):
        return []
    return [
        {
            "status": item.get("status", ""),
            "tool_id": item.get("tool_id", 0),
            "tool_name": item.get("tool_name", ""),
            "risk_tags": json.dumps(item.get("risk_tags", []), ensure_ascii=True),
            "repeats": item.get("repeats", 0),
            "defer_success_rate": item.get("defer_success_rate", 0.0),
            "deny_error_rate": item.get("deny_error_rate", 0.0),
            "session_mismatch_error_rate": item.get("session_mismatch_error_rate", 0.0),
            "defer_avg_ms": item.get("defer_latency_ms", {}).get("avg", 0.0),
            "defer_p95_ms": item.get("defer_latency_ms", {}).get("p95", 0.0),
            "deny_avg_ms": item.get("deny_latency_ms", {}).get("avg", 0.0),
            "deny_p95_ms": item.get("deny_latency_ms", {}).get("p95", 0.0),
            "sample_error": item.get("sample_error", ""),
        }
    ]


def flatten_path_rows(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        lat = item.get("latency_ms", {})
        arb = item.get("arbitration_ms", {})
        total = item.get("total_ms", {})
        rows.append(
            {
                "mode": item.get("mode", ""),
                "path": item.get("path", ""),
                "repeats": item.get("repeats", 0),
                "success_rate": item.get("success_rate", 0.0),
                "throughput_rps": item.get("throughput_rps", 0.0),
                "latency_avg_ms": lat.get("avg", 0.0),
                "latency_p50_ms": lat.get("p50", 0.0),
                "latency_p95_ms": lat.get("p95", 0.0),
                "latency_p99_ms": lat.get("p99", 0.0),
                "arbitration_avg_ms": arb.get("avg", 0.0),
                "arbitration_p95_ms": arb.get("p95", 0.0),
                "total_avg_ms": total.get("avg", 0.0),
                "total_p95_ms": total.get("p95", 0.0),
                "sample_error": item.get("sample_error", ""),
            }
        )
    return rows


def flatten_path_sample_rows(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        for sample in item.get("samples", []):
            if not isinstance(sample, dict):
                continue
            rows.append(
                {
                    "mode": item.get("mode", ""),
                    "path": item.get("path", ""),
                    "sample_idx": sample.get("sample_idx", 0),
                    "status": sample.get("status", ""),
                    "decision": sample.get("decision", ""),
                    "e2e_ms": sample.get("e2e_ms", 0.0),
                    "arbitration_ms": sample.get("arbitration_ms", 0.0),
                    "total_ms": sample.get("total_ms", 0.0),
                }
            )
    return rows


def flatten_restart_rows(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(item, dict):
        return []
    return [
        {
            "status": item.get("status", ""),
            "requests": item.get("requests", 0),
            "restart_after": item.get("restart_after", 0),
            "success_rate": item.get("success_rate", 0.0),
            "error_rate": item.get("error_rate", 0.0),
            "post_restart_error_rate": item.get("post_restart_error_rate", 0.0),
            "outage_ms": item.get("outage_ms", 0.0),
            "latency_avg_ms": item.get("latency_ms", {}).get("avg", 0.0),
            "latency_p95_ms": item.get("latency_ms", {}).get("p95", 0.0),
            "latency_p99_ms": item.get("latency_ms", {}).get("p99", 0.0),
        }
    ]


def flatten_tool_service_recovery_rows(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(item, dict):
        return []
    return [
        {
            "status": item.get("status", ""),
            "app_id": item.get("app_id", ""),
            "tool_id": item.get("tool_id", 0),
            "tool_name": item.get("tool_name", ""),
            "requests": item.get("requests", 0),
            "restart_after": item.get("restart_after", 0),
            "success_rate": item.get("success_rate", 0.0),
            "error_rate": item.get("error_rate", 0.0),
            "post_restart_error_rate": item.get("post_restart_error_rate", 0.0),
            "outage_ms": item.get("outage_ms", 0.0),
            "latency_avg_ms": item.get("latency_ms", {}).get("avg", 0.0),
            "latency_p95_ms": item.get("latency_ms", {}).get("p95", 0.0),
            "latency_p99_ms": item.get("latency_ms", {}).get("p99", 0.0),
        }
    ]


def derive_comparison_rows(
    e2e_items: Sequence[Dict[str, Any]],
    variant_items: Dict[str, Sequence[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    base: Dict[tuple[str, int], Dict[str, Any]] = {}
    for item in e2e_items:
        if not isinstance(item, dict):
            continue
        base[(str(item.get("mode", "")), int(item.get("concurrency", 0)))] = item

    rows: List[Dict[str, Any]] = []
    for conc in sorted({int(item.get("concurrency", 0)) for item in e2e_items if isinstance(item, dict)}):
        direct = base.get(("direct", conc))
        mcpd = base.get(("mcpd", conc))
        if direct is not None and mcpd is not None:
            rows.append(
                {
                    "kind": "mcpd_vs_direct",
                    "concurrency": conc,
                    "lhs": "mcpd",
                    "rhs": "direct",
                    "throughput_ratio": round(float(mcpd.get("throughput_rps", 0.0)) / max(float(direct.get("throughput_rps", 1.0)), 1e-9), 6),
                    "p95_ratio": round(float(mcpd.get("latency_ms", {}).get("p95", 0.0)) / max(float(direct.get("latency_ms", {}).get("p95", 1.0)), 1e-9), 6),
                    "p99_ratio": round(float(mcpd.get("latency_ms", {}).get("p99", 0.0)) / max(float(direct.get("latency_ms", {}).get("p99", 1.0)), 1e-9), 6),
                }
            )
    for label, items in variant_items.items():
        for item in items:
            if not isinstance(item, dict):
                continue
            conc = int(item.get("concurrency", 0))
            mcpd = base.get(("mcpd", conc))
            if mcpd is None:
                continue
            rows.append(
                {
                    "kind": "variant_vs_mcpd",
                    "concurrency": conc,
                    "lhs": label,
                    "rhs": "mcpd",
                    "throughput_ratio": round(float(item.get("throughput_rps", 0.0)) / max(float(mcpd.get("throughput_rps", 1.0)), 1e-9), 6),
                    "p95_ratio": round(float(item.get("latency_ms", {}).get("p95", 0.0)) / max(float(mcpd.get("latency_ms", {}).get("p95", 1.0)), 1e-9), 6),
                    "p99_ratio": round(float(item.get("latency_ms", {}).get("p99", 0.0)) / max(float(mcpd.get("latency_ms", {}).get("p99", 1.0)), 1e-9), 6),
                }
            )
    return rows


@contextlib.contextmanager
def managed_mcpd_variant(*, mode: str, sock_path: str, timeout_s: float) -> Iterator[None]:
    proc = launch_mcpd_variant(mode=mode, sock_path=sock_path)
    try:
        wait_mcpd_ready(sock_path, timeout_s)
        yield
    finally:
        stop_process(proc, sock_path)


def launch_mcpd_variant(*, mode: str, sock_path: str) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env["MCPD_EXPERIMENT_MODE"] = mode
    env["MCPD_SOCK_PATH"] = sock_path
    env["MCPD_TRACE_TIMING"] = "1"
    return subprocess.Popen(  # noqa: S603
        [sys.executable, "-u", "mcpd/server.py"],
        cwd=ROOT_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def wait_mcpd_ready(sock_path: str, timeout_s: float) -> None:
    deadline = time.time() + timeout_s
    last_error = ""
    while time.time() < deadline:
        time.sleep(0.1)
        try:
            resp = rpc_call(sock_path, {"sys": "list_apps"}, 1.0)
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            continue
        if resp.get("status") == "ok":
            return
        last_error = str(resp.get("error", "mcpd variant not ready"))
    raise RuntimeError(f"mcpd variant startup timed out: {last_error}")


def stop_process(proc: subprocess.Popen[str], sock_path: str) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5.0)
    Path(sock_path).unlink(missing_ok=True)


def benchmark_rpc_case(
    *,
    name: str,
    repeats: int,
    fn,
) -> Dict[str, Any]:
    durations: List[float] = []
    ok_count = 0
    errors: List[str] = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        try:
            resp = fn()
            ok = isinstance(resp, dict) and resp.get("status") == "ok"
            if ok:
                ok_count += 1
            else:
                errors.append(str(resp.get("error", "unknown error")) if isinstance(resp, dict) else "non-dict response")
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
        durations.append((time.perf_counter() - t0) * 1000.0)

    return {
        "case": name,
        "repeats": repeats,
        "ok": ok_count,
        "error": repeats - ok_count,
        "success_rate": round(ok_count / repeats, 6) if repeats else 0.0,
        "latency_ms": summarize_durations_ms(durations),
        "sample_error": errors[0] if errors else "",
    }


def run_control_plane_rpcs(*, sock_path: str, timeout_s: float, repeats: int) -> Dict[str, Any]:
    return {
        "list_apps": benchmark_rpc_case(
            name="list_apps",
            repeats=repeats,
            fn=lambda: rpc_call(sock_path, {"sys": "list_apps"}, timeout_s),
        ),
        "list_tools": benchmark_rpc_case(
            name="list_tools",
            repeats=repeats,
            fn=lambda: rpc_call(sock_path, {"sys": "list_tools"}, timeout_s),
        ),
        "open_session": benchmark_rpc_case(
            name="open_session",
            repeats=repeats,
            fn=lambda: rpc_call(
                sock_path,
                {"sys": "open_session", "client_name": "atc-bench", "ttl_ms": 60_000},
                timeout_s,
            ),
        ),
    }


def run_summaries_for_sock(
    *,
    mode_name: str,
    sock_path: str,
    tools: Sequence[ToolCase],
    requests: int,
    concurrency: Sequence[int],
    timeout_s: float,
    seed: int,
) -> List[Dict[str, Any]]:
    summaries: List[Dict[str, Any]] = []
    for conc in concurrency:
        rows = run_scenario(
            scenario_name=f"{mode_name}_c{conc}",
            mode="mcpd",
            tools=list(tools),
            concurrency=conc,
            total_requests=requests,
            mcpd_sock=sock_path,
            timeout_s=timeout_s,
            include_hash=True,
            seed=seed,
        )
        summary = summarize_rows(rows, f"{mode_name}_c{conc}")
        summary["mode"] = mode_name
        summary["concurrency"] = conc
        summaries.append(summary)
    return summaries


def choose_defer_tool(tools: Sequence[ToolCase]) -> ToolCase | None:
    for tool in tools:
        if any(tag in HIGH_RISK_TAGS for tag in tool.risk_tags):
            return tool
    return None


def choose_safe_tool(tools: Sequence[ToolCase]) -> ToolCase | None:
    for tool in tools:
        if not any(tag in HIGH_RISK_TAGS for tag in tool.risk_tags):
            return tool
    return None


def run_approval_path(
    *,
    sock_path: str,
    timeout_s: float,
    tool: ToolCase | None,
    repeats: int,
) -> Dict[str, Any]:
    if tool is None:
        return {"status": "skipped", "reason": "no high-risk tool available in manifests"}

    session_id, _agent_id = open_session(sock_path, timeout_s, "atc-approval")
    payload = dict(tool.payloads[0])
    defer_latencies: List[float] = []
    deny_latencies: List[float] = []
    session_mismatch_errors = 0
    defer_count = 0
    deny_error_count = 0
    sample_error = ""

    for idx in range(repeats):
        req_id = 10_000 + idx
        t0 = time.perf_counter()
        resp = call_tool_via_mcpd(
            tool,
            payload,
            timeout_s,
            req_id=req_id,
            mcpd_sock=sock_path,
            session_id=session_id,
            include_hash=True,
        )
        defer_latencies.append((time.perf_counter() - t0) * 1000.0)
        if resp.get("decision") == "DEFER":
            defer_count += 1
        ticket_id = resp.get("ticket_id", 0)
        if not isinstance(ticket_id, int) or ticket_id <= 0:
            sample_error = str(resp.get("error", "expected DEFER ticket"))
            continue

        bad_session_resp = rpc_call(
            sock_path,
            {
                "sys": "approval_reply",
                "session_id": "bad-session",
                "ticket_id": ticket_id,
                "decision": "deny",
                "reason": "bad session",
                "ttl_ms": 300_000,
            },
            timeout_s,
        )
        if bad_session_resp.get("status") == "error":
            session_mismatch_errors += 1

        t1 = time.perf_counter()
        deny_resp = rpc_call(
            sock_path,
            {
                "sys": "approval_reply",
                "session_id": session_id,
                "ticket_id": ticket_id,
                "decision": "deny",
                "reason": "denied in atc-eval",
                "ttl_ms": 300_000,
            },
            timeout_s,
        )
        deny_latencies.append((time.perf_counter() - t1) * 1000.0)
        if deny_resp.get("status") == "error":
            deny_error_count += 1

    return {
        "status": "ok",
        "tool_id": tool.tool_id,
        "tool_name": tool.tool_name,
        "risk_tags": list(tool.risk_tags),
        "repeats": repeats,
        "defer_success_rate": round(defer_count / repeats, 6) if repeats else 0.0,
        "deny_error_rate": round(deny_error_count / repeats, 6) if repeats else 0.0,
        "session_mismatch_error_rate": round(session_mismatch_errors / repeats, 6) if repeats else 0.0,
        "defer_latency_ms": summarize_durations_ms(defer_latencies),
        "deny_latency_ms": summarize_durations_ms(deny_latencies),
        "sample_error": sample_error,
    }


def _timing_value(resp: Dict[str, Any], key: str) -> float:
    timing = resp.get("timing_ms", {})
    if not isinstance(timing, dict):
        return 0.0
    try:
        return float(timing.get(key, 0.0))
    except Exception:
        return 0.0


def run_path_breakdown(
    *,
    sock_path: str,
    timeout_s: float,
    mode_label: str,
    safe_tool: ToolCase | None,
    risky_tool: ToolCase | None,
    repeats: int,
) -> List[Dict[str, Any]]:
    if safe_tool is None:
        return []
    cases: List[tuple[str, ToolCase, Dict[str, Any]]] = [
        ("allow", safe_tool, {"tool_hash": safe_tool.manifest_hash}),
        ("deny", safe_tool, {"tool_hash": "deadbeef"}),
    ]
    if risky_tool is not None:
        cases.append(("defer", risky_tool, {"tool_hash": risky_tool.manifest_hash}))
    details = open_session(sock_path, timeout_s, f"path-{mode_label}")
    session_id = details[0]
    rows: List[Dict[str, Any]] = []
    for path_name, tool, extra in cases:
        latencies: List[float] = []
        arbitration_latencies: List[float] = []
        total_latencies: List[float] = []
        ok_count = 0
        sample_error = ""
        samples: List[Dict[str, Any]] = []
        started = time.perf_counter()
        for idx in range(repeats):
            req = {
                "kind": "tool:exec",
                "req_id": 910000 + (1000 * len(rows)) + idx,
                "session_id": session_id,
                "app_id": tool.app_id,
                "tool_id": tool.tool_id,
                "payload": dict(tool.payloads[0]),
                "tool_hash": str(extra.get("tool_hash", tool.manifest_hash)),
            }
            t0 = time.perf_counter()
            resp = rpc_call(sock_path, req, timeout_s)
            latencies.append((time.perf_counter() - t0) * 1000.0)
            arbitration_latencies.append(_timing_value(resp, "arbitration"))
            total_latencies.append(_timing_value(resp, "total"))
            samples.append(
                {
                    "sample_idx": idx,
                    "status": str(resp.get("status", "")),
                    "decision": str(resp.get("decision", "")),
                    "e2e_ms": round(latencies[-1], 3),
                    "arbitration_ms": round(arbitration_latencies[-1], 3),
                    "total_ms": round(total_latencies[-1], 3),
                }
            )
            decision = str(resp.get("decision", ""))
            if path_name == "allow" and resp.get("status") == "ok":
                ok_count += 1
            elif path_name == "deny" and decision == "DENY":
                ok_count += 1
            elif path_name == "defer" and decision == "DEFER":
                ok_count += 1
            elif not sample_error:
                sample_error = str(resp.get("error", "unexpected path response"))
        elapsed_s = max(time.perf_counter() - started, 1e-9)
        rows.append(
            {
                "mode": mode_label,
                "path": path_name,
                "repeats": repeats,
                "success_rate": round(ok_count / repeats, 6) if repeats else 0.0,
                "throughput_rps": round(repeats / elapsed_s, 3),
                "latency_ms": summarize_durations_ms(latencies),
                "arbitration_ms": summarize_durations_ms(arbitration_latencies),
                "total_ms": summarize_durations_ms(total_latencies),
                "samples": samples,
                "sample_error": sample_error,
            }
        )
    return rows


def _trace_mixed(tools: Sequence[ToolCase], requests: int) -> List[ToolCase]:
    return [tools[idx % len(tools)] for idx in range(requests)] if tools else []


def _trace_hotspot(tools: Sequence[ToolCase], requests: int) -> List[ToolCase]:
    if not tools:
        return []
    hot = tools[0]
    cold = list(tools[1:]) or [hot]
    trace: List[ToolCase] = []
    for idx in range(requests):
        if idx % 10 < 8:
            trace.append(hot)
        else:
            trace.append(cold[idx % len(cold)])
    return trace


def run_trace_workload(
    *,
    label: str,
    mode: str,
    mode_label: str,
    trace: Sequence[ToolCase],
    sock_path: str,
    timeout_s: float,
) -> Dict[str, Any]:
    latencies: List[float] = []
    ok_count = 0
    session_id = ""
    if mode == "mcpd":
        session_id, _agent_id = open_session(sock_path, timeout_s, f"trace-{label}")
    for idx, tool in enumerate(trace):
        payload = dict(tool.payloads[0])
        t0 = time.perf_counter()
        if mode == "direct":
            resp = call_tool_direct(tool, payload, timeout_s, idx + 1)
        else:
            resp = call_tool_via_mcpd(
                tool,
                payload,
                timeout_s,
                idx + 1,
                mcpd_sock=sock_path,
                session_id=session_id,
                include_hash=True,
            )
        latencies.append((time.perf_counter() - t0) * 1000.0)
        if resp.get("status") == "ok":
            ok_count += 1
    return {
        "label": label,
        "mode": mode_label,
        "requests": len(trace),
        "success_rate": round(ok_count / len(trace), 6) if trace else 0.0,
        "latency_ms": summarize_durations_ms(latencies),
    }


def run_policy_mix(
    *,
    sock_path: str,
    timeout_s: float,
    safe_tool: ToolCase | None,
    risky_tool: ToolCase | None,
    requests: int,
) -> List[Dict[str, Any]]:
    if safe_tool is None or risky_tool is None:
        return []
    mixes = (0, 25, 50, 75, 100)
    results: List[Dict[str, Any]] = []
    for risky_pct in mixes:
        session_id, _agent_id = open_session(sock_path, timeout_s, f"policy-mix-{risky_pct}")
        latencies: List[float] = []
        ok_count = 0
        defer_count = 0
        deny_count = 0
        for idx in range(requests):
            tool = risky_tool if ((idx * 100) // max(requests, 1)) < risky_pct else safe_tool
            payload = dict(tool.payloads[0])
            t0 = time.perf_counter()
            resp = call_tool_via_mcpd(
                tool,
                payload,
                timeout_s,
                idx + 1,
                mcpd_sock=sock_path,
                session_id=session_id,
                include_hash=True,
            )
            latencies.append((time.perf_counter() - t0) * 1000.0)
            if resp.get("status") == "ok":
                ok_count += 1
            decision = str(resp.get("decision", ""))
            if decision == "DEFER":
                defer_count += 1
            if decision == "DENY":
                deny_count += 1
        results.append(
            {
                "risky_pct": risky_pct,
                "requests": requests,
                "success_rate": round(ok_count / requests, 6) if requests else 0.0,
                "defer_rate": round(defer_count / requests, 6) if requests else 0.0,
                "deny_rate": round(deny_count / requests, 6) if requests else 0.0,
                "latency_ms": summarize_durations_ms(latencies),
            }
        )
    return results


def run_mcpd_restart_recovery(
    *,
    tool: ToolCase,
    timeout_s: float,
    requests: int,
    restart_after: int,
) -> Dict[str, Any]:
    sock_path = "/tmp/mcpd-restart-recovery.sock"
    proc = launch_mcpd_variant(mode="normal", sock_path=sock_path)
    try:
        wait_mcpd_ready(sock_path, max(10.0, timeout_s))
        latencies: List[float] = []
        ok_count = 0
        error_count = 0
        recovery_errors = 0
        outage_start: float | None = None
        outage_end: float | None = None
        session_id, _agent_id = open_session(sock_path, timeout_s, "restart-recovery")
        payload = dict(tool.payloads[0])

        for idx in range(requests):
            if idx == restart_after:
                stop_process(proc, sock_path)
                proc = launch_mcpd_variant(mode="normal", sock_path=sock_path)
                outage_start = time.time()
                wait_mcpd_ready(sock_path, max(10.0, timeout_s))
                session_id, _agent_id = open_session(sock_path, timeout_s, "restart-recovery")
            t0 = time.perf_counter()
            try:
                resp = call_tool_via_mcpd(
                    tool,
                    payload,
                    timeout_s,
                    idx + 1,
                    mcpd_sock=sock_path,
                    session_id=session_id,
                    include_hash=True,
                )
            except Exception as exc:  # noqa: BLE001
                resp = {"status": "error", "error": str(exc)}
            latencies.append((time.perf_counter() - t0) * 1000.0)
            if resp.get("status") == "ok":
                ok_count += 1
                if outage_start is not None and outage_end is None:
                    outage_end = time.time()
                continue
            error_count += 1
            if idx >= restart_after:
                recovery_errors += 1
            wait_mcpd_ready(sock_path, max(10.0, timeout_s))
            session_id, _agent_id = open_session(sock_path, timeout_s, "restart-recovery")

        outage_ms = 0.0
        if outage_start is not None and outage_end is not None:
            outage_ms = max(0.0, (outage_end - outage_start) * 1000.0)
        return {
            "status": "ok",
            "requests": requests,
            "restart_after": restart_after,
            "success_rate": round(ok_count / requests, 6) if requests else 0.0,
            "error_rate": round(error_count / requests, 6) if requests else 0.0,
            "post_restart_error_rate": round(recovery_errors / max(requests - restart_after, 1), 6),
            "outage_ms": round(outage_ms, 3),
            "latency_ms": summarize_durations_ms(latencies),
        }
    finally:
        stop_process(proc, sock_path)


def clone_manifest_tree(scale: int, out_dir: Path) -> Dict[str, int]:
    manifest_paths = sorted((ROOT_DIR / "tool-app" / "manifests").glob("*.json"))
    next_tool_id = scale * 10_000
    app_count = 0
    tool_count = 0
    for replica in range(scale):
        for src_path in manifest_paths:
            raw = json.loads(src_path.read_text(encoding="utf-8"))
            app_suffix = f"_x{replica}"
            raw["app_id"] = f"{raw['app_id']}{app_suffix}"
            raw["app_name"] = f"{raw['app_name']} x{replica}"
            tools = raw.get("tools", [])
            for tool in tools:
                tool["tool_id"] = next_tool_id
                next_tool_id += 1
                tool_count += 1
            app_count += 1
            dst_path = out_dir / f"{src_path.stem}-x{replica}.json"
            dst_path.write_text(json.dumps(raw, ensure_ascii=True, indent=2), encoding="utf-8")
    return {"app_count": app_count, "tool_count": tool_count}


def run_manifest_scale(*, scales: Sequence[int], repeats: int) -> List[Dict[str, Any]]:
    import sys

    sys.path.insert(0, str(ROOT_DIR))
    from mcpd.manifest_loader import load_all_manifests, load_all_tools
    from mcpd.public_catalog import list_tools_public

    results: List[Dict[str, Any]] = []
    for scale in scales:
        load_manifest_lat: List[float] = []
        load_tool_lat: List[float] = []
        render_catalog_lat: List[float] = []
        app_count = 0
        tool_count = 0
        payload_bytes = 0
        with tempfile.TemporaryDirectory(prefix=f"linux-mcp-scale-{scale}-") as tmp:
            manifest_dir = Path(tmp)
            counts = clone_manifest_tree(scale, manifest_dir)
            app_count = counts["app_count"]
            tool_count = counts["tool_count"]
            for _ in range(repeats):
                t0 = time.perf_counter()
                apps = load_all_manifests(manifest_dir)
                load_manifest_lat.append((time.perf_counter() - t0) * 1000.0)

                t1 = time.perf_counter()
                tools = load_all_tools(manifest_dir)
                load_tool_lat.append((time.perf_counter() - t1) * 1000.0)

                t2 = time.perf_counter()
                catalog = list_tools_public(tools)
                render_catalog_lat.append((time.perf_counter() - t2) * 1000.0)
                payload_bytes = len(
                    json.dumps(catalog, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
                )
                if len(apps) != app_count or len(tools) != tool_count:
                    raise RuntimeError("synthetic manifest scale produced inconsistent counts")

        results.append(
            {
                "scale": scale,
                "apps": app_count,
                "tools": tool_count,
                "catalog_bytes": payload_bytes,
                "load_manifests_ms": summarize_durations_ms(load_manifest_lat),
                "load_tools_ms": summarize_durations_ms(load_tool_lat),
                "render_catalog_ms": summarize_durations_ms(render_catalog_lat),
            }
        )
    return results


def maybe_run_reload_10x(timeout_s: float) -> Dict[str, Any]:
    script = ROOT_DIR / "scripts" / "reload_10x.sh"
    if os.geteuid() != 0:
        return {"status": "skipped", "reason": "reload_10x requires root"}
    t0 = time.perf_counter()
    proc = subprocess.run(  # noqa: S603
        ["bash", str(script)],
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
        timeout=timeout_s,
        check=False,
    )
    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "returncode": proc.returncode,
        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "stdout_tail": "\n".join(proc.stdout.strip().splitlines()[-10:]),
        "stderr_tail": "\n".join(proc.stderr.strip().splitlines()[-10:]),
    }


def _load_app_manifest(app_id: str) -> tuple[Path, Dict[str, Any]]:
    for manifest_path in sorted((ROOT_DIR / "tool-app" / "manifests").glob("*.json")):
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        if raw.get("app_id") == app_id:
            if not isinstance(raw, dict):
                break
            return (manifest_path, raw)
    raise RuntimeError(f"manifest not found for app_id={app_id}")


def _app_pidfile(app_id: str) -> Path:
    return Path(f"/tmp/linux-mcp-app-{app_id}.pid")


def _stop_app_service(app_id: str, endpoint: str) -> None:
    pidfile = _app_pidfile(app_id)
    pid_text = pidfile.read_text(encoding="utf-8").strip() if pidfile.exists() else ""
    if pid_text:
        try:
            os.kill(int(pid_text), 15)
        except Exception:  # noqa: BLE001
            pass
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                os.kill(int(pid_text), 0)
                time.sleep(0.05)
            except OSError:
                break
        try:
            os.kill(int(pid_text), 9)
        except Exception:  # noqa: BLE001
            pass
    pidfile.unlink(missing_ok=True)
    Path(endpoint).unlink(missing_ok=True)


def _start_app_service(app_id: str, timeout_s: float) -> None:
    manifest_path, manifest = _load_app_manifest(app_id)
    demo_entrypoint = str(manifest.get("demo_entrypoint", ""))
    endpoint = str(manifest.get("endpoint", ""))
    if not demo_entrypoint or not endpoint:
        raise RuntimeError(f"manifest missing demo_entrypoint/endpoint for app_id={app_id}")
    service_file = ROOT_DIR / demo_entrypoint
    if not service_file.exists():
        raise RuntimeError(f"missing service file: {service_file}")
    Path(endpoint).unlink(missing_ok=True)
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, "-u", str(service_file), "--manifest", str(manifest_path)],
        cwd=ROOT_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    _app_pidfile(app_id).write_text(str(proc.pid), encoding="utf-8")
    deadline = time.time() + max(5.0, timeout_s)
    while time.time() < deadline:
        if Path(endpoint).exists():
            return
        time.sleep(0.05)
    raise RuntimeError(f"service restart timed out for app_id={app_id}")


def run_tool_service_restart_recovery(
    *,
    tool: ToolCase,
    timeout_s: float,
    requests: int,
    restart_after: int,
    mcpd_sock: str,
) -> Dict[str, Any]:
    _manifest_path, manifest = _load_app_manifest(tool.app_id)
    endpoint = str(manifest.get("endpoint", ""))
    latencies: List[float] = []
    ok_count = 0
    error_count = 0
    post_restart_errors = 0
    outage_start: float | None = None
    outage_end: float | None = None
    session_id, _agent_id = open_session(mcpd_sock, timeout_s, "tool-restart-recovery")
    payload = dict(tool.payloads[0])

    for idx in range(requests):
        if idx == restart_after:
            outage_start = time.time()
            _stop_app_service(tool.app_id, endpoint)
            _start_app_service(tool.app_id, timeout_s)
        t0 = time.perf_counter()
        try:
            resp = call_tool_via_mcpd(
                tool,
                payload,
                timeout_s,
                idx + 1,
                mcpd_sock=mcpd_sock,
                session_id=session_id,
                include_hash=True,
            )
        except Exception as exc:  # noqa: BLE001
            resp = {"status": "error", "error": str(exc)}
        latencies.append((time.perf_counter() - t0) * 1000.0)
        if resp.get("status") == "ok":
            ok_count += 1
            if outage_start is not None and outage_end is None:
                outage_end = time.time()
        else:
            error_count += 1
            if idx >= restart_after:
                post_restart_errors += 1

    outage_ms = 0.0
    if outage_start is not None and outage_end is not None:
        outage_ms = max(0.0, (outage_end - outage_start) * 1000.0)
    return {
        "status": "ok",
        "app_id": tool.app_id,
        "tool_id": tool.tool_id,
        "tool_name": tool.tool_name,
        "requests": requests,
        "restart_after": restart_after,
        "success_rate": round(ok_count / requests, 6) if requests else 0.0,
        "error_rate": round(error_count / requests, 6) if requests else 0.0,
        "post_restart_error_rate": round(post_restart_errors / max(requests - restart_after, 1), 6),
        "outage_ms": round(outage_ms, 3),
        "latency_ms": summarize_durations_ms(latencies),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ATC-style evaluation for linux-mcp")
    parser.add_argument("--mcpd-sock", default=DEFAULT_MCPD_SOCK)
    parser.add_argument("--timeout-s", type=float, default=10.0)
    parser.add_argument("--output-dir", type=str, default="experiment-results/atc")
    parser.add_argument("--requests", type=int, default=4000)
    parser.add_argument("--concurrency", type=str, default="1,4,8,16,32")
    parser.add_argument("--negative-repeats", type=int, default=500)
    parser.add_argument("--approval-repeats", type=int, default=100)
    parser.add_argument("--rpc-repeats", type=int, default=300)
    parser.add_argument("--scale-repeats", type=int, default=10)
    parser.add_argument("--manifest-scales", type=str, default="1,2,4,8")
    parser.add_argument("--trace-requests", type=int, default=1000)
    parser.add_argument("--policy-requests", type=int, default=1000)
    parser.add_argument("--restart-requests", type=int, default=1000)
    parser.add_argument("--restart-after", type=int, default=300)
    parser.add_argument("--tool-restart-requests", type=int, default=1000)
    parser.add_argument("--tool-restart-after", type=int, default=300)
    parser.add_argument("--max-tools", type=int, default=20)
    parser.add_argument("--include-write-tools", action="store_true")
    parser.add_argument("--skip-direct", action="store_true")
    parser.add_argument("--skip-reload-10x", action="store_true")
    parser.add_argument("--seed", type=int, default=20260403)
    args = parser.parse_args()

    out_root = Path(args.output_dir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    run_ts = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    run_dir = out_root / f"run-{run_ts}"
    run_dir.mkdir(parents=True, exist_ok=True)

    ensure_prerequisites(args.mcpd_sock, args.timeout_s)
    tools = enrich_hash_from_mcpd(load_manifest_tools(), args.mcpd_sock, args.timeout_s)
    selected = preflight_tools(
        tools,
        mcpd_sock=args.mcpd_sock,
        timeout_s=args.timeout_s,
        include_write=args.include_write_tools,
        max_tools=args.max_tools,
    )
    if not selected:
        raise RuntimeError("no tools passed preflight")

    conc_list = parse_concurrency(args.concurrency)
    summaries: List[Dict[str, Any]] = []
    if not args.skip_direct:
        for conc in conc_list:
            rows = run_scenario(
                scenario_name=f"direct_c{conc}",
                mode="direct",
                tools=selected,
                concurrency=conc,
                total_requests=args.requests,
                mcpd_sock=args.mcpd_sock,
                timeout_s=args.timeout_s,
                include_hash=True,
                seed=args.seed,
            )
            summary = summarize_rows(rows, f"direct_c{conc}")
            summary["mode"] = "direct"
            summary["concurrency"] = conc
            summaries.append(summary)
    for conc in conc_list:
        rows = run_scenario(
            scenario_name=f"mcpd_c{conc}",
            mode="mcpd",
            tools=selected,
            concurrency=conc,
            total_requests=args.requests,
            mcpd_sock=args.mcpd_sock,
            timeout_s=args.timeout_s,
            include_hash=True,
            seed=args.seed,
        )
        summary = summarize_rows(rows, f"mcpd_c{conc}")
        summary["mode"] = "mcpd"
        summary["concurrency"] = conc
        summaries.append(summary)

    variant_summaries: Dict[str, List[Dict[str, Any]]] = {}
    variant_socks = {
        "forwarder_only": "/tmp/mcpd-forwarder-only.sock",
        "userspace_semantic_plane": "/tmp/mcpd-userspace-semantic.sock",
    }
    variant_modes = {
        "forwarder_only": "forwarder_only",
        "userspace_semantic_plane": "userspace_semantic_plane",
    }
    for label, experiment_mode in variant_modes.items():
        with managed_mcpd_variant(mode=experiment_mode, sock_path=variant_socks[label], timeout_s=max(10.0, args.timeout_s)) as _:
            variant_summaries[label] = run_summaries_for_sock(
                mode_name=label,
                sock_path=variant_socks[label],
                tools=selected,
                requests=args.requests,
                concurrency=conc_list,
                timeout_s=args.timeout_s,
                seed=args.seed,
            )

    traces = {
        "mixed": _trace_mixed(selected, args.trace_requests),
        "hotspot": _trace_hotspot(selected, args.trace_requests),
    }
    trace_results: List[Dict[str, Any]] = []
    if not args.skip_direct:
        for label, trace in traces.items():
            trace_results.append(
                run_trace_workload(
                    label=label,
                    mode="direct",
                    mode_label="direct",
                    trace=trace,
                    sock_path=args.mcpd_sock,
                    timeout_s=args.timeout_s,
                )
            )
    for label, trace in traces.items():
        trace_results.append(
            run_trace_workload(
                label=label,
                mode="mcpd",
                mode_label="mcpd",
                trace=trace,
                sock_path=args.mcpd_sock,
                timeout_s=args.timeout_s,
            )
        )
        for variant_label, experiment_mode in variant_modes.items():
            with managed_mcpd_variant(
                mode=experiment_mode,
                sock_path=variant_socks[variant_label],
                timeout_s=max(10.0, args.timeout_s),
            ) as _:
                trace_results.append(
                    run_trace_workload(
                        label=label,
                        mode="mcpd",
                        mode_label=variant_label,
                        trace=trace,
                        sock_path=variant_socks[variant_label],
                        timeout_s=args.timeout_s,
                    )
                )

    policy_mix = run_policy_mix(
        sock_path=args.mcpd_sock,
        timeout_s=args.timeout_s,
        safe_tool=choose_safe_tool(selected),
        risky_tool=choose_defer_tool(tools),
        requests=args.policy_requests,
    )
    restart_recovery = run_mcpd_restart_recovery(
        tool=selected[0],
        timeout_s=args.timeout_s,
        requests=args.restart_requests,
        restart_after=min(args.restart_after, max(args.restart_requests - 1, 0)),
    )
    tool_service_recovery = run_tool_service_restart_recovery(
        tool=choose_safe_tool(selected) or selected[0],
        timeout_s=args.timeout_s,
        requests=args.tool_restart_requests,
        restart_after=min(args.tool_restart_after, max(args.tool_restart_requests - 1, 0)),
        mcpd_sock=args.mcpd_sock,
    )

    negative = run_negative_controls(
        tool=selected[0],
        mcpd_sock=args.mcpd_sock,
        timeout_s=args.timeout_s,
        repeats=args.negative_repeats,
    )
    approval = run_approval_path(
        sock_path=args.mcpd_sock,
        timeout_s=args.timeout_s,
        tool=choose_defer_tool(tools),
        repeats=args.approval_repeats,
    )
    control_plane = run_control_plane_rpcs(
        sock_path=args.mcpd_sock,
        timeout_s=args.timeout_s,
        repeats=args.rpc_repeats,
    )
    path_breakdown = run_path_breakdown(
        sock_path=args.mcpd_sock,
        timeout_s=args.timeout_s,
        mode_label="mcpd",
        safe_tool=choose_safe_tool(selected) or selected[0],
        risky_tool=choose_defer_tool(tools),
        repeats=max(20, min(args.rpc_repeats, 200)),
    )
    with managed_mcpd_variant(
        mode="userspace_semantic_plane",
        sock_path=variant_socks["userspace_semantic_plane"],
        timeout_s=max(10.0, args.timeout_s),
    ) as _:
        path_breakdown.extend(
            run_path_breakdown(
                sock_path=variant_socks["userspace_semantic_plane"],
                timeout_s=args.timeout_s,
                mode_label="userspace_semantic_plane",
                safe_tool=choose_safe_tool(selected) or selected[0],
                risky_tool=choose_defer_tool(tools),
                repeats=max(20, min(args.rpc_repeats, 200)),
            )
        )
    scale_results = run_manifest_scale(
        scales=parse_concurrency(args.manifest_scales),
        repeats=args.scale_repeats,
    )
    reload_result = {"status": "skipped", "reason": "disabled by flag"}
    if not args.skip_reload_10x:
        reload_result = maybe_run_reload_10x(max(30.0, args.timeout_s * 10.0))

    result = {
        "meta": {
            "run_ts": run_ts,
            "requests_per_scenario": args.requests,
            "concurrency": conc_list,
            "negative_repeats": args.negative_repeats,
            "approval_repeats": args.approval_repeats,
            "rpc_repeats": args.rpc_repeats,
            "trace_requests": args.trace_requests,
            "policy_requests": args.policy_requests,
            "restart_requests": args.restart_requests,
            "restart_after": args.restart_after,
            "tool_restart_requests": args.tool_restart_requests,
            "tool_restart_after": args.tool_restart_after,
            "manifest_scales": parse_concurrency(args.manifest_scales),
            "selected_tools": [
                {
                    "tool_id": tool.tool_id,
                    "tool_name": tool.tool_name,
                    "app_id": tool.app_id,
                    "risk_tags": list(tool.risk_tags),
                }
                for tool in selected
            ],
        },
        "e2e_summaries": summaries,
        "variant_summaries": variant_summaries,
        "trace_results": trace_results,
        "policy_mix": policy_mix,
        "restart_recovery": restart_recovery,
        "tool_service_recovery": tool_service_recovery,
        "negative_controls": negative,
        "approval_path": approval,
        "control_plane_rpcs": control_plane,
        "path_breakdown": path_breakdown,
        "manifest_scale": scale_results,
        "reload_10x": reload_result,
    }

    (run_dir / "atc_summary.json").write_text(
        json.dumps(result, ensure_ascii=True, indent=2),
        encoding="utf-8",
    )
    write_csv(
        run_dir / "e2e_summaries.csv",
        flatten_summary_rows(result["e2e_summaries"]),
        [
            "scenario",
            "mode",
            "concurrency",
            "requests",
            "ok",
            "error",
            "success_rate",
            "throughput_rps",
            "latency_avg_ms",
            "latency_p50_ms",
            "latency_p95_ms",
            "latency_p99_ms",
        ],
    )
    variant_rows: List[Dict[str, Any]] = []
    for items in result["variant_summaries"].values():
        variant_rows.extend(flatten_summary_rows(items))
    write_csv(
        run_dir / "variant_summaries.csv",
        variant_rows,
        [
            "scenario",
            "mode",
            "concurrency",
            "requests",
            "ok",
            "error",
            "success_rate",
            "throughput_rps",
            "latency_avg_ms",
            "latency_p50_ms",
            "latency_p95_ms",
            "latency_p99_ms",
        ],
    )
    write_csv(
        run_dir / "trace_results.csv",
        flatten_trace_rows(result["trace_results"]),
        [
            "label",
            "mode",
            "requests",
            "success_rate",
            "latency_avg_ms",
            "latency_p50_ms",
            "latency_p95_ms",
            "latency_p99_ms",
        ],
    )
    write_csv(
        run_dir / "policy_mix.csv",
        flatten_policy_mix_rows(result["policy_mix"]),
        [
            "risky_pct",
            "requests",
            "success_rate",
            "defer_rate",
            "deny_rate",
            "latency_avg_ms",
            "latency_p50_ms",
            "latency_p95_ms",
            "latency_p99_ms",
        ],
    )
    write_csv(
        run_dir / "control_plane_rpcs.csv",
        flatten_control_plane_rows(result["control_plane_rpcs"]),
        [
            "rpc",
            "repeats",
            "ok",
            "error",
            "success_rate",
            "sample_error",
            "latency_avg_ms",
            "latency_p50_ms",
            "latency_p95_ms",
            "latency_p99_ms",
        ],
    )
    write_csv(
        run_dir / "negative_controls.csv",
        flatten_negative_rows(result["negative_controls"]),
        [
            "case",
            "repeats",
            "error_rate",
            "deny_rate",
            "defer_rate",
            "latency_avg_ms",
            "latency_p95_ms",
        ],
    )
    write_csv(
        run_dir / "path_breakdown.csv",
        flatten_path_rows(result["path_breakdown"]),
        [
            "mode",
            "path",
            "repeats",
            "success_rate",
            "throughput_rps",
            "latency_avg_ms",
            "latency_p50_ms",
            "latency_p95_ms",
            "latency_p99_ms",
            "arbitration_avg_ms",
            "arbitration_p95_ms",
            "total_avg_ms",
            "total_p95_ms",
            "sample_error",
        ],
    )
    write_csv(
        run_dir / "path_breakdown_raw.csv",
        flatten_path_sample_rows(result["path_breakdown"]),
        [
            "mode",
            "path",
            "sample_idx",
            "status",
            "decision",
            "e2e_ms",
            "arbitration_ms",
            "total_ms",
        ],
    )
    write_csv(
        run_dir / "manifest_scale.csv",
        flatten_manifest_scale_rows(result["manifest_scale"]),
        [
            "scale",
            "apps",
            "tools",
            "catalog_bytes",
            "load_manifests_avg_ms",
            "load_manifests_p95_ms",
            "load_tools_avg_ms",
            "load_tools_p95_ms",
            "render_catalog_avg_ms",
            "render_catalog_p95_ms",
        ],
    )
    write_csv(
        run_dir / "approval_path.csv",
        flatten_approval_rows(result["approval_path"]),
        [
            "status",
            "tool_id",
            "tool_name",
            "risk_tags",
            "repeats",
            "defer_success_rate",
            "deny_error_rate",
            "session_mismatch_error_rate",
            "defer_avg_ms",
            "defer_p95_ms",
            "deny_avg_ms",
            "deny_p95_ms",
            "sample_error",
        ],
    )
    write_csv(
        run_dir / "restart_recovery.csv",
        flatten_restart_rows(result["restart_recovery"]),
        [
            "status",
            "requests",
            "restart_after",
            "success_rate",
            "error_rate",
            "post_restart_error_rate",
            "outage_ms",
            "latency_avg_ms",
            "latency_p95_ms",
            "latency_p99_ms",
        ],
    )
    write_csv(
        run_dir / "tool_service_recovery.csv",
        flatten_tool_service_recovery_rows(result["tool_service_recovery"]),
        [
            "status",
            "app_id",
            "tool_id",
            "tool_name",
            "requests",
            "restart_after",
            "success_rate",
            "error_rate",
            "post_restart_error_rate",
            "outage_ms",
            "latency_avg_ms",
            "latency_p95_ms",
            "latency_p99_ms",
        ],
    )
    write_csv(
        run_dir / "derived_metrics.csv",
        derive_comparison_rows(result["e2e_summaries"], result["variant_summaries"]),
        [
            "kind",
            "concurrency",
            "lhs",
            "rhs",
            "throughput_ratio",
            "p95_ratio",
            "p99_ratio",
        ],
    )
    write_csv(
        run_dir / "selected_tools.csv",
        list(result["meta"].get("selected_tools", [])),
        [
            "tool_id",
            "tool_name",
            "app_id",
            "risk_tags",
        ],
    )
    print(f"[done] atc_result_dir={run_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
