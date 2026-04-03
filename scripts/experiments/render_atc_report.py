#!/usr/bin/env python3
"""Render an ATC-oriented markdown report from atc_summary.json."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def fmt_ms(value: Any) -> str:
    try:
        return f"{float(value):.2f}"
    except Exception:
        return "0.00"


def fmt_pct(value: Any) -> str:
    try:
        return f"{float(value) * 100:.2f}%"
    except Exception:
        return "0.00%"


def load_summary(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def render_e2e_table(items: List[Dict[str, Any]]) -> List[str]:
    lines = [
        "| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in items:
        lat = item.get("latency_ms", {})
        lines.append(
            f"| {item.get('scenario','')} | {item.get('mode','')} | {item.get('concurrency',0)} | "
            f"{item.get('requests',0)} | {fmt_pct(item.get('success_rate', 0.0))} | {item.get('throughput_rps',0)} | "
            f"{fmt_ms(lat.get('p50', 0))} | {fmt_ms(lat.get('p95', 0))} | {fmt_ms(lat.get('p99', 0))} |"
        )
    return lines


def render_report(data: Dict[str, Any]) -> str:
    meta = data.get("meta", {})
    e2e = [item for item in data.get("e2e_summaries", []) if isinstance(item, dict)]
    variants = data.get("variant_summaries", {})
    traces = [item for item in data.get("trace_results", []) if isinstance(item, dict)]
    policy_mix = [item for item in data.get("policy_mix", []) if isinstance(item, dict)]
    restart_recovery = data.get("restart_recovery", {})
    negative = data.get("negative_controls", {})
    approval = data.get("approval_path", {})
    control = data.get("control_plane_rpcs", {})
    scale = data.get("manifest_scale", [])
    reload_result = data.get("reload_10x", {})

    lines: List[str] = []
    lines.append("# linux-mcp ATC Evaluation Report")
    lines.append("")
    lines.append("## Run Meta")
    lines.append("")
    lines.append(f"- run_ts: {meta.get('run_ts', '')}")
    lines.append(f"- requests_per_scenario: {meta.get('requests_per_scenario', 0)}")
    lines.append(f"- concurrency: {meta.get('concurrency', [])}")
    lines.append(f"- selected_tools: {len(meta.get('selected_tools', []))}")
    lines.append("")

    lines.append("## E2E Overhead")
    lines.append("")
    lines.extend(render_e2e_table(e2e))
    lines.append("")

    lines.append("## Ablation")
    lines.append("")
    for name, items in variants.items():
        scenario_items = [item for item in items if isinstance(item, dict)]
        lines.append(f"### {name}")
        lines.append("")
        lines.extend(render_e2e_table(scenario_items))
        lines.append("")
    if variants:
        lines.append("These variants are intended to separate pure forwarding cost from semantically equivalent userspace control-plane cost.")
        lines.append("")

    lines.append("## Trace Workloads")
    lines.append("")
    lines.append("| trace | mode | requests | success_rate | avg_ms | p95_ms | p99_ms |")
    lines.append("|---|---|---:|---:|---:|---:|---:|")
    for item in traces:
        lat = item.get("latency_ms", {})
        lines.append(
            f"| {item.get('label','')} | {item.get('mode','')} | {item.get('requests',0)} | "
            f"{fmt_pct(item.get('success_rate', 0.0))} | {fmt_ms(lat.get('avg', 0))} | "
            f"{fmt_ms(lat.get('p95', 0))} | {fmt_ms(lat.get('p99', 0))} |"
        )
    lines.append("")

    lines.append("## Policy Mix")
    lines.append("")
    lines.append("| risky_pct | requests | success_rate | defer_rate | deny_rate | avg_ms | p95_ms | p99_ms |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for item in policy_mix:
        lat = item.get("latency_ms", {})
        lines.append(
            f"| {item.get('risky_pct',0)} | {item.get('requests',0)} | {fmt_pct(item.get('success_rate', 0.0))} | "
            f"{fmt_pct(item.get('defer_rate', 0.0))} | {fmt_pct(item.get('deny_rate', 0.0))} | "
            f"{fmt_ms(lat.get('avg', 0))} | {fmt_ms(lat.get('p95', 0))} | {fmt_ms(lat.get('p99', 0))} |"
        )
    lines.append("")

    lines.append("## Restart Recovery")
    lines.append("")
    lines.append(f"- status: {restart_recovery.get('status', '')}")
    if restart_recovery.get("status") == "ok":
        lat = restart_recovery.get("latency_ms", {})
        lines.append(f"- requests: {restart_recovery.get('requests', 0)}")
        lines.append(f"- restart_after: {restart_recovery.get('restart_after', 0)}")
        lines.append(f"- success_rate: {fmt_pct(restart_recovery.get('success_rate', 0.0))}")
        lines.append(f"- error_rate: {fmt_pct(restart_recovery.get('error_rate', 0.0))}")
        lines.append(f"- post_restart_error_rate: {fmt_pct(restart_recovery.get('post_restart_error_rate', 0.0))}")
        lines.append(f"- outage_ms: {fmt_ms(restart_recovery.get('outage_ms', 0))}")
        lines.append(f"- p95_ms: {fmt_ms(lat.get('p95', 0))}")
    lines.append("")

    lines.append("## Control-Plane RPCs")
    lines.append("")
    lines.append("| rpc | repeats | success_rate | avg_ms | p95_ms | sample_error |")
    lines.append("|---|---:|---:|---:|---:|---|")
    for name, item in control.items():
        if not isinstance(item, dict):
            continue
        lat = item.get("latency_ms", {})
        lines.append(
            f"| {name} | {item.get('repeats', 0)} | {fmt_pct(item.get('success_rate', 0.0))} | "
            f"{fmt_ms(lat.get('avg', 0))} | {fmt_ms(lat.get('p95', 0))} | {item.get('sample_error', '')} |"
        )
    lines.append("")

    lines.append("## Safety Controls")
    lines.append("")
    lines.append("| case | repeats | error_rate | deny_rate | defer_rate | avg_ms | p95_ms |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for case_name, item in negative.items():
        if not isinstance(item, dict):
            continue
        lines.append(
            f"| {case_name} | {item.get('repeats', 0)} | {fmt_pct(item.get('error_rate', 0.0))} | "
            f"{fmt_pct(item.get('deny_rate', 0.0))} | {fmt_pct(item.get('defer_rate', 0.0))} | "
            f"{fmt_ms(item.get('latency_ms_avg', 0))} | {fmt_ms(item.get('latency_ms_p95', 0))} |"
        )
    lines.append("")

    lines.append("## Approval Path")
    lines.append("")
    if approval.get("status") == "ok":
        defer_lat = approval.get("defer_latency_ms", {})
        deny_lat = approval.get("deny_latency_ms", {})
        lines.append(f"- tool: {approval.get('tool_name', '')} ({approval.get('tool_id', 0)})")
        lines.append(f"- risk_tags: {approval.get('risk_tags', [])}")
        lines.append(f"- defer_success_rate: {fmt_pct(approval.get('defer_success_rate', 0.0))}")
        lines.append(f"- deny_error_rate: {fmt_pct(approval.get('deny_error_rate', 0.0))}")
        lines.append(f"- session_mismatch_error_rate: {fmt_pct(approval.get('session_mismatch_error_rate', 0.0))}")
        lines.append(f"- defer_p95_ms: {fmt_ms(defer_lat.get('p95', 0))}")
        lines.append(f"- deny_p95_ms: {fmt_ms(deny_lat.get('p95', 0))}")
    else:
        lines.append(f"- skipped: {approval.get('reason', 'unknown reason')}")
    lines.append("")

    lines.append("## Manifest Scale")
    lines.append("")
    lines.append("| scale | apps | tools | catalog_bytes | load_manifests_p95_ms | load_tools_p95_ms | render_catalog_p95_ms |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for item in scale:
        if not isinstance(item, dict):
            continue
        lines.append(
            f"| {item.get('scale', 0)} | {item.get('apps', 0)} | {item.get('tools', 0)} | {item.get('catalog_bytes', 0)} | "
            f"{fmt_ms(item.get('load_manifests_ms', {}).get('p95', 0))} | "
            f"{fmt_ms(item.get('load_tools_ms', {}).get('p95', 0))} | "
            f"{fmt_ms(item.get('render_catalog_ms', {}).get('p95', 0))} |"
        )
    lines.append("")

    lines.append("## Reload Stability")
    lines.append("")
    lines.append(f"- status: {reload_result.get('status', '')}")
    if reload_result.get("status") == "ok":
        lines.append(f"- elapsed_ms: {fmt_ms(reload_result.get('elapsed_ms', 0))}")
        lines.append("```text")
        lines.append(str(reload_result.get("stdout_tail", "")))
        lines.append("```")
    else:
        lines.append(f"- reason: {reload_result.get('reason', reload_result.get('stderr_tail', ''))}")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render markdown from atc_summary.json")
    parser.add_argument("summary_json", type=str)
    parser.add_argument("--output", type=str, default="")
    args = parser.parse_args()

    report = render_report(load_summary(Path(args.summary_json)))
    if args.output:
        out_path = Path(args.output)
        out_path.write_text(report, encoding="utf-8")
        print(f"report written: {out_path}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
