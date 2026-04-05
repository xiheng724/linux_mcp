#!/usr/bin/env python3
"""Render a markdown report from linux_mcp_summary.json."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def render(summary: Dict[str, Any]) -> str:
    precomputed = summary.get("report_markdown")
    if isinstance(precomputed, str) and precomputed.strip():
        return precomputed
    latency_rows = summary.get("latency_summary", [])
    scalability_rows = summary.get("scalability_summary", [])
    attack_rows = summary.get("attack_matrix", [])
    lines: List[str] = []
    lines.append("# linux_mcp Experiment Report")
    lines.append("")
    lines.append("## Latency")
    lines.append("")
    lines.append("| system | payload | avg_ms | p50_ms | p95_ms | p99_ms |")
    lines.append("|---|---|---:|---:|---:|---:|")
    for row in latency_rows:
        lines.append(
            f"| {row.get('system','')} | {row.get('payload_label','')} | {row.get('latency_avg_ms',0.0)} | "
            f"{row.get('latency_p50_ms',0.0)} | {row.get('latency_p95_ms',0.0)} | {row.get('latency_p99_ms',0.0)} |"
        )
    lines.append("")
    lines.append("## Scalability")
    lines.append("")
    lines.append("| system | agents | concurrency | throughput_rps | error_rate | p95_ms |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for row in scalability_rows:
        lines.append(
            f"| {row.get('system','')} | {row.get('agents',0)} | {row.get('concurrency',0)} | {row.get('throughput_rps',0.0)} | "
            f"{float(row.get('error_rate',0.0))*100:.2f}% | {row.get('latency_p95_ms',0.0)} |"
        )
    lines.append("")
    lines.append("## Attack Matrix")
    lines.append("")
    lines.append("| attack_type | userspace | seccomp | kernel |")
    lines.append("|---|---|---|---|")
    by_attack: Dict[str, Dict[str, str]] = {}
    for row in attack_rows:
        by_attack.setdefault(str(row.get("attack_type", "")), {})[str(row.get("system", ""))] = str(row.get("outcome", ""))
    for attack_type in ("spoof", "replay", "substitute", "escalation"):
        item = by_attack.get(attack_type, {})
        lines.append(
            f"| {attack_type} | {item.get('userspace','')} | {item.get('seccomp','')} | {item.get('kernel','')} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render linux_mcp markdown report")
    parser.add_argument("summary_json", type=str)
    parser.add_argument("--output", type=str)
    args = parser.parse_args()

    summary = json.loads(Path(args.summary_json).read_text(encoding="utf-8"))
    rendered = render(summary)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
