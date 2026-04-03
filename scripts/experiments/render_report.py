#!/usr/bin/env python3
"""Render a concise markdown report from benchmark_suite summary.json."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def fmt_pct(x: float) -> str:
    return f"{x * 100:.2f}%"


def fmt_ms(x: Any) -> str:
    try:
        return f"{float(x):.2f}"
    except Exception:
        return "0.00"


def load_summary(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def row_for_summary(item: Dict[str, Any]) -> str:
    lat = item.get("latency_ms", {})
    return (
        f"| {item.get('scenario','')} | {item.get('mode','')} | {item.get('concurrency',0)} | "
        f"{item.get('requests',0)} | {fmt_pct(float(item.get('success_rate', 0.0)))} | "
        f"{item.get('throughput_rps',0)} | {fmt_ms(lat.get('p50', 0))} | "
        f"{fmt_ms(lat.get('p95', 0))} | {fmt_ms(lat.get('p99', 0))} |"
    )


def render_markdown(data: Dict[str, Any]) -> str:
    meta = data.get("meta", {})
    summaries: List[Dict[str, Any]] = [x for x in data.get("summaries", []) if isinstance(x, dict)]
    negatives = data.get("negative_controls", {})

    lines: List[str] = []
    lines.append("# linux-mcp Experiment Report")
    lines.append("")
    lines.append(f"- run_ts: {meta.get('run_ts', '')}")
    lines.append(f"- requests_per_scenario: {meta.get('requests_per_scenario', 0)}")
    lines.append(f"- concurrency: {meta.get('concurrency', [])}")
    lines.append(f"- negative_repeats: {meta.get('negative_repeats', 0)}")
    lines.append("")

    lines.append("## Performance Scenarios")
    lines.append("")
    lines.append("| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for item in summaries:
        lines.append(row_for_summary(item))
    lines.append("")

    lines.append("## Negative Controls")
    lines.append("")
    lines.append("| case | repeats | error_rate | deny_rate | defer_rate | avg_ms | p95_ms |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for case_name, item in negatives.items():
        if not isinstance(item, dict):
            continue
        lines.append(
            f"| {case_name} | {item.get('repeats', 0)} | {fmt_pct(float(item.get('error_rate', 0.0)))} | "
            f"{fmt_pct(float(item.get('deny_rate', 0.0)))} | {fmt_pct(float(item.get('defer_rate', 0.0)))} | "
            f"{fmt_ms(item.get('latency_ms_avg', 0))} | {fmt_ms(item.get('latency_ms_p95', 0))} |"
        )
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render markdown report from benchmark summary")
    parser.add_argument("summary_json", type=str)
    parser.add_argument("--output", type=str, default="")
    args = parser.parse_args()

    data = load_summary(Path(args.summary_json))
    report = render_markdown(data)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(report, encoding="utf-8")
        print(f"report written: {out_path}")
    else:
        print(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
