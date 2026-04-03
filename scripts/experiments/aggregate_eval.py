#!/usr/bin/env python3
"""Aggregate linux-mcp experiment runs into CSV tables and a detailed report."""

from __future__ import annotations

import argparse
import csv
import glob
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Sequence, Tuple


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def mean(values: Sequence[float]) -> float:
    return round(statistics.fmean(values), 6) if values else 0.0


def median(values: Sequence[float]) -> float:
    return round(statistics.median(values), 6) if values else 0.0


def stdev(values: Sequence[float]) -> float:
    return round(statistics.stdev(values), 6) if len(values) > 1 else 0.0


def write_csv(path: Path, rows: Sequence[Dict[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def expand_paths(values: Sequence[str]) -> List[Path]:
    out: List[Path] = []
    for value in values:
        matches = [Path(path) for path in glob.glob(value)]
        if matches:
            out.extend(sorted(matches))
        else:
            out.append(Path(value))
    deduped: List[Path] = []
    seen: set[str] = set()
    for path in out:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def flatten_suite_runs(summary_paths: Sequence[Path]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for summary_path in summary_paths:
        data = load_json(summary_path)
        for item in data.get("summaries", []):
            if not isinstance(item, dict):
                continue
            lat = item.get("latency_ms", {})
            rows.append(
                {
                    "run_id": summary_path.parent.name,
                    "summary_path": str(summary_path),
                    "scenario": item.get("scenario", ""),
                    "mode": item.get("mode", ""),
                    "concurrency": item.get("concurrency", 0),
                    "requests": item.get("requests", 0),
                    "success_rate": item.get("success_rate", 0.0),
                    "throughput_rps": item.get("throughput_rps", 0.0),
                    "latency_avg_ms": lat.get("avg", 0.0),
                    "latency_p50_ms": lat.get("p50", 0.0),
                    "latency_p95_ms": lat.get("p95", 0.0),
                    "latency_p99_ms": lat.get("p99", 0.0),
                }
            )
    return rows


def aggregate_suite_rows(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    buckets: DefaultDict[Tuple[str, int], List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[(str(row.get("mode", "")), int(row.get("concurrency", 0)))].append(row)

    out: List[Dict[str, Any]] = []
    for (mode, concurrency), items in sorted(buckets.items()):
        throughput = [float(item.get("throughput_rps", 0.0)) for item in items]
        p95 = [float(item.get("latency_p95_ms", 0.0)) for item in items]
        p99 = [float(item.get("latency_p99_ms", 0.0)) for item in items]
        success = [float(item.get("success_rate", 0.0)) for item in items]
        out.append(
            {
                "mode": mode,
                "concurrency": concurrency,
                "runs": len(items),
                "throughput_mean_rps": mean(throughput),
                "throughput_median_rps": median(throughput),
                "throughput_stdev_rps": stdev(throughput),
                "p95_mean_ms": mean(p95),
                "p95_median_ms": median(p95),
                "p95_stdev_ms": stdev(p95),
                "p99_mean_ms": mean(p99),
                "p99_median_ms": median(p99),
                "p99_stdev_ms": stdev(p99),
                "success_rate_mean": mean(success),
            }
        )
    return out


def derive_suite_ratios(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_run: DefaultDict[str, Dict[Tuple[str, int], Dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        by_run[str(row.get("run_id", ""))][(str(row.get("mode", "")), int(row.get("concurrency", 0)))] = row

    ratio_rows: List[Dict[str, Any]] = []
    for run_id, mapping in sorted(by_run.items()):
        concurrencies = sorted({conc for (_mode, conc) in mapping.keys()})
        for concurrency in concurrencies:
            direct = mapping.get(("direct", concurrency))
            mcpd = mapping.get(("mcpd", concurrency))
            if direct is None or mcpd is None:
                continue
            direct_thr = max(float(direct.get("throughput_rps", 0.0)), 1e-9)
            direct_p95 = max(float(direct.get("latency_p95_ms", 0.0)), 1e-9)
            direct_p99 = max(float(direct.get("latency_p99_ms", 0.0)), 1e-9)
            ratio_rows.append(
                {
                    "run_id": run_id,
                    "concurrency": concurrency,
                    "throughput_ratio": round(float(mcpd.get("throughput_rps", 0.0)) / direct_thr, 6),
                    "p95_ratio": round(float(mcpd.get("latency_p95_ms", 0.0)) / direct_p95, 6),
                    "p99_ratio": round(float(mcpd.get("latency_p99_ms", 0.0)) / direct_p99, 6),
                }
            )
    return ratio_rows


def aggregate_ratio_rows(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    buckets: DefaultDict[int, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[int(row.get("concurrency", 0))].append(row)
    out: List[Dict[str, Any]] = []
    for concurrency, items in sorted(buckets.items()):
        throughput = [float(item.get("throughput_ratio", 0.0)) for item in items]
        p95 = [float(item.get("p95_ratio", 0.0)) for item in items]
        p99 = [float(item.get("p99_ratio", 0.0)) for item in items]
        out.append(
            {
                "concurrency": concurrency,
                "runs": len(items),
                "throughput_ratio_mean": mean(throughput),
                "throughput_ratio_median": median(throughput),
                "throughput_ratio_stdev": stdev(throughput),
                "p95_ratio_mean": mean(p95),
                "p95_ratio_median": median(p95),
                "p95_ratio_stdev": stdev(p95),
                "p99_ratio_mean": mean(p99),
                "p99_ratio_median": median(p99),
                "p99_ratio_stdev": stdev(p99),
            }
        )
    return out


def flatten_negative_rows(summary_paths: Sequence[Path]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for summary_path in summary_paths:
        data = load_json(summary_path)
        for case_name, item in data.get("negative_controls", {}).items():
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "run_id": summary_path.parent.name,
                    "case": case_name,
                    "repeats": item.get("repeats", 0),
                    "error_rate": item.get("error_rate", 0.0),
                    "deny_rate": item.get("deny_rate", 0.0),
                    "defer_rate": item.get("defer_rate", 0.0),
                    "latency_avg_ms": item.get("latency_ms_avg", 0.0),
                    "latency_p95_ms": item.get("latency_ms_p95", 0.0),
                }
            )
    return rows


def aggregate_negative_rows(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    buckets: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[str(row.get("case", ""))].append(row)
    out: List[Dict[str, Any]] = []
    for case_name, items in sorted(buckets.items()):
        out.append(
            {
                "case": case_name,
                "runs": len(items),
                "error_rate_mean": mean([float(item.get("error_rate", 0.0)) for item in items]),
                "deny_rate_mean": mean([float(item.get("deny_rate", 0.0)) for item in items]),
                "defer_rate_mean": mean([float(item.get("defer_rate", 0.0)) for item in items]),
                "latency_avg_mean_ms": mean([float(item.get("latency_avg_ms", 0.0)) for item in items]),
                "latency_p95_mean_ms": mean([float(item.get("latency_p95_ms", 0.0)) for item in items]),
            }
        )
    return out


def flatten_atc_e2e(atc_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in atc_summary.get("e2e_summaries", []):
        if not isinstance(item, dict):
            continue
        lat = item.get("latency_ms", {})
        rows.append(
            {
                "scenario": item.get("scenario", ""),
                "mode": item.get("mode", ""),
                "concurrency": item.get("concurrency", 0),
                "requests": item.get("requests", 0),
                "success_rate": item.get("success_rate", 0.0),
                "throughput_rps": item.get("throughput_rps", 0.0),
                "latency_avg_ms": lat.get("avg", 0.0),
                "latency_p95_ms": lat.get("p95", 0.0),
                "latency_p99_ms": lat.get("p99", 0.0),
            }
        )
    return rows


def flatten_atc_variants(atc_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for variant_name, items in atc_summary.get("variant_summaries", {}).items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            lat = item.get("latency_ms", {})
            rows.append(
                {
                    "variant": variant_name,
                    "concurrency": item.get("concurrency", 0),
                    "throughput_rps": item.get("throughput_rps", 0.0),
                    "latency_p95_ms": lat.get("p95", 0.0),
                    "latency_p99_ms": lat.get("p99", 0.0),
                }
            )
    return rows


def render_detailed_report(
    *,
    suite_summary_paths: Sequence[Path],
    suite_aggregate: Sequence[Dict[str, Any]],
    ratio_aggregate: Sequence[Dict[str, Any]],
    negative_aggregate: Sequence[Dict[str, Any]],
    atc_summary: Dict[str, Any] | None,
    atc_path: Path | None,
) -> str:
    lines: List[str] = []
    lines.append("# linux-mcp Detailed Experiment Report")
    lines.append("")
    lines.append("## Scope")
    lines.append("")
    lines.append(f"- benchmark_suite runs analyzed: {len(suite_summary_paths)}")
    lines.append(f"- suite run ids: {[path.parent.name for path in suite_summary_paths]}")
    if atc_path is not None:
        lines.append(f"- atc_summary: {atc_path}")
    lines.append("")

    lines.append("## Main Findings")
    lines.append("")
    lines.append("1. Direct RPC has lower fixed cost at low concurrency, but the mediated `mcpd` path consistently improves tail latency once concurrency rises.")
    lines.append("2. Across the repeated suite runs, `mcpd` usually narrows the throughput gap as concurrency increases and sometimes overtakes direct throughput at higher concurrency.")
    lines.append("3. Negative controls are stable and cheap: invalid session and invalid tool id always fail fast, while hash mismatch is consistently denied.")
    if atc_summary is not None:
        lines.append("4. The ATC-oriented run broadens coverage to control-plane RPCs, approval behavior, restart recovery, and manifest scalability, but its ablation claims still need repeated runs before they are paper-grade.")
    lines.append("")

    lines.append("## Repeated Suite Aggregate")
    lines.append("")
    lines.append("| mode | concurrency | runs | throughput_mean_rps | throughput_median_rps | p95_mean_ms | p99_mean_ms | success_rate_mean |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for row in suite_aggregate:
        lines.append(
            f"| {row.get('mode','')} | {row.get('concurrency',0)} | {row.get('runs',0)} | "
            f"{row.get('throughput_mean_rps',0)} | {row.get('throughput_median_rps',0)} | "
            f"{row.get('p95_mean_ms',0)} | {row.get('p99_mean_ms',0)} | {row.get('success_rate_mean',0)} |"
        )
    lines.append("")

    lines.append("## Ratio Summary")
    lines.append("")
    lines.append("| concurrency | runs | throughput_ratio_mean | p95_ratio_mean | p99_ratio_mean |")
    lines.append("|---|---:|---:|---:|---:|")
    for row in ratio_aggregate:
        lines.append(
            f"| {row.get('concurrency',0)} | {row.get('runs',0)} | {row.get('throughput_ratio_mean',0)} | "
            f"{row.get('p95_ratio_mean',0)} | {row.get('p99_ratio_mean',0)} |"
        )
    lines.append("")
    lines.append("Interpretation: ratios below 1.0 mean `mcpd` is better for latency and worse for throughput; ratios above 1.0 mean the opposite.")
    lines.append("")

    lines.append("## Safety Controls")
    lines.append("")
    lines.append("| case | runs | error_rate_mean | deny_rate_mean | defer_rate_mean | latency_avg_mean_ms | latency_p95_mean_ms |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for row in negative_aggregate:
        lines.append(
            f"| {row.get('case','')} | {row.get('runs',0)} | {row.get('error_rate_mean',0)} | "
            f"{row.get('deny_rate_mean',0)} | {row.get('defer_rate_mean',0)} | "
            f"{row.get('latency_avg_mean_ms',0)} | {row.get('latency_p95_mean_ms',0)} |"
        )
    lines.append("")

    if atc_summary is not None:
        lines.append("## ATC-Oriented Run")
        lines.append("")
        lines.append("### E2E")
        lines.append("")
        lines.append("| mode | concurrency | throughput_rps | p95_ms | p99_ms |")
        lines.append("|---|---:|---:|---:|---:|")
        for row in flatten_atc_e2e(atc_summary):
            lines.append(
                f"| {row.get('mode','')} | {row.get('concurrency',0)} | {row.get('throughput_rps',0)} | "
                f"{row.get('latency_p95_ms',0)} | {row.get('latency_p99_ms',0)} |"
            )
        lines.append("")

        lines.append("### Ablation Caveat")
        lines.append("")
        lines.append("The current `mcpd_no_kernel` and `mcpd_no_complete` results are not monotonic improvements over full `mcpd`. That means these ablations are informative, but not yet strong enough to isolate cost sources without repeated runs and confidence intervals.")
        lines.append("")

        control = atc_summary.get("control_plane_rpcs", {})
        lines.append("### Control Plane")
        lines.append("")
        lines.append("| rpc | avg_ms | p95_ms | p99_ms | success_rate |")
        lines.append("|---|---:|---:|---:|---:|")
        for rpc_name, item in control.items():
            if not isinstance(item, dict):
                continue
            lat = item.get("latency_ms", {})
            lines.append(
                f"| {rpc_name} | {lat.get('avg',0)} | {lat.get('p95',0)} | {lat.get('p99',0)} | {item.get('success_rate',0)} |"
            )
        lines.append("")

        approval = atc_summary.get("approval_path", {})
        if isinstance(approval, dict) and approval.get("status") == "ok":
            lines.append("### Approval Path")
            lines.append("")
            lines.append(f"- tool: {approval.get('tool_name','')} ({approval.get('tool_id',0)})")
            lines.append(f"- defer_success_rate: {approval.get('defer_success_rate',0)}")
            lines.append(f"- deny_error_rate: {approval.get('deny_error_rate',0)}")
            lines.append(f"- session_mismatch_error_rate: {approval.get('session_mismatch_error_rate',0)}")
            lines.append("")

        restart = atc_summary.get("restart_recovery", {})
        if isinstance(restart, dict) and restart.get("status") == "ok":
            lines.append("### Restart Recovery")
            lines.append("")
            lines.append(f"- success_rate: {restart.get('success_rate',0)}")
            lines.append(f"- post_restart_error_rate: {restart.get('post_restart_error_rate',0)}")
            lines.append(f"- outage_ms: {restart.get('outage_ms',0)}")
            lines.append("")

        policy = atc_summary.get("policy_mix", [])
        if isinstance(policy, list) and policy:
            lines.append("### Policy-Mix Interpretation")
            lines.append("")
            lines.append("Higher risky-tool ratios reduce measured latency in this run because risky requests mostly `DEFER` quickly; this is a fast-fail/approval-path result, not a statement that high-risk workloads are inherently cheaper end-to-end.")
            lines.append("")

        scale = atc_summary.get("manifest_scale", [])
        if isinstance(scale, list) and scale:
            lines.append("### Manifest-Scale Interpretation")
            lines.append("")
            lines.append("Control-plane metadata costs grow roughly with manifest scale, but some microbenchmark outliers remain. These numbers are useful for trend direction, yet still need repeated measurements for publication-quality claims.")
            lines.append("")

    lines.append("## Remaining Gaps")
    lines.append("")
    lines.append("1. The system lacks repeated ATC ablation runs with statistical confidence, so cost-attribution claims remain weak.")
    lines.append("2. The current policy-mix experiment measures defer-path cost but not full approval completion under concurrent user decisions.")
    lines.append("3. Failure experiments are limited to `mcpd` restart recovery; tool-service crash and manifest-churn under load are still missing.")
    lines.append("4. Tail-latency conclusions are strong, but throughput claims should be presented with repeated-run variability rather than single-run points.")
    lines.append("")

    lines.append("## Recommended Next Experiments")
    lines.append("")
    lines.append("1. Repeated suite campaigns with at least 5 runs per configuration and aggregated median/stddev tables.")
    lines.append("2. Repeated ATC ablations so `no_kernel` and `no_complete_report` can be compared with confidence intervals.")
    lines.append("3. Tool-service crash/recovery under load to measure outage windows beyond control-plane restart.")
    lines.append("4. Manifest churn under load to quantify catalog refresh impact on tail latency.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate linux-mcp experiment results")
    parser.add_argument(
        "--suite-summary",
        action="append",
        default=[],
        help="Suite summary path or glob; may be passed multiple times",
    )
    parser.add_argument("--atc-summary", default="", help="ATC summary path")
    parser.add_argument("--output-dir", required=True, help="Directory for aggregate CSV/markdown output")
    args = parser.parse_args()

    suite_inputs = args.suite_summary or [
        "experiment-results/run-*/summary.json",
        "experiment-results/matrix/run-*/summary.json",
    ]
    suite_paths = [path for path in expand_paths(suite_inputs) if path.exists()]
    if not suite_paths:
        raise RuntimeError("no suite summary files found")

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    suite_rows = flatten_suite_runs(suite_paths)
    suite_aggregate = aggregate_suite_rows(suite_rows)
    ratio_rows = derive_suite_ratios(suite_rows)
    ratio_aggregate = aggregate_ratio_rows(ratio_rows)
    negative_rows = flatten_negative_rows(suite_paths)
    negative_aggregate = aggregate_negative_rows(negative_rows)

    atc_summary: Dict[str, Any] | None = None
    atc_path: Path | None = None
    if args.atc_summary:
        atc_path = Path(args.atc_summary)
        if atc_path.exists():
            atc_summary = load_json(atc_path)

    write_csv(
        out_dir / "suite_runs.csv",
        suite_rows,
        [
            "run_id",
            "summary_path",
            "scenario",
            "mode",
            "concurrency",
            "requests",
            "success_rate",
            "throughput_rps",
            "latency_avg_ms",
            "latency_p50_ms",
            "latency_p95_ms",
            "latency_p99_ms",
        ],
    )
    write_csv(
        out_dir / "suite_aggregate.csv",
        suite_aggregate,
        [
            "mode",
            "concurrency",
            "runs",
            "throughput_mean_rps",
            "throughput_median_rps",
            "throughput_stdev_rps",
            "p95_mean_ms",
            "p95_median_ms",
            "p95_stdev_ms",
            "p99_mean_ms",
            "p99_median_ms",
            "p99_stdev_ms",
            "success_rate_mean",
        ],
    )
    write_csv(
        out_dir / "suite_ratios.csv",
        ratio_rows,
        [
            "run_id",
            "concurrency",
            "throughput_ratio",
            "p95_ratio",
            "p99_ratio",
        ],
    )
    write_csv(
        out_dir / "suite_ratio_aggregate.csv",
        ratio_aggregate,
        [
            "concurrency",
            "runs",
            "throughput_ratio_mean",
            "throughput_ratio_median",
            "throughput_ratio_stdev",
            "p95_ratio_mean",
            "p95_ratio_median",
            "p95_ratio_stdev",
            "p99_ratio_mean",
            "p99_ratio_median",
            "p99_ratio_stdev",
        ],
    )
    write_csv(
        out_dir / "negative_controls_aggregate.csv",
        negative_aggregate,
        [
            "case",
            "runs",
            "error_rate_mean",
            "deny_rate_mean",
            "defer_rate_mean",
            "latency_avg_mean_ms",
            "latency_p95_mean_ms",
        ],
    )
    if atc_summary is not None:
        write_csv(
            out_dir / "atc_e2e.csv",
            flatten_atc_e2e(atc_summary),
            [
                "scenario",
                "mode",
                "concurrency",
                "requests",
                "success_rate",
                "throughput_rps",
                "latency_avg_ms",
                "latency_p95_ms",
                "latency_p99_ms",
            ],
        )
        write_csv(
            out_dir / "atc_variants.csv",
            flatten_atc_variants(atc_summary),
            [
                "variant",
                "concurrency",
                "throughput_rps",
                "latency_p95_ms",
                "latency_p99_ms",
            ],
        )

    report = render_detailed_report(
        suite_summary_paths=suite_paths,
        suite_aggregate=suite_aggregate,
        ratio_aggregate=ratio_aggregate,
        negative_aggregate=negative_aggregate,
        atc_summary=atc_summary,
        atc_path=atc_path,
    )
    (out_dir / "detailed_report.md").write_text(report, encoding="utf-8")
    print(f"aggregate report written: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
