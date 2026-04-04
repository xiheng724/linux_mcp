#!/usr/bin/env python3
"""Aggregate repeated ATC runs into CSV tables and a markdown summary."""

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
    return [path for path in out if path.exists()]


def flatten_atc_runs(summary_paths: Sequence[Path]) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    e2e_rows: List[Dict[str, Any]] = []
    variant_rows: List[Dict[str, Any]] = []
    for summary_path in summary_paths:
        data = load_json(summary_path)
        run_id = summary_path.parent.name
        for item in data.get("e2e_summaries", []):
            if not isinstance(item, dict):
                continue
            lat = item.get("latency_ms", {})
            e2e_rows.append(
                {
                    "run_id": run_id,
                    "mode": item.get("mode", ""),
                    "concurrency": item.get("concurrency", 0),
                    "throughput_rps": item.get("throughput_rps", 0.0),
                    "latency_p95_ms": lat.get("p95", 0.0),
                    "latency_p99_ms": lat.get("p99", 0.0),
                }
            )
        for variant_name, items in data.get("variant_summaries", {}).items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                lat = item.get("latency_ms", {})
                variant_rows.append(
                    {
                        "run_id": run_id,
                        "variant": variant_name,
                        "concurrency": item.get("concurrency", 0),
                        "throughput_rps": item.get("throughput_rps", 0.0),
                        "latency_p95_ms": lat.get("p95", 0.0),
                        "latency_p99_ms": lat.get("p99", 0.0),
                    }
                )
    return e2e_rows, variant_rows


def aggregate_rows(
    rows: Sequence[Dict[str, Any]],
    key_fields: Sequence[str],
    value_fields: Sequence[str],
) -> List[Dict[str, Any]]:
    buckets: DefaultDict[Tuple[Any, ...], List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[tuple(row[field] for field in key_fields)].append(row)
    out: List[Dict[str, Any]] = []
    for key, items in sorted(buckets.items()):
        entry = {field: key[idx] for idx, field in enumerate(key_fields)}
        entry["runs"] = len(items)
        for value_field in value_fields:
            values = [float(item[value_field]) for item in items]
            entry[f"{value_field}_mean"] = mean(values)
            entry[f"{value_field}_median"] = median(values)
            entry[f"{value_field}_stdev"] = stdev(values)
        out.append(entry)
    return out


def render_markdown(e2e_agg: Sequence[Dict[str, Any]], var_agg: Sequence[Dict[str, Any]]) -> str:
    lines: List[str] = []
    lines.append("# Repeated ATC Aggregate")
    lines.append("")
    lines.append("## E2E Aggregate")
    lines.append("")
    lines.append("| mode | concurrency | runs | throughput_mean | p95_mean | p99_mean |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for row in e2e_agg:
        lines.append(
            f"| {row.get('mode','')} | {row.get('concurrency',0)} | {row.get('runs',0)} | "
            f"{row.get('throughput_rps_mean',0)} | {row.get('latency_p95_ms_mean',0)} | {row.get('latency_p99_ms_mean',0)} |"
        )
    lines.append("")
    lines.append("## Variant Aggregate")
    lines.append("")
    lines.append("| variant | concurrency | runs | throughput_mean | p95_mean | p99_mean |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for row in var_agg:
        lines.append(
            f"| {row.get('variant','')} | {row.get('concurrency',0)} | {row.get('runs',0)} | "
            f"{row.get('throughput_rps_mean',0)} | {row.get('latency_p95_ms_mean',0)} | {row.get('latency_p99_ms_mean',0)} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate repeated ATC runs")
    parser.add_argument("--summary", action="append", default=[], help="ATC summary path or glob")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    summary_inputs = args.summary or ["experiment-results/atc-repeat/run-*/raw/run-*/atc_summary.json"]
    summary_paths = expand_paths(summary_inputs)
    if not summary_paths:
        raise RuntimeError("no ATC summary files found")

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    e2e_rows, variant_rows = flatten_atc_runs(summary_paths)
    e2e_agg = aggregate_rows(e2e_rows, ["mode", "concurrency"], ["throughput_rps", "latency_p95_ms", "latency_p99_ms"])
    var_agg = aggregate_rows(variant_rows, ["variant", "concurrency"], ["throughput_rps", "latency_p95_ms", "latency_p99_ms"])

    write_csv(out_dir / "atc_e2e_runs.csv", e2e_rows, ["run_id", "mode", "concurrency", "throughput_rps", "latency_p95_ms", "latency_p99_ms"])
    write_csv(
        out_dir / "atc_e2e_aggregate.csv",
        e2e_agg,
        ["mode", "concurrency", "runs", "throughput_rps_mean", "throughput_rps_median", "throughput_rps_stdev", "latency_p95_ms_mean", "latency_p95_ms_median", "latency_p95_ms_stdev", "latency_p99_ms_mean", "latency_p99_ms_median", "latency_p99_ms_stdev"],
    )
    write_csv(
        out_dir / "atc_variant_aggregate.csv",
        var_agg,
        ["variant", "concurrency", "runs", "throughput_rps_mean", "throughput_rps_median", "throughput_rps_stdev", "latency_p95_ms_mean", "latency_p95_ms_median", "latency_p95_ms_stdev", "latency_p99_ms_mean", "latency_p99_ms_median", "latency_p99_ms_stdev"],
    )
    (out_dir / "repeated_atc_report.md").write_text(render_markdown(e2e_agg, var_agg), encoding="utf-8")
    print(f"repeated atc aggregate written: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
