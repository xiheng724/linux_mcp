#!/usr/bin/env python3
"""Aggregate repeated security runs into CSV tables and a markdown summary."""

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


def flatten_security(summary_paths: Sequence[Path]) -> Dict[str, List[Dict[str, Any]]]:
    attack_rows: List[Dict[str, Any]] = []
    semantic_rows: List[Dict[str, Any]] = []
    daemon_rows: List[Dict[str, Any]] = []
    ablation_rows: List[Dict[str, Any]] = []
    observability_rows: List[Dict[str, Any]] = []
    mixed_rows: List[Dict[str, Any]] = []
    for summary_path in summary_paths:
        data = load_json(summary_path)
        run_id = summary_path.parent.name
        for item in data.get("attack_summary", []):
            if not isinstance(item, dict):
                continue
            attack_rows.append(
                {
                    "run_id": run_id,
                    "scenario_group": item.get("scenario_group", ""),
                    "attack_case": item.get("attack_case", ""),
                    "mode": item.get("mode", ""),
                    "bypass_success_rate": item.get("bypass_success_rate", 0.0),
                    "detection_rate": item.get("detection_rate", 0.0),
                    "reject_latency_p95_ms": item.get("reject_latency_p95_ms", 0.0),
                }
            )
        semantic = data.get("semantic_tampering", {})
        if isinstance(semantic, dict) and semantic.get("status") == "ok":
            summary = semantic.get("summary", {})
            semantic_rows.append(
                {
                    "run_id": run_id,
                    "precision": summary.get("precision", 0.0),
                    "recall": summary.get("recall", 0.0),
                    "false_positive_rate": summary.get("false_positive_rate", 0.0),
                    "false_negative_rate": summary.get("false_negative_rate", 0.0),
                    "bypass_success_rate": summary.get("bypass_success_rate", 0.0),
                }
            )
        for item in data.get("daemon_compromise", []):
            if not isinstance(item, dict):
                continue
            daemon_rows.append(
                {
                    "run_id": run_id,
                    "mode": item.get("mode", ""),
                    "approval_state_preserved": item.get("approval_state_preserved", 0),
                    "session_state_preserved": item.get("session_state_preserved", 0),
                    "post_crash_agent_visible": item.get("post_crash_agent_visible", 0),
                    "approval_latency_ms": item.get("approval_latency_ms", 0.0),
                    "replay_latency_ms": item.get("replay_latency_ms", 0.0),
                }
            )
        for item in data.get("mechanism_ablation", []):
            if not isinstance(item, dict):
                continue
            ablation_rows.append(
                {
                    "run_id": run_id,
                    "mechanism": item.get("mechanism", ""),
                    "delta": item.get("delta", 0.0),
                    "baseline_attack_success_rate": item.get("baseline_attack_success_rate", 0.0),
                    "ablated_attack_success_rate": item.get("ablated_attack_success_rate", 0.0),
                }
            )
        for item in data.get("observability", []):
            if not isinstance(item, dict):
                continue
            observability_rows.append(
                {
                    "run_id": run_id,
                    "mode": item.get("mode", ""),
                    "independent_audit": item.get("independent_audit", 0),
                    "state_introspection": item.get("state_introspection", 0),
                    "post_crash_visibility": item.get("post_crash_visibility", 0),
                    "root_cause_success_rate": item.get("root_cause_success_rate", 0.0),
                }
            )
        for item in data.get("mixed_attack", []):
            if not isinstance(item, dict):
                continue
            mixed_rows.append(
                {
                    "run_id": run_id,
                    "mode": item.get("mode", ""),
                    "malicious_pct": item.get("malicious_pct", 0),
                    "legit_throughput_rps": item.get("legit_throughput_rps", 0.0),
                    "legit_success_rate": item.get("legit_success_rate", 0.0),
                    "legit_p95_ms": item.get("legit_p95_ms", 0.0),
                    "attack_acceptance_rate": item.get("attack_acceptance_rate", 0.0),
                }
            )
    return {
        "attack": attack_rows,
        "semantic": semantic_rows,
        "daemon": daemon_rows,
        "ablation": ablation_rows,
        "observability": observability_rows,
        "mixed": mixed_rows,
    }


def render_markdown(
    attack_agg: Sequence[Dict[str, Any]],
    semantic_agg: Sequence[Dict[str, Any]],
    daemon_agg: Sequence[Dict[str, Any]],
    ablation_agg: Sequence[Dict[str, Any]],
    mixed_agg: Sequence[Dict[str, Any]],
) -> str:
    lines: List[str] = []
    lines.append("# Repeated Security Aggregate")
    lines.append("")
    lines.append("## Attack Aggregate")
    lines.append("")
    lines.append("| group | case | mode | runs | bypass_mean | detection_mean | reject_p95_mean_ms |")
    lines.append("|---|---|---|---:|---:|---:|---:|")
    for row in attack_agg:
        lines.append(
            f"| {row.get('scenario_group','')} | {row.get('attack_case','')} | {row.get('mode','')} | {row.get('runs',0)} | "
            f"{float(row.get('bypass_success_rate_mean',0.0))*100:.2f}% | {float(row.get('detection_rate_mean',0.0))*100:.2f}% | "
            f"{row.get('reject_latency_p95_ms_mean',0)} |"
        )
    lines.append("")
    lines.append("## Semantic Aggregate")
    lines.append("")
    lines.append("| runs | precision_mean | recall_mean | fnr_mean | bypass_mean |")
    lines.append("|---:|---:|---:|---:|---:|")
    for row in semantic_agg:
        lines.append(
            f"| {row.get('runs',0)} | {float(row.get('precision_mean',0.0))*100:.2f}% | {float(row.get('recall_mean',0.0))*100:.2f}% | "
            f"{float(row.get('false_negative_rate_mean',0.0))*100:.2f}% | {float(row.get('bypass_success_rate_mean',0.0))*100:.2f}% |"
        )
    lines.append("")
    lines.append("## Daemon Aggregate")
    lines.append("")
    lines.append("| mode | runs | approval_state_preserved_mean | session_state_preserved_mean | post_crash_visibility_mean |")
    lines.append("|---|---:|---:|---:|---:|")
    for row in daemon_agg:
        lines.append(
            f"| {row.get('mode','')} | {row.get('runs',0)} | {float(row.get('approval_state_preserved_mean',0.0))*100:.2f}% | "
            f"{float(row.get('session_state_preserved_mean',0.0))*100:.2f}% | {float(row.get('post_crash_agent_visible_mean',0.0))*100:.2f}% |"
        )
    lines.append("")
    lines.append("## Mechanism Ablation Aggregate")
    lines.append("")
    lines.append("| mechanism | runs | delta_mean |")
    lines.append("|---|---:|---:|")
    for row in ablation_agg:
        lines.append(
            f"| {row.get('mechanism','')} | {row.get('runs',0)} | {float(row.get('delta_mean',0.0))*100:.2f}% |"
        )
    lines.append("")
    lines.append("## Mixed Attack Aggregate")
    lines.append("")
    lines.append("| mode | malicious_pct | runs | legit_p95_mean_ms | attack_acceptance_mean |")
    lines.append("|---|---:|---:|---:|---:|")
    for row in mixed_agg:
        lines.append(
            f"| {row.get('mode','')} | {row.get('malicious_pct',0)} | {row.get('runs',0)} | {row.get('legit_p95_ms_mean',0)} | "
            f"{float(row.get('attack_acceptance_rate_mean',0.0))*100:.2f}% |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate repeated security runs")
    parser.add_argument("--summary", action="append", default=[], help="security summary path or glob")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    summary_inputs = args.summary or ["experiment-results/security-repeat/run-*/raw/run-*/security_summary.json"]
    summary_paths = expand_paths(summary_inputs)
    if not summary_paths:
        raise RuntimeError("no security summary files found")

    rows = flatten_security(summary_paths)
    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    attack_agg = aggregate_rows(rows["attack"], ["scenario_group", "attack_case", "mode"], ["bypass_success_rate", "detection_rate", "reject_latency_p95_ms"])
    semantic_agg = aggregate_rows(rows["semantic"], [], ["precision", "recall", "false_positive_rate", "false_negative_rate", "bypass_success_rate"])
    daemon_agg = aggregate_rows(rows["daemon"], ["mode"], ["approval_state_preserved", "session_state_preserved", "post_crash_agent_visible", "approval_latency_ms", "replay_latency_ms"])
    ablation_agg = aggregate_rows(rows["ablation"], ["mechanism"], ["delta", "baseline_attack_success_rate", "ablated_attack_success_rate"])
    observability_agg = aggregate_rows(rows["observability"], ["mode"], ["independent_audit", "state_introspection", "post_crash_visibility", "root_cause_success_rate"])
    mixed_agg = aggregate_rows(rows["mixed"], ["mode", "malicious_pct"], ["legit_throughput_rps", "legit_success_rate", "legit_p95_ms", "attack_acceptance_rate"])

    write_csv(out_dir / "security_attack_runs.csv", rows["attack"], ["run_id", "scenario_group", "attack_case", "mode", "bypass_success_rate", "detection_rate", "reject_latency_p95_ms"])
    write_csv(out_dir / "security_attack_aggregate.csv", attack_agg, ["scenario_group", "attack_case", "mode", "runs", "bypass_success_rate_mean", "bypass_success_rate_median", "bypass_success_rate_stdev", "detection_rate_mean", "detection_rate_median", "detection_rate_stdev", "reject_latency_p95_ms_mean", "reject_latency_p95_ms_median", "reject_latency_p95_ms_stdev"])
    write_csv(out_dir / "security_semantic_runs.csv", rows["semantic"], ["run_id", "precision", "recall", "false_positive_rate", "false_negative_rate", "bypass_success_rate"])
    write_csv(out_dir / "security_semantic_aggregate.csv", semantic_agg, ["runs", "precision_mean", "precision_median", "precision_stdev", "recall_mean", "recall_median", "recall_stdev", "false_positive_rate_mean", "false_positive_rate_median", "false_positive_rate_stdev", "false_negative_rate_mean", "false_negative_rate_median", "false_negative_rate_stdev", "bypass_success_rate_mean", "bypass_success_rate_median", "bypass_success_rate_stdev"])
    write_csv(out_dir / "security_daemon_aggregate.csv", daemon_agg, ["mode", "runs", "approval_state_preserved_mean", "approval_state_preserved_median", "approval_state_preserved_stdev", "session_state_preserved_mean", "session_state_preserved_median", "session_state_preserved_stdev", "post_crash_agent_visible_mean", "post_crash_agent_visible_median", "post_crash_agent_visible_stdev", "approval_latency_ms_mean", "approval_latency_ms_median", "approval_latency_ms_stdev", "replay_latency_ms_mean", "replay_latency_ms_median", "replay_latency_ms_stdev"])
    write_csv(out_dir / "security_ablation_aggregate.csv", ablation_agg, ["mechanism", "runs", "delta_mean", "delta_median", "delta_stdev", "baseline_attack_success_rate_mean", "ablated_attack_success_rate_mean"])
    write_csv(out_dir / "security_observability_aggregate.csv", observability_agg, ["mode", "runs", "independent_audit_mean", "state_introspection_mean", "post_crash_visibility_mean", "root_cause_success_rate_mean"])
    write_csv(out_dir / "security_mixed_aggregate.csv", mixed_agg, ["mode", "malicious_pct", "runs", "legit_throughput_rps_mean", "legit_success_rate_mean", "legit_p95_ms_mean", "attack_acceptance_rate_mean"])
    (out_dir / "repeated_security_report.md").write_text(render_markdown(attack_agg, semantic_agg, daemon_agg, ablation_agg, mixed_agg), encoding="utf-8")
    print(f"repeated security aggregate written: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
