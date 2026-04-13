#!/usr/bin/env python3
"""Render a top-level index of all experiment snapshots.

Scans `experiment-results/` for known suite directories and emits a single
markdown file that lists each run (most recent first), links to its per-run
report, and surfaces the headline numbers from each suite's `*_summary.json`.

This is intentionally non-destructive: it only reads the existing
`<suite>/run-<ts>/*_summary.json` files written by the individual runners
(linux_mcp_eval, netlink_microbench, semantic_hash_prompt_injection,
kernel_ablation, registry_scaling, overload_eval, attack_extended,
stats_rehash). Nothing is re-computed and nothing under
`experiment-results/` is modified.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Known suites and the logical name of their per-run summary / report files.
# Each entry: (suite_dirname, summary_json_filename, report_md_filename, extractor)
SUITES: List[Tuple[str, str, str, Optional[Callable[[Dict[str, Any]], str]]]] = [
    ("linux-mcp-paper-final-n5",   "linux_mcp_summary.json",         "linux_mcp_report.md",        None),
    ("linux-mcp-paper-final-n30",  "linux_mcp_summary.json",         "linux_mcp_report.md",        None),
    ("linux-mcp-boundary-n10",     "linux_mcp_summary.json",         "linux_mcp_report.md",        None),
    ("linux-mcp-hardened-final",   "linux_mcp_summary.json",         "linux_mcp_report.md",        None),
    ("netlink-microbench-e",       "netlink_microbench_summary.json","netlink_microbench_report.md", None),
    ("semantic-hash-injection-a",  "semantic_hash_prompt_injection_summary.json", "semantic_hash_prompt_injection_report.md", None),
    ("kernel-ablation",            "kernel_ablation_summary.json",   "kernel_ablation_report.md",  None),
    ("registry-scaling",           "registry_scaling_summary.json",  "registry_scaling_report.md", None),
    ("overload",                   "overload_summary.json",          "overload_report.md",         None),
    ("attack-extended",            "attack_extended_summary.json",   "attack_extended_report.md",  None),
    ("netlink-microbench",         "netlink_microbench_summary.json","netlink_microbench_report.md", None),
]


def headline_kernel_ablation(summary: Dict[str, Any]) -> str:
    modes = summary.get("mode_summaries", [])
    noop = summary.get("noop", {})
    if not modes:
        return "(no data)"
    by_name = {row.get("mode"): row for row in modes}
    full = by_name.get("full", {})
    skip_lookups = by_name.get("skip_lookups", {})
    noop_avg = noop.get("avg_ms", 0.0)
    return (
        f"full avg={full.get('avg_ms', 0.0):.6f} ms, "
        f"skip_lookups avg={skip_lookups.get('avg_ms', 0.0):.6f} ms, "
        f"noop floor={noop_avg:.6f} ms"
    )


def headline_registry_scaling(summary: Dict[str, Any]) -> str:
    points = summary.get("points") or summary.get("per_N") or summary.get("rows") or []
    if not points:
        return "(no data)"
    first = points[0]
    last = points[-1]
    return (
        f"N {first.get('N', '?')}→{last.get('N', '?')}: "
        f"lookup {first.get('lookup_avg_ms', '?')}→{last.get('lookup_avg_ms', '?')} ms"
    )


def headline_overload(summary: Dict[str, Any]) -> str:
    knees = summary.get("knees") or summary.get("knee_points") or []
    if not knees:
        return "(no data)"
    return f"knees: " + ", ".join(f"{k.get('system','?')}={k.get('knee_concurrency','?')}" for k in knees)


def headline_attack_extended(summary: Dict[str, Any]) -> str:
    parts: List[str] = []
    toctou = summary.get("toctou", {})
    if toctou:
        parts.append(f"toctou breach_rate={toctou.get('breach_rate', 0.0):.3%}")
    crossuid = summary.get("crossuid", {})
    if crossuid:
        parts.append(f"crossuid passed={crossuid.get('passed', 0)}/{crossuid.get('attempts', 0)}")
    fuzz = summary.get("fuzz", {})
    if fuzz:
        parts.append(f"fuzz oops={fuzz.get('oops_count', 0)} sent={fuzz.get('total_sent', 0)}")
    return " | ".join(parts) if parts else "(no data)"


HEADLINE_EXTRACTORS: Dict[str, Callable[[Dict[str, Any]], str]] = {
    "kernel-ablation": headline_kernel_ablation,
    "registry-scaling": headline_registry_scaling,
    "overload": headline_overload,
    "attack-extended": headline_attack_extended,
}


def discover_runs(root: Path) -> List[Tuple[str, Path]]:
    """Return list of (suite_name, run_dir) pairs, newest first within each suite."""
    results: List[Tuple[str, Path]] = []
    if not root.exists():
        return results
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        runs = sorted(
            (p for p in child.iterdir() if p.is_dir() and p.name.startswith("run-")),
            reverse=True,
        )
        for run in runs:
            results.append((child.name, run))
    return results


def load_json_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def render_index(root: Path) -> str:
    lines: List[str] = [
        "# linux-mcp experiment index",
        "",
        "Auto-generated aggregate of all experiment snapshots under",
        f"`{root}`. Each row links to the per-suite run directory and its",
        "headline summary. This file is a convenience index, not a re-run —",
        "individual suites remain the authoritative source for raw data.",
        "",
        "| suite | run | report | summary |",
        "|---|---|---|---|",
    ]

    discovered = discover_runs(root)
    for suite_name, run_dir in discovered:
        summary_name = None
        report_name = None
        for dirname, summary_file, report_file, _ in SUITES:
            if dirname == suite_name:
                summary_name = summary_file
                report_name = report_file
                break
        # Best-effort guess if not in known list
        if summary_name is None:
            candidates = list(run_dir.glob("*_summary.json"))
            summary_name = candidates[0].name if candidates else ""
        if report_name is None:
            candidates = list(run_dir.glob("*_report.md"))
            report_name = candidates[0].name if candidates else ""

        summary_path = run_dir / summary_name if summary_name else None
        report_path = run_dir / report_name if report_name else None

        headline = ""
        if summary_path is not None and summary_path.exists():
            summary = load_json_if_exists(summary_path)
            extractor = HEADLINE_EXTRACTORS.get(suite_name)
            if summary is not None and extractor is not None:
                try:
                    headline = extractor(summary)
                except Exception as exc:  # noqa: BLE001
                    headline = f"(extract failed: {exc})"

        report_link = f"[{report_name}]({run_dir / report_name})" if (report_path and report_path.exists()) else ""
        summary_link = f"[{summary_name}]({run_dir / summary_name})" if (summary_path and summary_path.exists()) else ""
        lines.append(f"| {suite_name} | {run_dir.name} | {report_link} | {summary_link} |")
        if headline:
            lines.append(f"| | | {headline} | |")

    if not discovered:
        lines.append("| _(empty)_ | | | |")

    lines += [
        "",
        "## Suite key",
        "",
        "| suite | scope |",
        "|---|---|",
        "| linux-mcp-paper-final-n5 / n30 | three-system main evaluation (latency, scalability, attacks) |",
        "| netlink-microbench / netlink-microbench-e | Generic Netlink bare vs full RTT |",
        "| semantic-hash-injection-a | runtime hash-substitution block rate on real planner |",
        "| kernel-ablation | E1 — per-stage kernel path cost ablation |",
        "| registry-scaling | E2 — tool-registry scaling (N=8..16k) |",
        "| overload | E3 — sustained tail-latency regime test |",
        "| attack-extended | E4 — TOCTOU / cross-uid / dumb fuzzer |",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render linux-mcp experiment index")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("experiment-results"),
        help="Directory containing per-suite run directories.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output markdown path (default: <root>/INDEX.md).",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    rendered = render_index(root)
    out = args.output.resolve() if args.output else root / "INDEX.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered, encoding="utf-8")
    print(f"[index] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
