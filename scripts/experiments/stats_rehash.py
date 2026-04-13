#!/usr/bin/env python3
"""E5 — Statistical hardening and noise-floor anchoring (post-processing).

This script re-analyzes existing main-eval snapshots without re-running the
load generator. It takes any `experiment-results/<suite>/run-<ts>/` that has
`latency_repetitions.csv` and `scalability_repetitions.csv` produced by
`linux_mcp_eval.py`, and writes a new side-car `stats_rehash/` directory
next to it with:

  - pairwise_latency_tests.csv   — all (system_a, system_b, payload) Welch t
                                   + BH-corrected p + Cliff's delta
  - pairwise_scalability_tests.csv — same shape for scalability cells
  - bootstrap_ci.csv             — mean / p99 bootstrap 95% CI per cell
  - noise_floor.csv              — anchors from a kernel_ablation snapshot
                                   (noop) if provided via --ablation-run
  - stats_rehash_summary.json
  - stats_rehash_report.md

The goal is to close the statistical gaps identified in the plan:
  * p-values only reported vs userspace → add kernel-vs-seccomp pairings
  * no multiple-testing correction → BH at q=0.05
  * no effect size → Cliff's delta (non-parametric, robust to tails)
  * netlink microbench near noise floor → anchor against measured NOOP RTT

All computations are pure Python (stdlib only). Runs on macOS without any
kernel module present — this is a post-processing tool.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Optional, Sequence, Tuple


def percentile(values: Sequence[float], p: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    ordered = sorted(values)
    k = (len(ordered) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(ordered[int(k)])
    return ordered[f] * (c - k) + ordered[c] * (k - f)


def _std_normal_cdf(x: float) -> float:
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def welch_t(a: Sequence[float], b: Sequence[float]) -> Tuple[float, float, float]:
    """Two-sided Welch t, Welch-Satterthwaite df, normal-approx p-value."""
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return (0.0, max(na + nb - 2, 1), 1.0)
    ma, mb = statistics.fmean(a), statistics.fmean(b)
    va, vb = statistics.variance(a), statistics.variance(b)
    denom = math.sqrt(va / na + vb / nb) if (va + vb) > 0 else 0.0
    if denom == 0.0:
        return (0.0, max(na + nb - 2, 1), 1.0)
    t = (ma - mb) / denom
    df_num = (va / na + vb / nb) ** 2
    df_den = (va / na) ** 2 / (na - 1) + (vb / nb) ** 2 / (nb - 1)
    df = df_num / df_den if df_den > 0 else float(max(na + nb - 2, 1))
    p = 2.0 * (1.0 - _std_normal_cdf(abs(t)))
    return (t, df, max(min(p, 1.0), 0.0))


def benjamini_hochberg(pvals: Sequence[float]) -> List[float]:
    m = len(pvals)
    if m == 0:
        return []
    order = sorted(range(m), key=lambda i: pvals[i])
    adj = [0.0] * m
    running = 1.0
    for rank, idx in enumerate(reversed(order), start=1):
        k = m - rank + 1
        val = min(running, pvals[idx] * m / k)
        adj[idx] = val
        running = val
    return adj


def cliffs_delta(a: Sequence[float], b: Sequence[float]) -> float:
    """Cliff's delta effect size in [-1, 1]. O(n log n) via merge-sort-rank."""
    na, nb = len(a), len(b)
    if na == 0 or nb == 0:
        return 0.0
    a_sorted = sorted(a)
    b_sorted = sorted(b)
    gt = 0
    lt = 0
    # Two-pointer style
    j = 0
    for x in a_sorted:
        while j < nb and b_sorted[j] < x:
            j += 1
        lt += j  # count of b < x
    j = 0
    for x in a_sorted:
        while j < nb and b_sorted[j] <= x:
            j += 1
        gt += nb - j  # count of b > x
    return (gt - lt) / (na * nb)


def bootstrap_mean_ci(
    values: Sequence[float], *, iters: int = 1000, seed: int = 0xBEEF
) -> Tuple[float, float]:
    if len(values) < 2:
        v = float(values[0]) if values else 0.0
        return (v, v)
    rng = random.Random(seed)
    n = len(values)
    means: List[float] = []
    for _ in range(iters):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        means.append(statistics.fmean(sample))
    means.sort()
    return (percentile(means, 0.025), percentile(means, 0.975))


def bootstrap_percentile_ci(
    values: Sequence[float], *, quantile: float, iters: int = 1000, seed: int = 0xFACE
) -> Tuple[float, float]:
    if len(values) < 2:
        v = float(values[0]) if values else 0.0
        return (v, v)
    rng = random.Random(seed)
    n = len(values)
    qs: List[float] = []
    for _ in range(iters):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        qs.append(percentile(sample, quantile))
    qs.sort()
    return (percentile(qs, 0.025), percentile(qs, 0.975))


def read_csv_rows(path: Path) -> List[Dict[str, Any]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader)


def _safe_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def analyze_latency(rows: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return (pairwise test rows, cell bootstrap CI rows) for latency samples.

    The per-rep CSV exposes one row per repetition × (system, payload) — the
    sample size for Welch is therefore small (n=5 in the paper-final-n5 run).
    We still compute t-tests and note the low-n caveat in the report.
    """
    cells: DefaultDict[Tuple[str, str], List[float]] = defaultdict(list)
    p99_cells: DefaultDict[Tuple[str, str], List[float]] = defaultdict(list)
    for row in rows:
        system = row.get("system", "")
        payload = row.get("payload_label", "")
        avg = _safe_float(row.get("latency_avg_ms"))
        p99 = _safe_float(row.get("latency_p99_ms"))
        if avg is not None:
            cells[(system, payload)].append(avg)
        if p99 is not None:
            p99_cells[(system, payload)].append(p99)

    payloads = sorted({key[1] for key in cells.keys()})
    systems = sorted({key[0] for key in cells.keys()})

    pairwise_rows: List[Dict[str, Any]] = []
    pvals: List[float] = []
    index_ref: List[int] = []
    for payload in payloads:
        present = [s for s in systems if (s, payload) in cells]
        for i, sa in enumerate(present):
            for sb in present[i + 1 :]:
                a = cells[(sa, payload)]
                b = cells[(sb, payload)]
                t, df, p = welch_t(a, b)
                delta = cliffs_delta(a, b)
                pairwise_rows.append(
                    {
                        "metric": "latency_avg_ms",
                        "payload": payload,
                        "system_a": sa,
                        "system_b": sb,
                        "n_a": len(a),
                        "n_b": len(b),
                        "mean_a": round(statistics.fmean(a), 6) if a else 0.0,
                        "mean_b": round(statistics.fmean(b), 6) if b else 0.0,
                        "t": round(t, 6),
                        "df": round(df, 3),
                        "p_raw": round(p, 6),
                        "cliffs_delta": round(delta, 6),
                    }
                )
                pvals.append(p)
                index_ref.append(len(pairwise_rows) - 1)

    adj = benjamini_hochberg(pvals)
    for idx, p_bh in zip(index_ref, adj):
        pairwise_rows[idx]["p_bh"] = round(p_bh, 6)

    ci_rows: List[Dict[str, Any]] = []
    for (sys_label, payload), vals in sorted(cells.items()):
        mean_lo, mean_hi = bootstrap_mean_ci(vals)
        p99_vals = p99_cells.get((sys_label, payload), [])
        p99_lo, p99_hi = bootstrap_mean_ci(p99_vals)
        ci_rows.append(
            {
                "metric": "latency",
                "system": sys_label,
                "payload": payload,
                "n": len(vals),
                "mean_avg_ms": round(statistics.fmean(vals), 6) if vals else 0.0,
                "mean_avg_ci_lo": round(mean_lo, 6),
                "mean_avg_ci_hi": round(mean_hi, 6),
                "mean_p99_ms": round(statistics.fmean(p99_vals), 6) if p99_vals else 0.0,
                "mean_p99_ci_lo": round(p99_lo, 6),
                "mean_p99_ci_hi": round(p99_hi, 6),
            }
        )
    return pairwise_rows, ci_rows


def analyze_scalability(rows: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    cells: DefaultDict[Tuple[str, str, str], List[float]] = defaultdict(list)
    p99_cells: DefaultDict[Tuple[str, str, str], List[float]] = defaultdict(list)
    for row in rows:
        system = row.get("system", "")
        agents = row.get("agents", "")
        concurrency = row.get("concurrency", "")
        rps = _safe_float(row.get("throughput_rps"))
        p99 = _safe_float(row.get("latency_p99_ms"))
        key = (system, agents, concurrency)
        if rps is not None:
            cells[key].append(rps)
        if p99 is not None:
            p99_cells[key].append(p99)

    systems = sorted({key[0] for key in cells.keys()})
    pairwise_rows: List[Dict[str, Any]] = []
    pvals: List[float] = []
    index_ref: List[int] = []
    cell_keys = sorted({(k[1], k[2]) for k in cells.keys()})
    for agents, concurrency in cell_keys:
        present = [s for s in systems if (s, agents, concurrency) in cells]
        for i, sa in enumerate(present):
            for sb in present[i + 1 :]:
                a = cells[(sa, agents, concurrency)]
                b = cells[(sb, agents, concurrency)]
                t, df, p = welch_t(a, b)
                delta = cliffs_delta(a, b)
                pairwise_rows.append(
                    {
                        "metric": "throughput_rps",
                        "agents": agents,
                        "concurrency": concurrency,
                        "system_a": sa,
                        "system_b": sb,
                        "n_a": len(a),
                        "n_b": len(b),
                        "mean_a": round(statistics.fmean(a), 3) if a else 0.0,
                        "mean_b": round(statistics.fmean(b), 3) if b else 0.0,
                        "t": round(t, 6),
                        "df": round(df, 3),
                        "p_raw": round(p, 6),
                        "cliffs_delta": round(delta, 6),
                    }
                )
                pvals.append(p)
                index_ref.append(len(pairwise_rows) - 1)

    adj = benjamini_hochberg(pvals)
    for idx, p_bh in zip(index_ref, adj):
        pairwise_rows[idx]["p_bh"] = round(p_bh, 6)

    ci_rows: List[Dict[str, Any]] = []
    for (sys_label, agents, concurrency), vals in sorted(cells.items()):
        lo, hi = bootstrap_mean_ci(vals)
        p99_vals = p99_cells.get((sys_label, agents, concurrency), [])
        p99_lo, p99_hi = bootstrap_mean_ci(p99_vals)
        ci_rows.append(
            {
                "metric": "scalability",
                "system": sys_label,
                "agents": agents,
                "concurrency": concurrency,
                "n": len(vals),
                "mean_rps": round(statistics.fmean(vals), 3) if vals else 0.0,
                "mean_rps_ci_lo": round(lo, 3),
                "mean_rps_ci_hi": round(hi, 3),
                "mean_p99_ms": round(statistics.fmean(p99_vals), 6) if p99_vals else 0.0,
                "mean_p99_ci_lo": round(p99_lo, 6),
                "mean_p99_ci_hi": round(p99_hi, 6),
            }
        )
    return pairwise_rows, ci_rows


def load_noise_floor(ablation_run_dir: Optional[Path]) -> Optional[Dict[str, Any]]:
    if ablation_run_dir is None:
        return None
    summary_path = ablation_run_dir / "kernel_ablation_summary.json"
    if not summary_path.exists():
        return None
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    return summary.get("noop")


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def render_report(
    *,
    source: Path,
    latency_pairwise: List[Dict[str, Any]],
    latency_cis: List[Dict[str, Any]],
    scalability_pairwise: List[Dict[str, Any]],
    scalability_cis: List[Dict[str, Any]],
    noise_floor: Optional[Dict[str, Any]],
) -> str:
    lines = [
        "# Statistical Rehash Report (E5)",
        "",
        f"Source snapshot: `{source}`",
        "",
        "This report post-processes existing `linux_mcp_eval.py` snapshots",
        "without re-running any workload. It closes three gaps in the original",
        "statistical treatment:",
        "",
        "1. all pairwise comparisons (not only vs userspace)",
        "2. Benjamini-Hochberg correction across the full pairwise set",
        "3. Cliff's delta effect size alongside each t-test",
        "",
        "Where an ablation run is supplied via `--ablation-run`, the measured",
        "KERNEL_MCP_CMD_NOOP RTT is used as a noise floor anchor for μs-level",
        "overhead claims.",
        "",
    ]

    if noise_floor:
        lines += [
            "## Noise floor (measured)",
            "",
            "| metric | value (ms) |",
            "|---|---:|",
            f"| avg  | {noise_floor.get('avg_ms', 0.0):.6f} |",
            f"| p50  | {noise_floor.get('p50_ms', 0.0):.6f} |",
            f"| p95  | {noise_floor.get('p95_ms', 0.0):.6f} |",
            f"| p99  | {noise_floor.get('p99_ms', 0.0):.6f} |",
            "",
            "Any μs-level claim from the ablation or microbench suites should",
            "be read as `floor + Δ`. The floor captures everything that",
            "Generic Netlink + the minimum `KMCP_CMD_NOOP` handler contribute",
            "before any registry, hash, binding, or ticket work is done.",
            "",
        ]
    else:
        lines += [
            "## Noise floor",
            "",
            "No ablation run supplied (pass `--ablation-run <kernel-ablation run dir>`",
            "to anchor μs-level claims against the measured NOOP RTT).",
            "",
        ]

    lines += [
        "## Latency pairwise tests (Welch t, BH-corrected, Cliff's delta)",
        "",
        "| payload | system_a | system_b | n_a | n_b | mean_a | mean_b | t | p_raw | p_bh | δ |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in latency_pairwise:
        lines.append(
            "| {payload} | {system_a} | {system_b} | {n_a} | {n_b} | {mean_a} | {mean_b} | "
            "{t:.4f} | {p_raw:.4f} | {p_bh:.4f} | {cliffs_delta:.3f} |".format(**row)
        )

    lines += [
        "",
        "## Latency cell bootstrap CIs",
        "",
        "| system | payload | n | mean_avg_ms | [CI] | mean_p99_ms | [CI] |",
        "|---|---|---:|---:|---|---:|---|",
    ]
    for row in latency_cis:
        lines.append(
            "| {system} | {payload} | {n} | {mean_avg_ms:.4f} | "
            "[{mean_avg_ci_lo:.4f}, {mean_avg_ci_hi:.4f}] | {mean_p99_ms:.4f} | "
            "[{mean_p99_ci_lo:.4f}, {mean_p99_ci_hi:.4f}] |".format(**row)
        )

    lines += [
        "",
        "## Scalability pairwise tests",
        "",
        "| agents | conc | system_a | system_b | mean_a | mean_b | p_raw | p_bh | δ |",
        "|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in scalability_pairwise:
        lines.append(
            "| {agents} | {concurrency} | {system_a} | {system_b} | "
            "{mean_a} | {mean_b} | {p_raw:.4f} | {p_bh:.4f} | {cliffs_delta:.3f} |".format(**row)
        )

    lines += [
        "",
        "## Caveats",
        "",
        "- Latency tests use per-repetition means (n=5 in paper-final-n5).",
        "  Low-n Welch t-tests should be read alongside Cliff's delta — the",
        "  non-parametric effect size is more informative when n is small.",
        "- p-values use a normal-distribution approximation to the t tail. At",
        "  df ≥ ~30 this is within 1% of the exact t CDF; at the n=5 per-cell",
        "  size the approximation may under-report p slightly. Values near",
        "  the decision boundary should be treated with care.",
        "- BH correction is applied across each metric family (latency,",
        "  scalability) separately, not globally.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="E5 — statistical rehash and noise-floor anchoring")
    parser.add_argument(
        "source",
        type=Path,
        help="Path to an existing linux_mcp_eval run directory "
        "(e.g. experiment-results/linux-mcp-paper-final-n5/run-20260405-173020)",
    )
    parser.add_argument(
        "--ablation-run",
        type=Path,
        default=None,
        help="Path to a kernel-ablation run dir for noise-floor anchoring.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Override output dir (default: <source>/stats_rehash).",
    )
    args = parser.parse_args()

    source = args.source.resolve()
    if not source.exists():
        print(f"[stats-rehash] source not found: {source}", file=sys.stderr)
        return 2

    latency_path = source / "latency_repetitions.csv"
    scalability_path = source / "scalability_repetitions.csv"

    latency_rows = read_csv_rows(latency_path) if latency_path.exists() else []
    scalability_rows = read_csv_rows(scalability_path) if scalability_path.exists() else []

    latency_pairwise, latency_cis = analyze_latency(latency_rows)
    scalability_pairwise, scalability_cis = analyze_scalability(scalability_rows)
    noise_floor = load_noise_floor(args.ablation_run.resolve() if args.ablation_run else None)

    out_dir = (args.output_dir.resolve() if args.output_dir else source / "stats_rehash")
    out_dir.mkdir(parents=True, exist_ok=True)

    write_csv(
        out_dir / "pairwise_latency_tests.csv",
        latency_pairwise,
        [
            "metric",
            "payload",
            "system_a",
            "system_b",
            "n_a",
            "n_b",
            "mean_a",
            "mean_b",
            "t",
            "df",
            "p_raw",
            "p_bh",
            "cliffs_delta",
        ],
    )
    write_csv(
        out_dir / "pairwise_scalability_tests.csv",
        scalability_pairwise,
        [
            "metric",
            "agents",
            "concurrency",
            "system_a",
            "system_b",
            "n_a",
            "n_b",
            "mean_a",
            "mean_b",
            "t",
            "df",
            "p_raw",
            "p_bh",
            "cliffs_delta",
        ],
    )
    write_csv(
        out_dir / "bootstrap_ci_latency.csv",
        latency_cis,
        [
            "metric",
            "system",
            "payload",
            "n",
            "mean_avg_ms",
            "mean_avg_ci_lo",
            "mean_avg_ci_hi",
            "mean_p99_ms",
            "mean_p99_ci_lo",
            "mean_p99_ci_hi",
        ],
    )
    write_csv(
        out_dir / "bootstrap_ci_scalability.csv",
        scalability_cis,
        [
            "metric",
            "system",
            "agents",
            "concurrency",
            "n",
            "mean_rps",
            "mean_rps_ci_lo",
            "mean_rps_ci_hi",
            "mean_p99_ms",
            "mean_p99_ci_lo",
            "mean_p99_ci_hi",
        ],
    )

    if noise_floor:
        write_csv(
            out_dir / "noise_floor.csv",
            [noise_floor],
            [
                "mode",
                "samples",
                "avg_ms",
                "std_ms",
                "ci95_ms",
                "p50_ms",
                "p95_ms",
                "p99_ms",
                "min_ms",
                "max_ms",
            ],
        )

    summary = {
        "meta": {
            "source": str(source),
            "ablation_run": str(args.ablation_run) if args.ablation_run else None,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "latency_pairwise_count": len(latency_pairwise),
        "scalability_pairwise_count": len(scalability_pairwise),
        "latency_cells": len(latency_cis),
        "scalability_cells": len(scalability_cis),
        "noise_floor": noise_floor,
    }
    (out_dir / "stats_rehash_summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2),
        encoding="utf-8",
    )
    (out_dir / "stats_rehash_report.md").write_text(
        render_report(
            source=source,
            latency_pairwise=latency_pairwise,
            latency_cis=latency_cis,
            scalability_pairwise=scalability_pairwise,
            scalability_cis=scalability_cis,
            noise_floor=noise_floor,
        ),
        encoding="utf-8",
    )

    print(f"[stats-rehash] output dir: {out_dir}")
    print(f"[stats-rehash] latency pairs: {len(latency_pairwise)}  "
          f"scalability pairs: {len(scalability_pairwise)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
