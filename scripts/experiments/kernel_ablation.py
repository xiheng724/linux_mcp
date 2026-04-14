#!/usr/bin/env python3
"""E1 — Kernel path stage ablation microbenchmark.

Measures the per-stage cost of the kernel_mcp TOOL_REQUEST path by toggling
`KERNEL_MCP_EXPERIMENT_*` flags one at a time. The kernel module is expected
to honor the following flags (see `kernel-mcp/include/uapi/linux/kernel_mcp_schema.h`):

    SKIP_LOOKUPS  - short-circuit before touching any table (existing flag)
    SKIP_HASH     - perform the full path but skip tool_hash comparison
    SKIP_BINDING  - perform the full path but skip binding check
    SKIP_TICKET   - perform the full path but skip approval-ticket consume

We treat the result as single-factor ablation: each mode differs from `full`
by exactly one disabled stage. Per-stage cost is reported as both the absolute
delta (`full - mode`) and the ratio `(full - mode) / full`.

Every repetition shuffles mode order to avoid thermal drift aligning with
treatment. We also publish a measured noise floor via KERNEL_MCP_CMD_NOOP
(see `noop_samples` in the output), which anchors any sub-microsecond claims.

Outputs land in `experiment-results/kernel-ablation/run-<UTC-ts>/`.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from client.kernel_mcp.schema import EXPERIMENT_FLAGS  # noqa: E402

try:
    from mcpd.netlink_client import KernelMcpNetlinkClient  # noqa: E402
except Exception:  # pragma: no cover — dry-run on macOS shouldn't fail import
    KernelMcpNetlinkClient = None  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
# Mode catalog
# --------------------------------------------------------------------------- #
#
# Earlier versions of this runner registered a single tool + single agent and
# toggled experiment flags under an otherwise-identical workload. That
# configuration made skip_hash / skip_binding / skip_ticket path-identical to
# full (the guard bodies are short-circuited by workload state), and the
# xarray / hashtable walks in skip_lookups were tiny because both tables only
# held one entry.
#
# The redesigned scenario set gives each mode a different bit of kernel work
# to bypass. Pairs of modes differ by exactly one stage and run under
# workload conditions that force that stage's body onto the execution path:
#
#   benign-at-scale / skip_lookups
#       Workload: N tools + M agents registered; each request randomly
#       picks one. The workload is otherwise legal, so full path executes
#       all mutexes + xa_load (across an N-entry radix tree) + agent
#       hashtable walk (across M entries in a 256-bucket table).
#       Delta (full - skip_lookups) measures registry + agent lookup cost
#       at realistic scale.
#
#   ticket_trigger_full / ticket_trigger_skip
#       Workload: a dedicated high-risk tool (risk_flags set in
#       KERNEL_MCP_APPROVAL_REQUIRED_FLAGS) is registered. Requests do
#       NOT supply a ticket_id, so the full path enters the
#       `if (risk_flags & APPROVAL_REQUIRED_FLAGS)` branch, calls
#       kernel_mcp_consume_approval_ticket (mutex + approval hashtable
#       lookup), and then kernel_mcp_issue_approval_ticket (mutex +
#       new ticket allocation). Decision is DEFER. With the SKIP_TICKET
#       flag, that whole branch is bypassed and decision is ALLOW.
#       Delta (ticket_full - ticket_skip) measures the approval-ticket
#       machinery cost directly.
#
#   skip_hash / skip_binding (methodology notes, not primary numbers)
#       We keep these so the report can document that the hash and
#       binding guard bodies are ~10 ns-level and fall below measurement
#       resolution on this hardware, rather than silently dropping them.
#
# Every benchmark request writes the EXPERIMENT_FLAGS attribute
# unconditionally (including for full mode with flags=0) so that the
# netlink transport path is symmetric across modes — see the 20260414
# nlattr-asymmetry bug fix in commit 50ee3cd.

SCENARIO_BENIGN_SMALL = "benign_small_registry"
SCENARIO_BENIGN_LARGE = "benign_large_registry"
SCENARIO_TICKET_TRIGGER = "ticket_trigger"


@dataclass(frozen=True)
class AblationMode:
    name: str
    experiment_flags: int
    scenario: str
    ok_decisions: Tuple[str, ...]
    description: str


MODES: Tuple[AblationMode, ...] = (
    AblationMode(
        name="full",
        experiment_flags=0,
        scenario=SCENARIO_BENIGN_LARGE,
        ok_decisions=("ALLOW",),
        description="Full arbitration path at realistic registry scale (N tools, M agents)",
    ),
    AblationMode(
        name="skip_lookups",
        experiment_flags=EXPERIMENT_FLAGS["SKIP_LOOKUPS"],
        scenario=SCENARIO_BENIGN_LARGE,
        ok_decisions=("ALLOW",),
        description="Early return before any tool/agent lookup (bypasses 2 mutex pairs + xa_load + hashtable walk)",
    ),
    AblationMode(
        name="ticket_trigger_full",
        experiment_flags=0,
        scenario=SCENARIO_TICKET_TRIGGER,
        ok_decisions=("DEFER",),
        description="High-risk tool, request without ticket -> runs kernel_mcp_consume_approval_ticket + issue_approval_ticket",
    ),
    AblationMode(
        name="ticket_trigger_skip",
        experiment_flags=EXPERIMENT_FLAGS["SKIP_TICKET"],
        scenario=SCENARIO_TICKET_TRIGGER,
        ok_decisions=("ALLOW",),
        description="Same workload as ticket_trigger_full but SKIP_TICKET bypasses the approval branch",
    ),
    AblationMode(
        name="skip_hash",
        experiment_flags=EXPERIMENT_FLAGS["SKIP_HASH"],
        scenario=SCENARIO_BENIGN_LARGE,
        ok_decisions=("ALLOW",),
        description="Methodology note: guard body is dead under valid hash, reported to document the path-identity caveat",
    ),
    AblationMode(
        name="skip_binding",
        experiment_flags=EXPERIMENT_FLAGS["SKIP_BINDING"],
        scenario=SCENARIO_BENIGN_LARGE,
        ok_decisions=("ALLOW",),
        description="Methodology note: guard body is dead under valid binding, reported to document the path-identity caveat",
    ),
)


# Paired deltas that correspond to a meaningful body cost.
# Each entry is (delta_label, baseline_mode, bypass_mode, explanation).
MEANINGFUL_STAGE_DELTAS: Tuple[Tuple[str, str, str, str], ...] = (
    (
        "registry+agent_lookup",
        "full",
        "skip_lookups",
        "two mutex pairs + xa_load(N=%(n_tools)s) + agent hashtable walk(M=%(n_agents)s)",
    ),
    (
        "approval_ticket_body",
        "ticket_trigger_full",
        "ticket_trigger_skip",
        "kernel_mcp_consume_approval_ticket + kernel_mcp_issue_approval_ticket (approval_lock + hashtable insert)",
    ),
)

# Stage deltas reported only for methodology transparency (body unreachable
# under benign workload -> measured delta is noise, not stage cost).
METHODOLOGY_NOTE_DELTAS: Tuple[Tuple[str, str, str, str], ...] = (
    (
        "hash_guard_body",
        "full",
        "skip_hash",
        "hash_mismatch guard body is dead under valid hash (delta = noise floor)",
    ),
    (
        "binding_guard_body",
        "full",
        "skip_binding",
        "binding_mismatch guard body is dead under valid binding (delta = noise floor)",
    ),
)

# One phase per delta we want to measure.
# Each phase runs its two modes in lock-step via measure_paired_real.
# Flagged as "kind" so the summary layer knows which table to put the
# resulting delta in.
PAIRED_PHASES: Tuple[Tuple[str, str, str, str, str, str], ...] = (
    # (phase_label, mode_a_name, mode_b_name, kind, scenario_hint, note_template)
    (
        "registry+agent_lookup",
        "full",
        "skip_lookups",
        "meaningful",
        SCENARIO_BENIGN_LARGE,
        "two mutex pairs + xa_load(N=%(n_tools)s) + agent hashtable walk(M=%(n_agents)s)",
    ),
    (
        "approval_ticket_body",
        "ticket_trigger_full",
        "ticket_trigger_skip",
        "meaningful",
        SCENARIO_TICKET_TRIGGER,
        "kernel_mcp_consume_approval_ticket + kernel_mcp_issue_approval_ticket (approval_lock + hashtable insert)",
    ),
    (
        "hash_guard_body",
        "full",
        "skip_hash",
        "methodology_note",
        SCENARIO_BENIGN_LARGE,
        "hash_mismatch guard body is dead under valid hash (delta = noise floor)",
    ),
    (
        "binding_guard_body",
        "full",
        "skip_binding",
        "methodology_note",
        SCENARIO_BENIGN_LARGE,
        "binding_mismatch guard body is dead under valid binding (delta = noise floor)",
    ),
)


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


def summarize(label: str, samples_ms: Sequence[float]) -> Dict[str, Any]:
    ordered = sorted(samples_ms)
    n = len(ordered)
    avg = statistics.fmean(ordered) if ordered else 0.0
    std = statistics.stdev(ordered) if n > 1 else 0.0
    ci = 1.96 * std / math.sqrt(n) if n > 1 else 0.0
    return {
        "mode": label,
        "samples": n,
        "avg_ms": round(avg, 6),
        "std_ms": round(std, 6),
        "ci95_ms": round(ci, 6),
        "p50_ms": round(percentile(ordered, 0.50), 6),
        "p95_ms": round(percentile(ordered, 0.95), 6),
        "p99_ms": round(percentile(ordered, 0.99), 6),
        "min_ms": round(ordered[0], 6) if ordered else 0.0,
        "max_ms": round(ordered[-1], 6) if ordered else 0.0,
    }


def bootstrap_mean_ci(
    samples: Sequence[float], *, iters: int = 1000, seed: int = 0xBEEF
) -> Tuple[float, float]:
    if len(samples) < 2:
        return (0.0, 0.0)
    rng = random.Random(seed)
    n = len(samples)
    means: List[float] = []
    for _ in range(iters):
        pick = [samples[rng.randrange(n)] for _ in range(n)]
        means.append(statistics.fmean(pick))
    means.sort()
    return (round(percentile(means, 0.025), 6), round(percentile(means, 0.975), 6))


def paired_bootstrap_delta_ci(
    a: Sequence[float], b: Sequence[float], *, iters: int = 1000, seed: int = 0xCAFE
) -> Tuple[float, float, float]:
    """Bootstrap CI on mean(a - b) using shared indices for paired samples."""
    n = min(len(a), len(b))
    if n < 2:
        return (0.0, 0.0, 0.0)
    pairs = list(zip(a[:n], b[:n]))
    rng = random.Random(seed)
    deltas: List[float] = []
    for _ in range(iters):
        sample = [pairs[rng.randrange(n)] for _ in range(n)]
        deltas.append(statistics.fmean(x - y for x, y in sample))
    deltas.sort()
    return (
        round(statistics.fmean(deltas), 6),
        round(percentile(deltas, 0.025), 6),
        round(percentile(deltas, 0.975), 6),
    )


def paired_delta_stats(
    delta_samples: Sequence[float], *, iters: int = 1000, seed: int = 0xCAFE
) -> Dict[str, float]:
    """Compute paired-delta statistics from a pre-aligned delta vector.

    Returns:
      mean, median, std, ci_lo, ci_hi (bootstrap 95% on mean),
      t_paired, p_paired (paired t-test against H0: mean=0).
    """
    n = len(delta_samples)
    if n < 2:
        return {
            "mean_ms": 0.0,
            "median_ms": 0.0,
            "std_ms": 0.0,
            "ci_lo": 0.0,
            "ci_hi": 0.0,
            "t_paired": 0.0,
            "p_paired": 1.0,
            "n": n,
        }
    mean_d = statistics.fmean(delta_samples)
    median_d = percentile(sorted(delta_samples), 0.5)
    std_d = statistics.stdev(delta_samples)
    # Bootstrap CI on the mean by resampling the delta vector directly.
    rng = random.Random(seed)
    boots: List[float] = []
    for _ in range(iters):
        sample = [delta_samples[rng.randrange(n)] for _ in range(n)]
        boots.append(statistics.fmean(sample))
    boots.sort()
    ci_lo = percentile(boots, 0.025)
    ci_hi = percentile(boots, 0.975)
    # Paired t-test against mean=0 (normal approximation for large n).
    se = std_d / math.sqrt(n)
    if se == 0.0:
        t = 0.0
        p = 1.0
    else:
        t = mean_d / se
        p = 2.0 * (1.0 - _std_normal_cdf(abs(t)))
    return {
        "mean_ms": round(mean_d, 6),
        "median_ms": round(median_d, 6),
        "std_ms": round(std_d, 6),
        "ci_lo": round(ci_lo, 6),
        "ci_hi": round(ci_hi, 6),
        "t_paired": round(t, 4),
        "p_paired": round(max(min(p, 1.0), 0.0), 6),
        "n": n,
    }


def welch_t(a: Sequence[float], b: Sequence[float]) -> Tuple[float, float]:
    """Two-sided Welch t statistic and approximate p-value (no scipy)."""
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return (0.0, 1.0)
    ma, mb = statistics.fmean(a), statistics.fmean(b)
    va, vb = statistics.variance(a), statistics.variance(b)
    denom = math.sqrt(va / na + vb / nb) if (va + vb) > 0 else 0.0
    if denom == 0.0:
        return (0.0, 1.0)
    t = (ma - mb) / denom
    # Welch-Satterthwaite df
    df_num = (va / na + vb / nb) ** 2
    df_den = (va / na) ** 2 / (na - 1) + (vb / nb) ** 2 / (nb - 1)
    df = df_num / df_den if df_den > 0 else max(na + nb - 2, 1)
    # Two-sided normal-approximation p-value (OK for df > ~30)
    p = 2.0 * (1.0 - _std_normal_cdf(abs(t)))
    return (round(t, 6), round(max(min(p, 1.0), 0.0), 6))


def _std_normal_cdf(x: float) -> float:
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def benjamini_hochberg(pvals: Sequence[float], *, q: float = 0.05) -> List[float]:
    """Return BH-adjusted p-values in the same order as input."""
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
    return [round(v, 6) for v in adj]


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def maybe_import_plotting() -> Any:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except Exception:
        return None


def generate_plots(
    run_dir: Path,
    *,
    mode_summaries: List[Dict[str, Any]],
    stage_deltas: List[Dict[str, Any]],
) -> None:
    plt = maybe_import_plotting()
    plots_dir = run_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    if plt is None:
        (run_dir / "plots_status.json").write_text(
            json.dumps({"plots_generated": False, "reason": "matplotlib unavailable"}, indent=2),
            encoding="utf-8",
        )
        return

    labels = [row["mode"] for row in mode_summaries]
    means = [row["avg_ms"] for row in mode_summaries]
    ci = [row["ci95_ms"] for row in mode_summaries]

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    xs = list(range(len(labels)))
    ax.bar(xs, means, yerr=ci, color="#4C78A8", alpha=0.85, capsize=4)
    ax.set_xticks(xs)
    ax.set_xticklabels(labels, rotation=20, ha="right")
    ax.set_ylabel("RTT mean (ms)")
    ax.set_title("Per-mode kernel path RTT (lower is cheaper)")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(plots_dir / "figure_ablation_mean_rtt.pdf")
    plt.close(fig)

    if stage_deltas:
        stage_labels = [row["stage"] for row in stage_deltas]
        # Use delta_avg_ms (falls back to delta_ms for back-compat).
        deltas_us = [
            row.get("delta_avg_ms", row.get("delta_ms", 0.0)) * 1000.0
            for row in stage_deltas
        ]
        lo_us = [row["delta_ci_lo"] * 1000.0 for row in stage_deltas]
        hi_us = [row["delta_ci_hi"] * 1000.0 for row in stage_deltas]
        err_lo = [max(d - l, 0.0) for d, l in zip(deltas_us, lo_us)]
        err_hi = [max(h - d, 0.0) for d, h in zip(deltas_us, hi_us)]
        fig, ax = plt.subplots(figsize=(7.5, 4.5))
        xs = list(range(len(stage_labels)))
        ax.bar(xs, deltas_us, yerr=[err_lo, err_hi], color="#E45756", alpha=0.85, capsize=4)
        ax.set_xticks(xs)
        ax.set_xticklabels(stage_labels, rotation=15, ha="right")
        ax.set_ylabel("Per-stage body cost: baseline − bypass (μs)")
        ax.set_title("Per-stage kernel cost (paired bootstrap 95% CI)")
        ax.grid(axis="y", alpha=0.25)
        ax.axhline(0, color="#444", linewidth=0.8)
        fig.tight_layout()
        fig.savefig(plots_dir / "figure_ablation_stage_delta.pdf")
        plt.close(fig)

    (run_dir / "plots_status.json").write_text(
        json.dumps({"plots_generated": True, "reason": ""}, indent=2),
        encoding="utf-8",
    )


def render_report(summary: Dict[str, Any]) -> str:
    meta = summary["meta"]
    # The 'full' mode is the baseline for the total arbitration cost headline.
    full_row = next((r for r in summary["mode_summaries"] if r["mode"] == "full"), None)
    full_p50 = full_row["p50_ms"] if full_row else 0.0
    noop_p50 = summary["noop"]["p50_ms"]
    total_arb_p50 = full_p50 - noop_p50

    lines = [
        "# Kernel Path Ablation (E1)",
        "",
        "## Setup",
        "",
        f"- reps: {meta['reps']}",
        f"- pairs per phase (benign): {meta['requests_per_cell']}",
        f"- pairs per phase (ticket_trigger): {meta.get('ticket_requests', meta['requests_per_cell'] // 10)}",
        f"- benign registry scale: {meta['n_tools_registered']} tools, {meta['n_agents_registered']} agents",
        "- measurement method: **paired**, request-level alternation inside each phase",
        "- order randomization: per-rep shuffle of phase list",
        f"- dry-run: {meta['dry_run']}",
        "",
        "## Environment",
        "",
        "VMware guest / Apple aarch64 host / 4 vCPU / 8 GB. Absolute numbers",
        "must be read together with the measured noise floor (noop).",
        "",
        "## Scenarios",
        "",
    ]
    for mode in summary["modes"]:
        lines.append(f"- **{mode['name']}** ({mode['scenario']}, flags=0x{mode['experiment_flags']:x}): {mode['description']}")
    lines += [
        "",
        "## Per-mode RTT summary",
        "",
        "| mode | n | avg_ms | p50 | p95 | p99 | std |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary["mode_summaries"]:
        lines.append(
            "| {mode} | {samples} | {avg_ms:.6f} | {p50_ms:.6f} | {p95_ms:.6f} | "
            "{p99_ms:.6f} | {std_ms:.6f} |".format(**row)
        )

    lines += [
        "",
        "## Noise floor (KERNEL_MCP_CMD_NOOP)",
        "",
        "| metric | value (ms) |",
        "|---|---:|",
        f"| avg  | {summary['noop']['avg_ms']:.6f} |",
        f"| p50  | {summary['noop']['p50_ms']:.6f} |",
        f"| p95  | {summary['noop']['p95_ms']:.6f} |",
        f"| p99  | {summary['noop']['p99_ms']:.6f} |",
        "",
        "## Kernel arbitration total cost (primary number)",
        "",
        f"- full p50 (benign_large scenario): **{full_p50:.6f} ms**",
        f"- noop p50 (Generic Netlink floor): **{noop_p50:.6f} ms**",
        f"- **arbitration = full_p50 − noop_p50 = {total_arb_p50:.6f} ms**",
        "",
        "The median (p50) is preferred over the mean because VMware preemption",
        "events occasionally inject multi-millisecond outliers into single",
        "samples. The noise floor (noop) captures everything Generic Netlink",
        "and the minimum `KMCP_CMD_NOOP` handler contribute before any",
        "registry, hash, binding, or ticket work is done. The full-path",
        "measurement is taken at realistic registry scale",
        f"({meta['n_tools_registered']} tools in the xarray,",
        f"{meta['n_agents_registered']} agents in the hashtable), so the",
        "xa_load and agent-lookup walks exercise real data structures instead",
        "of single-entry trivial cases.",
        "",
        "## Per-stage body cost (paired ablation)",
        "",
        "Each row below was produced by a **paired measurement**: within a",
        "single benchmark phase, the baseline mode and the bypass mode were",
        "alternated request-by-request inside a tight loop, so the two",
        "samples in each pair are collected ~μs apart and share the same",
        "scheduler state, cache residency, and jiffies tick. The delta",
        "column is the mean of `baseline[i] - bypass[i]` across all pairs,",
        "not the difference of two independent means — which is why the",
        "bootstrap CIs are much tighter than a naive sequential ablation",
        "would produce. Hypervisor-level rep drift (the source of the ~200",
        "ns run-to-run shift we observed in earlier runs) cancels out",
        "inside the paired difference.",
        "",
        "| stage | baseline | bypass | n_pairs | Δ_avg (μs) | Δ_p50 (μs) | bootstrap 95% CI (μs) | t_paired | p_paired | note |",
        "|---|---|---|---:|---:|---:|---|---:|---:|---|",
    ]
    for row in summary["meaningful_stage_deltas"]:
        lines.append(
            "| {stage} | {baseline_mode} | {bypass_mode} | {n_pairs} | "
            "{d_avg_us:+.3f} | {d_p50_us:+.3f} | "
            "[{ci_lo_us:+.3f}, {ci_hi_us:+.3f}] | "
            "{t:+.2f} | {p:.3g} | {note} |".format(
                stage=row["stage"],
                baseline_mode=row["baseline_mode"],
                bypass_mode=row["bypass_mode"],
                n_pairs=row["n_pairs"],
                d_avg_us=row["delta_avg_ms"] * 1000.0,
                d_p50_us=row["delta_p50_ms"] * 1000.0,
                ci_lo_us=row["delta_ci_lo"] * 1000.0,
                ci_hi_us=row["delta_ci_hi"] * 1000.0,
                t=row["t_paired"],
                p=row["p_paired"],
                note=row["note"],
            )
        )

    lines += [
        "",
        "## Methodology-note deltas (not paper numbers)",
        "",
        "`hash_guard_body` and `binding_guard_body` are reported for transparency",
        "only. In any benign-credential benchmark workload, the `if (hash_mismatch",
        "&& ...)` and `if (binding != registered)` guard bodies in",
        "`kernel_mcp_cmd_tool_request` are short-circuited by the workload state",
        "before the experiment flag is consulted; full and skip_{hash,binding}",
        "therefore execute identical kernel code paths, and any measured delta",
        "between them is noise on the same code, not a stage cost. Under",
        "paired measurement this noise should cancel to within a few tens of",
        "nanoseconds, so the rows below are a consistency check on the paired",
        "method itself — if any of them reports a large non-zero delta,",
        "something in the measurement is broken.",
        "",
        "| stage | baseline | bypass | n_pairs | Δ_avg (μs) | Δ_p50 (μs) | bootstrap 95% CI (μs) | t_paired | p_paired | note |",
        "|---|---|---|---:|---:|---:|---|---:|---:|---|",
    ]
    for row in summary["methodology_note_deltas"]:
        lines.append(
            "| {stage} | {baseline_mode} | {bypass_mode} | {n_pairs} | "
            "{d_avg_us:+.3f} | {d_p50_us:+.3f} | "
            "[{ci_lo_us:+.3f}, {ci_hi_us:+.3f}] | "
            "{t:+.2f} | {p:.3g} | {note} |".format(
                stage=row["stage"],
                baseline_mode=row["baseline_mode"],
                bypass_mode=row["bypass_mode"],
                n_pairs=row["n_pairs"],
                d_avg_us=row["delta_avg_ms"] * 1000.0,
                d_p50_us=row["delta_p50_ms"] * 1000.0,
                ci_lo_us=row["delta_ci_lo"] * 1000.0,
                ci_hi_us=row["delta_ci_hi"] * 1000.0,
                t=row["t_paired"],
                p=row["p_paired"],
                note=row["note"],
            )
        )

    lines += [
        "",
        "## Paired t-tests (BH-corrected across all four phases)",
        "",
        "| stage | baseline | bypass | n_pairs | t | p_raw | p_bh |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for row in summary["pairwise_tests"]:
        lines.append(
            "| {stage} | {baseline} | {bypass} | {n_pairs} | "
            "{t:+.4f} | {p_raw:.6f} | {p_bh:.6f} |".format(**row)
        )

    lines += [
        "",
        "## Interpretation",
        "",
        "The redesigned ablation (vs earlier runs that used a single-tool,",
        "single-agent registry with only legal inputs) targets the two stages",
        "whose guard bodies actually execute in the benchmark: the",
        "registry+agent lookup under realistic scale, and the approval-ticket",
        "machinery under a high-risk tool. All other skip_* flags are kept",
        "for methodology transparency only — their deltas against full under",
        "benign inputs are measurements of the same kernel path twice, not",
        "per-stage cost.",
        "",
        f"On this aarch64 VMware guest, the full-path arbitration at",
        f"{meta['n_tools_registered']}-tool / {meta['n_agents_registered']}-agent scale",
        f"is {total_arb_p50*1000.0:.2f} μs above a {noop_p50*1000.0:.2f} μs Generic",
        "Netlink floor. Of that budget, the measured per-stage contributions",
        "are in the `meaningful_stage_deltas` table above. The residual that",
        "does not appear in any stage delta is attributable to reply-skb",
        "construction (`kernel_mcp_reply_tool_decision`, 5 × `nla_put_*` +",
        "`genlmsg_reply`) — this is the dominant non-decomposable cost.",
        "",
        "### Secondary finding: O(n) purge scan in approval-ticket issuance",
        "",
        "The `approval_ticket_body` delta reported above is **not** the pure",
        "intrinsic cost of the consume + issue logic. Tracing",
        "`kernel_mcp_issue_approval_ticket` in `kernel-mcp/src/kernel_mcp_main.c`",
        "reveals that every ticket issuance calls",
        "`kernel_mcp_purge_expired_tickets_locked()`, which iterates the",
        "full 256-bucket approval hashtable and checks `expires_jiffies`",
        "on every live entry. The default approval TTL is 300 seconds, so",
        "over a ~1-minute E1 run nothing in the table ever expires — the",
        "scan cost therefore grows linearly with the total number of",
        "tickets issued by the benchmark.",
        "",
        "The runner caps ticket_trigger samples at `--ticket-requests` (default",
        "100, vs 10,000 for benign modes) specifically to keep this O(n)",
        "amplification small relative to the intrinsic issue+consume cost.",
        "Even at this reduced sample count, some linear-growth contamination",
        "remains; the figure should therefore be read as an **upper bound**",
        "on the approval-ticket body cost under steady-state mcpd operation,",
        "where tickets are decided and consumed quickly rather than",
        "accumulating. A kernel-side optimization — moving the expiry scan",
        "to the existing periodic `kernel_mcp_ticket_cleanup_timer` instead",
        "of running it inline on every issuance — would eliminate the O(n)",
        "component entirely. We flag this as a secondary microbench finding,",
        "not a performance-characteristic claim about the kernel arbitration",
        "fast path.",
        "",
    ]
    return "\n".join(lines)


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    binding_hash: int
    binding_epoch: int


@dataclass(frozen=True)
class ToolRecord:
    tool_id: int
    tool_hash: str


def measure_mode_real(
    client: Any,
    *,
    mode: AblationMode,
    requests: int,
    req_start: int,
    seed: int,
    pool: Dict[str, Any],
) -> List[float]:
    """Drive `requests` calls of tool_request and return elapsed-ms samples.

    `pool` carries per-scenario state set up by setup_scenarios():
      - "benign": {"agents": [AgentRecord], "tools": [ToolRecord]}
      - "ticket_trigger": {"agent": AgentRecord, "tool": ToolRecord}

    For benign scenarios we uniformly pick one agent + one tool from the
    registered pool per request, so the kernel-side xa_load and
    kernel_mcp_find_agent_locked walks exercise a real hot set instead of a
    single-entry table. For ticket_trigger we always hit the one high-risk
    tool the setup phase registered.
    """
    samples: List[float] = []
    rnd = random.Random(seed)
    scenario = mode.scenario
    ok_decisions = set(mode.ok_decisions)

    if scenario == SCENARIO_TICKET_TRIGGER:
        agents = [pool["ticket_agent"]]
        tools = [pool["ticket_tool"]]
    else:
        agents = pool["benign_agents"]
        tools = pool["benign_tools"]
    n_agents = len(agents)
    n_tools = len(tools)
    if n_agents == 0 or n_tools == 0:
        raise RuntimeError(
            f"measure_mode_real: empty pool for scenario={scenario}"
        )

    for idx in range(requests):
        agent = agents[rnd.randrange(n_agents)] if n_agents > 1 else agents[0]
        tool = tools[rnd.randrange(n_tools)] if n_tools > 1 else tools[0]
        t0 = time.perf_counter()
        decision = client.tool_request(
            req_id=req_start + idx,
            agent_id=agent.agent_id,
            binding_hash=agent.binding_hash,
            binding_epoch=agent.binding_epoch,
            tool_id=tool.tool_id,
            tool_hash=tool.tool_hash,
            experiment_flags=mode.experiment_flags,
        )
        elapsed = (time.perf_counter() - t0) * 1000.0
        if decision.decision not in ok_decisions:
            raise RuntimeError(
                f"measure_mode_real mode={mode.name} unexpected decision "
                f"{decision.decision} (reason={decision.reason}); "
                f"expected one of {sorted(ok_decisions)}"
            )
        samples.append(elapsed)
    return samples


def measure_noop_real(client: Any, *, requests: int, req_start: int) -> List[float]:
    samples: List[float] = []
    for idx in range(requests):
        t0 = time.perf_counter()
        client.noop(req_id=req_start + idx)
        samples.append((time.perf_counter() - t0) * 1000.0)
    return samples


def measure_mode_dry(
    *,
    mode_name: str,
    requests: int,
    seed: int,
) -> List[float]:
    """Synthetic latency generator for macOS dry-runs.

    Per-mode centers are picked so the delta pairs land roughly where we
    expect them on the VM: skip_lookups saves ~400 ns relative to full,
    ticket_trigger_full pays ~1.5 μs more than ticket_trigger_skip, and
    the hash/binding methodology modes are indistinguishable from full.
    """
    rng = random.Random(seed)
    centers = {
        "full": 0.008,
        "skip_lookups": 0.0076,
        "ticket_trigger_full": 0.0095,
        "ticket_trigger_skip": 0.008,
        "skip_hash": 0.008,
        "skip_binding": 0.008,
    }
    center = centers.get(mode_name, 0.008)
    return [max(center + rng.gauss(0.0, 0.0004), 0.0005) for _ in range(requests)]


def measure_paired_real(
    client: Any,
    *,
    mode_a: AblationMode,
    mode_b: AblationMode,
    pair_requests: int,
    req_start: int,
    seed: int,
    pool: Dict[str, Any],
) -> Tuple[List[float], List[float]]:
    """Interleave tool_request calls between two modes to cancel VM jitter.

    The classic trap in microbenching two kernel paths on a shared VM is
    that rep-level timing drift (hypervisor scheduler window, NMI ticks,
    vCPU migration) moves both modes' means around by more than the
    signal you're trying to measure. We dodge it here by alternating
    request-by-request: mode A sample i and mode B sample i are
    measured ~μs apart, so they share the same scheduler state, same
    cache residency, same jiffies tick.

    Paired bootstrap / t-tests on (a[i], b[i]) then recover a much
    tighter CI than mean(a) - mean(b) would.

    Returns two lists of equal length `pair_requests`, one per mode,
    aligned by index so `a[i]` and `b[i]` are a matched pair.
    """
    a_samples: List[float] = []
    b_samples: List[float] = []
    a_samples_append = a_samples.append  # bind locally for tight loop
    b_samples_append = b_samples.append

    a_ok = set(mode_a.ok_decisions)
    b_ok = set(mode_b.ok_decisions)
    a_flags = mode_a.experiment_flags
    b_flags = mode_b.experiment_flags
    a_scenario = mode_a.scenario
    b_scenario = mode_b.scenario

    if a_scenario != b_scenario:
        raise RuntimeError(
            f"measure_paired_real: modes {mode_a.name} and {mode_b.name} "
            f"target different scenarios ({a_scenario} vs {b_scenario}); "
            f"paired measurement is only meaningful within a single scenario"
        )

    if a_scenario == SCENARIO_TICKET_TRIGGER:
        agents = [pool["ticket_agent"]]
        tools = [pool["ticket_tool"]]
    else:
        agents = pool["benign_agents"]
        tools = pool["benign_tools"]
    n_agents = len(agents)
    n_tools = len(tools)
    if n_agents == 0 or n_tools == 0:
        raise RuntimeError(
            f"measure_paired_real: empty pool for scenario={a_scenario}"
        )

    rnd = random.Random(seed)
    tr = client.tool_request
    perf = time.perf_counter

    # Randomize the A-first vs B-first ordering per pair so any
    # within-pair ordering bias (e.g. cache warm-up on the first call)
    # is split symmetrically across both modes.
    order_bits = [rnd.random() < 0.5 for _ in range(pair_requests)]

    for i in range(pair_requests):
        # Share agent/tool choice between the paired samples so the only
        # thing that differs between A and B is the experiment_flags value.
        if n_agents > 1:
            agent = agents[rnd.randrange(n_agents)]
        else:
            agent = agents[0]
        if n_tools > 1:
            tool = tools[rnd.randrange(n_tools)]
        else:
            tool = tools[0]

        req_id_a = req_start + 2 * i
        req_id_b = req_start + 2 * i + 1
        a_first = order_bits[i]

        if a_first:
            t0 = perf()
            dec_a = tr(
                req_id=req_id_a, agent_id=agent.agent_id,
                binding_hash=agent.binding_hash, binding_epoch=agent.binding_epoch,
                tool_id=tool.tool_id, tool_hash=tool.tool_hash,
                experiment_flags=a_flags,
            )
            t1 = perf()
            dec_b = tr(
                req_id=req_id_b, agent_id=agent.agent_id,
                binding_hash=agent.binding_hash, binding_epoch=agent.binding_epoch,
                tool_id=tool.tool_id, tool_hash=tool.tool_hash,
                experiment_flags=b_flags,
            )
            t2 = perf()
            a_ms = (t1 - t0) * 1000.0
            b_ms = (t2 - t1) * 1000.0
        else:
            t0 = perf()
            dec_b = tr(
                req_id=req_id_b, agent_id=agent.agent_id,
                binding_hash=agent.binding_hash, binding_epoch=agent.binding_epoch,
                tool_id=tool.tool_id, tool_hash=tool.tool_hash,
                experiment_flags=b_flags,
            )
            t1 = perf()
            dec_a = tr(
                req_id=req_id_a, agent_id=agent.agent_id,
                binding_hash=agent.binding_hash, binding_epoch=agent.binding_epoch,
                tool_id=tool.tool_id, tool_hash=tool.tool_hash,
                experiment_flags=a_flags,
            )
            t2 = perf()
            b_ms = (t1 - t0) * 1000.0
            a_ms = (t2 - t1) * 1000.0

        if dec_a.decision not in a_ok:
            raise RuntimeError(
                f"measure_paired_real mode_a={mode_a.name} unexpected decision "
                f"{dec_a.decision} (reason={dec_a.reason}); "
                f"expected one of {sorted(a_ok)}"
            )
        if dec_b.decision not in b_ok:
            raise RuntimeError(
                f"measure_paired_real mode_b={mode_b.name} unexpected decision "
                f"{dec_b.decision} (reason={dec_b.reason}); "
                f"expected one of {sorted(b_ok)}"
            )
        a_samples_append(a_ms)
        b_samples_append(b_ms)

    return a_samples, b_samples


def measure_paired_dry(
    *,
    mode_a_name: str,
    mode_b_name: str,
    pair_requests: int,
    seed: int,
) -> Tuple[List[float], List[float]]:
    """Synthetic paired-sample generator for macOS dry-runs.

    Shares a per-pair jitter component between the two modes so the
    paired delta distribution is tighter than (mean_a - mean_b), which
    is exactly the property a real paired measurement should have.
    """
    rng = random.Random(seed)
    centers = {
        "full": 0.008,
        "skip_lookups": 0.0076,
        "ticket_trigger_full": 0.0095,
        "ticket_trigger_skip": 0.008,
        "skip_hash": 0.008,
        "skip_binding": 0.008,
    }
    c_a = centers.get(mode_a_name, 0.008)
    c_b = centers.get(mode_b_name, 0.008)
    a_samples: List[float] = []
    b_samples: List[float] = []
    for _ in range(pair_requests):
        # Shared per-pair jitter (big), private per-call jitter (small).
        shared = rng.gauss(0.0, 0.0004)
        a_samples.append(max(c_a + shared + rng.gauss(0.0, 0.00005), 0.0005))
        b_samples.append(max(c_b + shared + rng.gauss(0.0, 0.00005), 0.0005))
    return a_samples, b_samples


def setup_scenarios(
    client: Any,
    *,
    n_tools: int,
    n_agents: int,
    base_tool_id: int,
    ticket_tool_id: int,
    ticket_risk_flags: int,
    base_tool_hash: str,
    base_binding_hash: int,
) -> Dict[str, Any]:
    """Register a realistic-scale pool + one dedicated high-risk tool.

    Returns a dict with:
      - "benign_tools":  list[ToolRecord] of size n_tools, each with a
                         unique tool_id and tool_hash "abcd%06d"
      - "benign_agents": list[AgentRecord] of size n_agents, each with a
                         unique agent_id "ablation-agent-%04d"
      - "ticket_tool":   ToolRecord for the high-risk tool that triggers
                         the approval-ticket body
      - "ticket_agent":  an AgentRecord reused for ticket_trigger requests

    Uses risk_flags=0 for every benign tool so the full path runs the
    hash + binding guards but falls through their unreachable bodies.
    The ticket tool uses ticket_risk_flags (which must be a bit in
    KERNEL_MCP_APPROVAL_REQUIRED_FLAGS, e.g. FILESYSTEM_DELETE=1<<1=2).
    """
    benign_tools: List[ToolRecord] = []
    for i in range(n_tools):
        tool_id = base_tool_id + i
        tool_hash = f"abcd{i:06d}"
        client.register_tool(
            tool_id=tool_id,
            name=f"ablation_tool_{i:04d}",
            risk_flags=0,
            tool_hash=tool_hash,
        )
        benign_tools.append(ToolRecord(tool_id=tool_id, tool_hash=tool_hash))

    benign_agents: List[AgentRecord] = []
    for i in range(n_agents):
        agent_id = f"ablation-agent-{i:04d}"
        binding_hash = base_binding_hash + i
        client.register_agent(
            agent_id,
            pid=1,
            uid=0,
            binding_hash=binding_hash,
            binding_epoch=1,
        )
        benign_agents.append(
            AgentRecord(agent_id=agent_id, binding_hash=binding_hash, binding_epoch=1)
        )

    # Dedicated high-risk tool for the ticket_trigger scenario.
    ticket_tool_hash = "deadc0de"
    client.register_tool(
        tool_id=ticket_tool_id,
        name="ablation_ticket_tool",
        risk_flags=ticket_risk_flags,
        tool_hash=ticket_tool_hash,
    )
    ticket_tool = ToolRecord(tool_id=ticket_tool_id, tool_hash=ticket_tool_hash)

    # Dedicated agent for ticket_trigger (reuses benign_agents[0] identity
    # space but with its own binding so the paths do not cross).
    ticket_agent_id = "ablation-ticket-agent"
    ticket_binding = base_binding_hash - 1
    client.register_agent(
        ticket_agent_id,
        pid=1,
        uid=0,
        binding_hash=ticket_binding,
        binding_epoch=1,
    )
    ticket_agent = AgentRecord(
        agent_id=ticket_agent_id,
        binding_hash=ticket_binding,
        binding_epoch=1,
    )

    return {
        "benign_tools": benign_tools,
        "benign_agents": benign_agents,
        "ticket_tool": ticket_tool,
        "ticket_agent": ticket_agent,
    }


def run_ablation(
    args: argparse.Namespace,
    run_dir: Path,
) -> Dict[str, Any]:
    per_mode: Dict[str, List[float]] = {m.name: [] for m in MODES}
    per_rep_rows: List[Dict[str, Any]] = []
    rng = random.Random(args.seed)

    # FILESYSTEM_DELETE (1 << 1 = 2) is inside KERNEL_MCP_APPROVAL_REQUIRED_FLAGS,
    # so registering a tool with this risk flag forces every TOOL_REQUEST
    # against it to take the approval-ticket branch.
    TICKET_RISK_FLAGS = 1 << 1

    pool: Dict[str, Any] = {}
    if args.dry_run:
        client = None
    else:
        if KernelMcpNetlinkClient is None:
            raise RuntimeError(
                "KernelMcpNetlinkClient unavailable in this environment; "
                "use --dry-run for non-Linux hosts."
            )
        client = KernelMcpNetlinkClient()
        # Reset any stale state from a previous run on this live kernel
        # so our base_tool_id space is clean.
        try:
            client.reset_tools()
        except Exception:
            pass
        pool = setup_scenarios(
            client,
            n_tools=args.n_tools,
            n_agents=args.n_agents,
            base_tool_id=args.tool_id,
            ticket_tool_id=args.tool_id + args.n_tools + 1,
            ticket_risk_flags=TICKET_RISK_FLAGS,
            base_tool_hash=args.tool_hash,
            base_binding_hash=args.binding_hash,
        )
        # Warmup on the full path so Python, netlink socket, and kernel
        # hot-path caches are primed before the measurement window opens.
        measure_mode_real(
            client,
            mode=MODES[0],
            requests=args.warmup_requests,
            req_start=10,
            seed=args.seed + 1,
            pool=pool,
        )

    # Paired measurement strategy.
    #
    # Each phase in PAIRED_PHASES runs a tight alternating loop over
    # two modes (one request of mode A, one of mode B, repeated) inside
    # measure_paired_real. Both samples in a pair share the same ~μs
    # window of VM state (scheduler, cache residency, jiffies tick),
    # so their difference a[i]-b[i] is a much tighter estimator of the
    # stage body cost than mean(A) - mean(B) would be under rep-level
    # hypervisor drift.
    #
    # ticket_trigger phases still run far fewer pairs than benign phases.
    # Every ticket_trigger_full request makes the kernel issue a fresh
    # approval ticket via kernel_mcp_issue_approval_ticket, which in turn
    # calls kernel_mcp_purge_expired_tickets_locked() that scans all
    # 256 buckets of the approval hashtable. TTL is 300s and nothing
    # expires during a ~minute-scale E1 run, so the scan cost grows
    # linearly in total live-ticket count. Default --ticket-requests=100
    # caps each ticket phase at 100 pairs/rep and bounds the purge-scan
    # contamination.
    def pair_count_for(scenario: str) -> int:
        if scenario == SCENARIO_TICKET_TRIGGER:
            if args.ticket_requests > 0:
                return args.ticket_requests
            return max(1, args.requests // 10)
        return args.requests

    # Paired samples per phase. Each value is a list of (a_ms, b_ms)
    # tuples aligned by index so `paired_phase_samples[phase][i]` is
    # one matched measurement pair for the phase's two modes.
    paired_phase_samples: Dict[str, List[Tuple[float, float]]] = {
        label: [] for (label, _, _, _, _, _) in PAIRED_PHASES
    }

    try:
        phase_labels = [p[0] for p in PAIRED_PHASES]
        for rep in range(args.reps):
            order = list(phase_labels)
            rng.shuffle(order)
            for label in order:
                phase = next(p for p in PAIRED_PHASES if p[0] == label)
                _, mode_a_name, mode_b_name, _kind, _scn, _note = phase
                mode_a = next(m for m in MODES if m.name == mode_a_name)
                mode_b = next(m for m in MODES if m.name == mode_b_name)
                pair_n = pair_count_for(mode_a.scenario)
                rep_seed = args.seed + rep * 997 + (hash(label) & 0xFFFF)
                if args.dry_run:
                    a_samples, b_samples = measure_paired_dry(
                        mode_a_name=mode_a_name,
                        mode_b_name=mode_b_name,
                        pair_requests=pair_n,
                        seed=rep_seed,
                    )
                else:
                    a_samples, b_samples = measure_paired_real(
                        client,
                        mode_a=mode_a,
                        mode_b=mode_b,
                        pair_requests=pair_n,
                        req_start=1_000_000
                        + rep * 100_000
                        + len(paired_phase_samples[label]) * 2,
                        seed=rep_seed,
                        pool=pool,
                    )
                for a_ms, b_ms in zip(a_samples, b_samples):
                    paired_phase_samples[label].append((a_ms, b_ms))
                    per_mode[mode_a_name].append(a_ms)
                    per_mode[mode_b_name].append(b_ms)
                delta_vec = [x - y for x, y in zip(a_samples, b_samples)]
                rep_mean_delta = (
                    statistics.fmean(delta_vec) if delta_vec else 0.0
                )
                rep_sum_a = summarize(f"{mode_a_name}_rep{rep}", a_samples)
                rep_sum_a["rep"] = rep
                rep_sum_a["mode"] = mode_a_name
                rep_sum_a["phase"] = label
                per_rep_rows.append(rep_sum_a)
                rep_sum_b = summarize(f"{mode_b_name}_rep{rep}", b_samples)
                rep_sum_b["rep"] = rep
                rep_sum_b["mode"] = mode_b_name
                rep_sum_b["phase"] = label
                per_rep_rows.append(rep_sum_b)
                print(
                    f"[kernel-ablation] rep={rep} phase={label} "
                    f"pairs={len(a_samples)} "
                    f"a_p50={rep_sum_a['p50_ms']:.6f} "
                    f"b_p50={rep_sum_b['p50_ms']:.6f} "
                    f"delta_mean={rep_mean_delta*1000.0:+.3f}us"
                )

        # Noise floor
        if args.dry_run:
            noop_samples = [
                max(0.003 + random.Random(args.seed + 7 + i).gauss(0.0, 0.0003), 0.0)
                for i in range(args.noop_requests)
            ]
        else:
            noop_samples = measure_noop_real(
                client, requests=args.noop_requests, req_start=9_000_000
            )
    finally:
        if client is not None:
            client.close()

    mode_summaries = [summarize(m.name, per_mode[m.name]) for m in MODES]
    noop_summary = summarize("noop", noop_samples)

    # Paired stage deltas: computed directly from the (a,b) pair vectors
    # collected by measure_paired_real. This is the key change vs the
    # previous run_ablation — we no longer compute `mean(A) - mean(B)`
    # across independent, rep-level-drift-contaminated runs. We compute
    # `mean(a[i] - b[i])` across index-aligned samples that were
    # collected μs apart inside the same rep.
    def _paired_delta(label: str, mode_a_name: str, mode_b_name: str, note_template: str) -> Dict[str, Any]:
        pairs = paired_phase_samples.get(label, [])
        a_col = [p[0] for p in pairs]
        b_col = [p[1] for p in pairs]
        delta_vec = [a - b for a, b in pairs]
        note = note_template % {"n_tools": args.n_tools, "n_agents": args.n_agents}
        if not delta_vec:
            return {
                "stage": label,
                "baseline_mode": mode_a_name,
                "bypass_mode": mode_b_name,
                "n_pairs": 0,
                "baseline_avg_ms": 0.0,
                "baseline_p50_ms": 0.0,
                "bypass_avg_ms": 0.0,
                "bypass_p50_ms": 0.0,
                "delta_avg_ms": 0.0,
                "delta_p50_ms": 0.0,
                "delta_std_ms": 0.0,
                "delta_ci_lo": 0.0,
                "delta_ci_hi": 0.0,
                "t_paired": 0.0,
                "p_paired": 1.0,
                "note": note,
            }
        stats = paired_delta_stats(
            delta_vec, iters=args.bootstrap_iters, seed=args.seed
        )
        return {
            "stage": label,
            "baseline_mode": mode_a_name,
            "bypass_mode": mode_b_name,
            "n_pairs": len(delta_vec),
            "baseline_avg_ms": round(statistics.fmean(a_col), 6),
            "baseline_p50_ms": round(percentile(sorted(a_col), 0.5), 6),
            "bypass_avg_ms": round(statistics.fmean(b_col), 6),
            "bypass_p50_ms": round(percentile(sorted(b_col), 0.5), 6),
            "delta_avg_ms": stats["mean_ms"],
            "delta_p50_ms": stats["median_ms"],
            "delta_std_ms": stats["std_ms"],
            "delta_ci_lo": stats["ci_lo"],
            "delta_ci_hi": stats["ci_hi"],
            "t_paired": stats["t_paired"],
            "p_paired": stats["p_paired"],
            "note": note,
        }

    meaningful_stage_deltas: List[Dict[str, Any]] = []
    methodology_note_deltas: List[Dict[str, Any]] = []
    for (label, mode_a_name, mode_b_name, kind, _scn, note) in PAIRED_PHASES:
        row = _paired_delta(label, mode_a_name, mode_b_name, note)
        if kind == "meaningful":
            meaningful_stage_deltas.append(row)
        else:
            methodology_note_deltas.append(row)

    # BH correction across every paired t-test in the run.
    pairwise_rows: List[Dict[str, Any]] = []
    pvals_raw: List[float] = []
    for row in meaningful_stage_deltas + methodology_note_deltas:
        pvals_raw.append(row["p_paired"])
        pairwise_rows.append(
            {
                "stage": row["stage"],
                "baseline": row["baseline_mode"],
                "bypass": row["bypass_mode"],
                "t": row["t_paired"],
                "p_raw": row["p_paired"],
                "n_pairs": row["n_pairs"],
            }
        )
    adj = benjamini_hochberg(pvals_raw)
    for row, p_bh in zip(pairwise_rows, adj):
        row["p_bh"] = p_bh

    summary = {
        "meta": {
            "reps": args.reps,
            "requests_per_cell": args.requests,
            "ticket_requests": args.ticket_requests,
            "warmup_requests": args.warmup_requests,
            "n_tools_registered": args.n_tools,
            "n_agents_registered": args.n_agents,
            "measurement_method": "paired",
            "dry_run": args.dry_run,
            "seed": args.seed,
            "bootstrap_iters": args.bootstrap_iters,
            "noop_requests": args.noop_requests,
            "scenario_notes": {
                "benign_large": f"{args.n_tools} tools + {args.n_agents} agents; uniformly random (tool, agent) per request",
                "ticket_trigger": f"1 high-risk tool (risk_flags=FILESYSTEM_DELETE); ticket path exercised; pair count capped at --ticket-requests (default 100) to limit approval-table growth",
                "measurement": "paired request-level alternation: for each delta phase, modes A and B are interleaved request-by-request in a tight loop so the two samples in each pair share the same scheduler state and cache residency; deltas are computed from paired samples directly, not from mean(A) - mean(B)",
            },
        },
        "modes": [
            {
                "name": m.name,
                "experiment_flags": m.experiment_flags,
                "scenario": m.scenario,
                "ok_decisions": list(m.ok_decisions),
                "description": m.description,
            }
            for m in MODES
        ],
        "mode_summaries": mode_summaries,
        "meaningful_stage_deltas": meaningful_stage_deltas,
        "methodology_note_deltas": methodology_note_deltas,
        "pairwise_tests": pairwise_rows,
        "noop": noop_summary,
    }

    write_csv(
        run_dir / "kernel_ablation_mode_summary.csv",
        mode_summaries,
        ["mode", "samples", "avg_ms", "std_ms", "ci95_ms", "p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"],
    )
    write_csv(
        run_dir / "kernel_ablation_per_rep.csv",
        per_rep_rows,
        ["rep", "phase", "mode", "samples", "avg_ms", "std_ms", "ci95_ms", "p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"],
    )
    # Stage-delta CSV schema: reflects the new paired measurement.
    delta_columns = [
        "stage", "baseline_mode", "bypass_mode", "n_pairs",
        "baseline_avg_ms", "baseline_p50_ms",
        "bypass_avg_ms", "bypass_p50_ms",
        "delta_avg_ms", "delta_p50_ms", "delta_std_ms",
        "delta_ci_lo", "delta_ci_hi",
        "t_paired", "p_paired",
        "note",
    ]
    write_csv(
        run_dir / "kernel_ablation_stage_deltas.csv",
        meaningful_stage_deltas,
        delta_columns,
    )
    write_csv(
        run_dir / "kernel_ablation_methodology_deltas.csv",
        methodology_note_deltas,
        delta_columns,
    )
    write_csv(
        run_dir / "kernel_ablation_pairwise_tests.csv",
        pairwise_rows,
        ["stage", "baseline", "bypass", "n_pairs", "t", "p_raw", "p_bh"],
    )
    write_csv(
        run_dir / "kernel_ablation_noop.csv",
        [noop_summary],
        ["mode", "samples", "avg_ms", "std_ms", "ci95_ms", "p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"],
    )

    # Per-mode sample rows (pooled across all phases that used that mode).
    sample_rows: List[Dict[str, Any]] = []
    for m in MODES:
        for idx, val in enumerate(per_mode[m.name], start=1):
            sample_rows.append({"mode": m.name, "sample_index": idx, "rtt_ms": round(val, 6)})
    write_csv(
        run_dir / "kernel_ablation_samples.csv",
        sample_rows,
        ["mode", "sample_index", "rtt_ms"],
    )

    # Paired sample rows (one row per measurement pair, carrying both modes'
    # latencies alongside the derived delta). Down-stream analysis should
    # prefer this file over kernel_ablation_samples.csv when computing
    # stage cost: each row is a μs-aligned pair that cancels VM drift.
    paired_rows: List[Dict[str, Any]] = []
    for phase_label, pairs in paired_phase_samples.items():
        phase_meta = next(p for p in PAIRED_PHASES if p[0] == phase_label)
        _, a_name, b_name, _kind, _scn, _note = phase_meta
        for idx, (a_ms, b_ms) in enumerate(pairs, start=1):
            paired_rows.append(
                {
                    "phase": phase_label,
                    "pair_index": idx,
                    "baseline_mode": a_name,
                    "bypass_mode": b_name,
                    "baseline_ms": round(a_ms, 6),
                    "bypass_ms": round(b_ms, 6),
                    "delta_ms": round(a_ms - b_ms, 6),
                }
            )
    write_csv(
        run_dir / "kernel_ablation_paired_samples.csv",
        paired_rows,
        ["phase", "pair_index", "baseline_mode", "bypass_mode",
         "baseline_ms", "bypass_ms", "delta_ms"],
    )

    (run_dir / "kernel_ablation_summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2),
        encoding="utf-8",
    )
    (run_dir / "kernel_ablation_report.md").write_text(render_report(summary), encoding="utf-8")

    generate_plots(run_dir, mode_summaries=mode_summaries, stage_deltas=meaningful_stage_deltas)

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="E1 — Kernel path ablation microbenchmark")
    parser.add_argument("--output-dir", default="experiment-results/kernel-ablation")
    parser.add_argument("--reps", type=int, default=10)
    parser.add_argument("--requests", type=int, default=10000,
                        help="requests per (mode, rep) for benign scenarios. "
                             "Overridden for ticket_trigger by --ticket-requests.")
    parser.add_argument("--ticket-requests", type=int, default=100,
                        help="requests per (mode, rep) for ticket_trigger "
                             "scenarios. Kept intentionally small (default 100, "
                             "vs 10000 for benign) because every ticket_trigger_full "
                             "request fires kernel_mcp_issue_approval_ticket, which "
                             "calls an O(n) purge_expired_tickets scan over every "
                             "live entry in the 256-bucket approval hashtable. "
                             "TTL is 300s and nothing expires during a single E1 "
                             "run, so the scan cost grows linearly in total "
                             "live-ticket count. 100 keeps the steady-state "
                             "number representative of the intrinsic issue+consume "
                             "cost rather than the accumulated purge_scan cost. "
                             "Set to 0 to fall back to the old requests//10 heuristic.")
    parser.add_argument("--warmup-requests", type=int, default=1000)
    parser.add_argument("--noop-requests", type=int, default=2000)
    parser.add_argument("--bootstrap-iters", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=0xABCDEF)
    parser.add_argument("--n-tools", type=int, default=1024,
                        help="number of benign tools to register in the xarray "
                             "before measurement, so xa_load walks a realistic "
                             "radix tree (default: 1024).")
    parser.add_argument("--n-agents", type=int, default=64,
                        help="number of benign agents to register in the "
                             "hashtable before measurement, so "
                             "kernel_mcp_find_agent_locked walks a realistic "
                             "chain (default: 64).")
    parser.add_argument("--tool-id", type=int, default=9101,
                        help="base tool_id for the benign tool pool; tools "
                             "occupy [tool_id, tool_id+n_tools)")
    parser.add_argument("--tool-hash", type=str, default="abcd1234",
                        help="unused; kept for CLI backwards compatibility — "
                             "per-tool hashes are now auto-generated")
    parser.add_argument("--binding-hash", type=int, default=0x1234,
                        help="base binding hash for the benign agent pool; "
                             "agents occupy [binding_hash, binding_hash+n_agents)")
    parser.add_argument("--dry-run", action="store_true", help="Stub netlink calls with synthetic samples; for macOS smoke tests.")
    parser.add_argument("--smoke", action="store_true", help="Short run for CI/smoke: 2 reps × 500 requests × 200 noop, N=32 tools, M=8 agents.")
    args = parser.parse_args()

    if args.smoke:
        args.reps = max(min(args.reps, 2), 2)
        args.requests = min(args.requests, 500)
        args.ticket_requests = min(args.ticket_requests, 50)
        args.warmup_requests = min(args.warmup_requests, 100)
        args.noop_requests = min(args.noop_requests, 200)
        args.bootstrap_iters = min(args.bootstrap_iters, 200)
        args.n_tools = min(args.n_tools, 32)
        args.n_agents = min(args.n_agents, 8)

    run_dir = Path(args.output_dir) / time.strftime("run-%Y%m%d-%H%M%S", time.gmtime())
    run_dir.mkdir(parents=True, exist_ok=True)

    run_ablation(args, run_dir)

    print(f"[kernel-ablation] result dir: {run_dir}")
    print(f"[kernel-ablation] summary:    {run_dir / 'kernel_ablation_summary.json'}")
    print(f"[kernel-ablation] report:     {run_dir / 'kernel_ablation_report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
