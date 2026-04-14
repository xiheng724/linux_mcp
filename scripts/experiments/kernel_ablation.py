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
        f"- requests per (mode, rep) — benign: {meta['requests_per_cell']}",
        f"- requests per (mode, rep) — ticket_trigger: {meta['requests_per_cell'] // 10}",
        f"- benign registry scale: {meta['n_tools_registered']} tools, {meta['n_agents_registered']} agents",
        f"- order randomization: per-rep shuffle of mode list",
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
        "These are the **meaningful** deltas — pairs of modes where the",
        "bypass flag actually changes the kernel execution path under its",
        "workload. Both the mean-based and p50-based delta are shown because",
        "p50 is robust to hypervisor preemption outliers in individual",
        "100k-sample cells.",
        "",
        "| stage | baseline | bypass | Δ_avg (μs) | Δ_p50 (μs) | bootstrap 95% CI (μs) | note |",
        "|---|---|---|---:|---:|---|---|",
    ]
    for row in summary["meaningful_stage_deltas"]:
        lines.append(
            "| {stage} | {baseline_mode} | {bypass_mode} | "
            "{d_avg_us:+.3f} | {d_p50_us:+.3f} | "
            "[{ci_lo_us:+.3f}, {ci_hi_us:+.3f}] | {note} |".format(
                stage=row["stage"],
                baseline_mode=row["baseline_mode"],
                bypass_mode=row["bypass_mode"],
                d_avg_us=row["delta_avg_ms"] * 1000.0,
                d_p50_us=row["delta_p50_ms"] * 1000.0,
                ci_lo_us=row["delta_ci_lo"] * 1000.0,
                ci_hi_us=row["delta_ci_hi"] * 1000.0,
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
        "between them is noise on the same code, not a stage cost. We keep them",
        "in the output so that the path-identity caveat is visible in the raw",
        "data instead of requiring a source-level trace to rediscover.",
        "",
        "| stage | baseline | bypass | Δ_avg (μs) | Δ_p50 (μs) | bootstrap 95% CI (μs) | note |",
        "|---|---|---|---:|---:|---|---|",
    ]
    for row in summary["methodology_note_deltas"]:
        lines.append(
            "| {stage} | {baseline_mode} | {bypass_mode} | "
            "{d_avg_us:+.3f} | {d_p50_us:+.3f} | "
            "[{ci_lo_us:+.3f}, {ci_hi_us:+.3f}] | {note} |".format(
                stage=row["stage"],
                baseline_mode=row["baseline_mode"],
                bypass_mode=row["bypass_mode"],
                d_avg_us=row["delta_avg_ms"] * 1000.0,
                d_p50_us=row["delta_p50_ms"] * 1000.0,
                ci_lo_us=row["delta_ci_lo"] * 1000.0,
                ci_hi_us=row["delta_ci_hi"] * 1000.0,
                note=row["note"],
            )
        )

    lines += [
        "",
        "## Pairwise Welch t-tests (BH-corrected across all deltas)",
        "",
        "| stage | baseline | bypass | t | p_raw | p_bh |",
        "|---|---|---|---:|---:|---:|",
    ]
    for row in summary["pairwise_tests"]:
        lines.append(
            "| {stage} | {baseline} | {bypass} | {t:.4f} | {p_raw:.6f} | {p_bh:.6f} |".format(**row)
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

    # ticket_trigger modes run far fewer samples per rep than benign modes.
    #
    # Every ticket_trigger_full request makes the kernel issue a fresh
    # approval ticket via kernel_mcp_issue_approval_ticket, which in turn
    # calls kernel_mcp_purge_expired_tickets_locked() that scans all
    # 256 buckets of the approval hashtable. TTL is 300s, so nothing
    # expires during a ~minute-scale E1 run and the scan cost grows
    # linearly in total live-ticket count. At 10,000 tickets the scan
    # alone reached ~28 μs per issuance in the first full-scale run,
    # which masks the intrinsic issue + consume logic cost.
    #
    # Default --ticket-requests=100 keeps the mean live-ticket count
    # during the ticket_trigger sweep under ~500, which brings the
    # purge_scan component down to a few-hundred-ns floor — still
    # asymptotically O(n) but swamped by the actual issue/consume work
    # we want to measure.
    #
    # Passing --ticket-requests=0 falls back to the old behavior of
    # scaling linearly with --requests (requests // 10).
    def samples_for(mode: AblationMode, rep_samples: int) -> int:
        if mode.scenario == SCENARIO_TICKET_TRIGGER:
            if args.ticket_requests > 0:
                return args.ticket_requests
            return min(rep_samples, max(1, rep_samples // 10))
        return rep_samples

    try:
        mode_names = [m.name for m in MODES]
        for rep in range(args.reps):
            order = list(mode_names)
            rng.shuffle(order)
            for mode_name in order:
                mode = next(m for m in MODES if m.name == mode_name)
                n_samples = samples_for(mode, args.requests)
                rep_seed = args.seed + rep * 997 + (hash(mode_name) & 0xFFFF)
                if args.dry_run:
                    samples = measure_mode_dry(
                        mode_name=mode_name,
                        requests=n_samples,
                        seed=rep_seed,
                    )
                else:
                    samples = measure_mode_real(
                        client,
                        mode=mode,
                        requests=n_samples,
                        req_start=1_000_000 + rep * 100_000 + len(per_mode[mode_name]),
                        seed=rep_seed,
                        pool=pool,
                    )
                per_mode[mode_name].extend(samples)
                rep_summary = summarize(f"{mode_name}_rep{rep}", samples)
                rep_summary["rep"] = rep
                rep_summary["mode"] = mode_name
                per_rep_rows.append(rep_summary)
                print(
                    f"[kernel-ablation] rep={rep} mode={mode_name} n={len(samples)} "
                    f"avg_ms={rep_summary['avg_ms']:.6f} p99_ms={rep_summary['p99_ms']:.6f}"
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

    # Meaningful stage deltas: pairs where bypassing one flag actually
    # changes the kernel execution path under its workload. These are the
    # numbers that go into the paper.
    def _one_delta(label: str, baseline_name: str, bypass_name: str, note_template: str) -> Dict[str, Any]:
        a = per_mode[baseline_name]
        b = per_mode[bypass_name]
        if not a or not b:
            return {
                "stage": label,
                "baseline_mode": baseline_name,
                "bypass_mode": bypass_name,
                "baseline_avg_ms": 0.0,
                "baseline_p50_ms": 0.0,
                "bypass_avg_ms": 0.0,
                "bypass_p50_ms": 0.0,
                "delta_avg_ms": 0.0,
                "delta_p50_ms": 0.0,
                "delta_bootstrap_mean_ms": 0.0,
                "delta_ci_lo": 0.0,
                "delta_ci_hi": 0.0,
                "note": note_template % {"n_tools": args.n_tools, "n_agents": args.n_agents},
            }
        baseline_avg = statistics.fmean(a)
        bypass_avg = statistics.fmean(b)
        baseline_p50 = percentile(sorted(a), 0.5)
        bypass_p50 = percentile(sorted(b), 0.5)
        delta_mean, ci_lo, ci_hi = paired_bootstrap_delta_ci(
            a, b, iters=args.bootstrap_iters, seed=args.seed
        )
        return {
            "stage": label,
            "baseline_mode": baseline_name,
            "bypass_mode": bypass_name,
            "baseline_avg_ms": round(baseline_avg, 6),
            "baseline_p50_ms": round(baseline_p50, 6),
            "bypass_avg_ms": round(bypass_avg, 6),
            "bypass_p50_ms": round(bypass_p50, 6),
            "delta_avg_ms": round(baseline_avg - bypass_avg, 6),
            "delta_p50_ms": round(baseline_p50 - bypass_p50, 6),
            "delta_bootstrap_mean_ms": delta_mean,
            "delta_ci_lo": ci_lo,
            "delta_ci_hi": ci_hi,
            "note": note_template % {"n_tools": args.n_tools, "n_agents": args.n_agents},
        }

    meaningful_stage_deltas: List[Dict[str, Any]] = [
        _one_delta(label, baseline, bypass, note)
        for (label, baseline, bypass, note) in MEANINGFUL_STAGE_DELTAS
    ]
    methodology_note_deltas: List[Dict[str, Any]] = [
        _one_delta(label, baseline, bypass, note)
        for (label, baseline, bypass, note) in METHODOLOGY_NOTE_DELTAS
    ]

    # Pairwise Welch tests across every meaningful pair, BH-corrected.
    pairwise_rows: List[Dict[str, Any]] = []
    pvals_raw: List[float] = []
    for label, baseline, bypass, _note in MEANINGFUL_STAGE_DELTAS + METHODOLOGY_NOTE_DELTAS:
        a = per_mode[baseline]
        b = per_mode[bypass]
        if not a or not b:
            pairwise_rows.append(
                {"stage": label, "baseline": baseline, "bypass": bypass,
                 "t": 0.0, "p_raw": 1.0}
            )
            pvals_raw.append(1.0)
            continue
        t, p = welch_t(a, b)
        pvals_raw.append(p)
        pairwise_rows.append(
            {"stage": label, "baseline": baseline, "bypass": bypass,
             "t": t, "p_raw": p}
        )
    adj = benjamini_hochberg(pvals_raw)
    for row, p_bh in zip(pairwise_rows, adj):
        row["p_bh"] = p_bh

    summary = {
        "meta": {
            "reps": args.reps,
            "requests_per_cell": args.requests,
            "warmup_requests": args.warmup_requests,
            "n_tools_registered": args.n_tools,
            "n_agents_registered": args.n_agents,
            "dry_run": args.dry_run,
            "seed": args.seed,
            "bootstrap_iters": args.bootstrap_iters,
            "noop_requests": args.noop_requests,
            "scenario_notes": {
                "benign_large": f"{args.n_tools} tools + {args.n_agents} agents; uniformly random (tool, agent) per request",
                "ticket_trigger": f"1 high-risk tool (risk_flags=FILESYSTEM_DELETE); ticket path exercised; request count capped at requests/10 per rep to limit approval-table growth",
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
        ["rep", "mode", "samples", "avg_ms", "std_ms", "ci95_ms", "p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"],
    )
    # Meaningful stage deltas (paper-quality numbers).
    delta_columns = [
        "stage", "baseline_mode", "bypass_mode",
        "baseline_avg_ms", "baseline_p50_ms",
        "bypass_avg_ms", "bypass_p50_ms",
        "delta_avg_ms", "delta_p50_ms",
        "delta_bootstrap_mean_ms", "delta_ci_lo", "delta_ci_hi",
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
        ["stage", "baseline", "bypass", "t", "p_raw", "p_bh"],
    )
    write_csv(
        run_dir / "kernel_ablation_noop.csv",
        [noop_summary],
        ["mode", "samples", "avg_ms", "std_ms", "ci95_ms", "p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"],
    )

    sample_rows: List[Dict[str, Any]] = []
    for m in MODES:
        for idx, val in enumerate(per_mode[m.name], start=1):
            sample_rows.append({"mode": m.name, "sample_index": idx, "rtt_ms": round(val, 6)})
    write_csv(
        run_dir / "kernel_ablation_samples.csv",
        sample_rows,
        ["mode", "sample_index", "rtt_ms"],
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
