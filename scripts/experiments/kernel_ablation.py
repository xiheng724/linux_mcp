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
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from client.kernel_mcp.schema import EXPERIMENT_FLAGS  # noqa: E402

try:
    from mcpd.netlink_client import KernelMcpNetlinkClient  # noqa: E402
except Exception:  # pragma: no cover — dry-run on macOS shouldn't fail import
    KernelMcpNetlinkClient = None  # type: ignore[assignment]


# Single-factor modes. Each one differs from `full` by exactly one disabled
# stage. `skip_lookups` is the existing "bare" path and short-circuits the
# most aggressively — we keep it so the new data is directly comparable to
# the earlier netlink_microbench snapshots.
MODES: Tuple[Tuple[str, int], ...] = (
    ("full", 0),
    ("skip_ticket", EXPERIMENT_FLAGS["SKIP_TICKET"]),
    ("skip_binding", EXPERIMENT_FLAGS["SKIP_BINDING"]),
    ("skip_hash", EXPERIMENT_FLAGS["SKIP_HASH"]),
    ("skip_lookups", EXPERIMENT_FLAGS["SKIP_LOOKUPS"]),
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
    fig.savefig(plots_dir / "figure_ablation_mean_rtt.png", dpi=180)
    plt.close(fig)

    if stage_deltas:
        stage_labels = [row["stage"] for row in stage_deltas]
        deltas = [row["delta_ms"] for row in stage_deltas]
        lo = [row["delta_ci_lo"] for row in stage_deltas]
        hi = [row["delta_ci_hi"] for row in stage_deltas]
        err_lo = [max(d - l, 0.0) for d, l in zip(deltas, lo)]
        err_hi = [max(h - d, 0.0) for d, h in zip(deltas, hi)]
        fig, ax = plt.subplots(figsize=(7.5, 4.5))
        xs = list(range(len(stage_labels)))
        ax.bar(xs, deltas, yerr=[err_lo, err_hi], color="#E45756", alpha=0.85, capsize=4)
        ax.set_xticks(xs)
        ax.set_xticklabels(stage_labels, rotation=20, ha="right")
        ax.set_ylabel("Per-stage cost: full - skip (ms)")
        ax.set_title("Isolated per-stage kernel cost (paired bootstrap 95% CI)")
        ax.grid(axis="y", alpha=0.25)
        ax.axhline(0, color="#444", linewidth=0.8)
        fig.tight_layout()
        fig.savefig(plots_dir / "figure_ablation_stage_delta.png", dpi=180)
        plt.close(fig)

    (run_dir / "plots_status.json").write_text(
        json.dumps({"plots_generated": True, "reason": ""}, indent=2),
        encoding="utf-8",
    )


def render_report(summary: Dict[str, Any]) -> str:
    lines = [
        "# Kernel Path Ablation (E1)",
        "",
        "## Setup",
        "",
        f"- kernel flags tested: {', '.join(name for name, _ in MODES)}",
        f"- reps: {summary['meta']['reps']}",
        f"- requests per (mode, rep): {summary['meta']['requests_per_cell']}",
        f"- payload: 100 B equivalent (bare netlink path)",
        f"- order randomization: per-rep shuffle of mode list",
        f"- dry-run: {summary['meta']['dry_run']}",
        "",
        "## Environment",
        "",
        "VMware guest / Apple aarch64 host / 4 vCPU / 8 GB. Absolute numbers",
        "must be read together with the measured noise floor (noop).",
        "",
        "## Per-mode summary",
        "",
        "| mode | n | avg_ms | p50 | p95 | p99 | std | 95% CI |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary["mode_summaries"]:
        lines.append(
            "| {mode} | {samples} | {avg_ms:.6f} | {p50_ms:.6f} | {p95_ms:.6f} | "
            "{p99_ms:.6f} | {std_ms:.6f} | +/- {ci95_ms:.6f} |".format(**row)
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
        "All ablation deltas below are stated as `full - skip`, so positive",
        "values mean the named stage is non-trivial on the current kernel.",
        "",
        "## Per-stage isolated cost",
        "",
        "| stage | full avg | skip avg | delta_ms | delta ratio | bootstrap CI |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for row in summary["stage_deltas"]:
        lines.append(
            "| {stage} | {full_avg_ms:.6f} | {skip_avg_ms:.6f} | {delta_ms:.6f} | "
            "{delta_ratio:.4f} | [{delta_ci_lo:.6f}, {delta_ci_hi:.6f}] |".format(**row)
        )
    lines += [
        "",
        "## Pairwise Welch t-tests (adjacent vs full), BH-corrected",
        "",
        "| mode | t | p_raw | p_bh |",
        "|---|---:|---:|---:|",
    ]
    for row in summary["pairwise_tests"]:
        lines.append(
            "| {mode} | {t:.4f} | {p_raw:.6f} | {p_bh:.6f} |".format(**row)
        )
    lines += [
        "",
        "## Caveats",
        "",
        "- Delta estimates near the sub-microsecond range should be read",
        "  together with the noop noise floor above.",
        "- This is single-factor ablation: cross-interactions between stages",
        "  are not measured. The absolute per-stage costs do not sum to",
        "  `full - skip_lookups` exactly because the kernel path has shared",
        "  prologue work that all non-skip modes still pay.",
        "",
    ]
    return "\n".join(lines)


def measure_mode_real(
    client: Any,
    *,
    experiment_flags: int,
    requests: int,
    agent_id: str,
    tool_id: int,
    tool_hash: str,
    binding_hash: int,
    binding_epoch: int,
    req_start: int,
) -> List[float]:
    samples: List[float] = []
    for idx in range(requests):
        t0 = time.perf_counter()
        decision = client.tool_request(
            req_id=req_start + idx,
            agent_id=agent_id,
            binding_hash=binding_hash,
            binding_epoch=binding_epoch,
            tool_id=tool_id,
            tool_hash=tool_hash,
            experiment_flags=experiment_flags,
        )
        elapsed = (time.perf_counter() - t0) * 1000.0
        if decision.decision != "ALLOW":
            raise RuntimeError(f"unexpected tool decision: {decision}")
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
    mode: str,
    requests: int,
    seed: int,
) -> List[float]:
    """Synthetic latency generator for macOS dry-runs.

    The shape roughly matches what we expect on the VM: `full` ≈ 26 μs,
    each skip shaves a small but noisy amount off, `skip_lookups` is fastest.
    """
    rng = random.Random(seed)
    centers = {
        "full": 0.026,
        "skip_ticket": 0.024,
        "skip_binding": 0.022,
        "skip_hash": 0.020,
        "skip_lookups": 0.009,
    }
    center = centers.get(mode, 0.020)
    return [max(center + rng.gauss(0.0, 0.003), 0.0005) for _ in range(requests)]


def run_ablation(
    args: argparse.Namespace,
    run_dir: Path,
) -> Dict[str, Any]:
    per_mode: Dict[str, List[float]] = {name: [] for name, _ in MODES}
    per_rep_rows: List[Dict[str, Any]] = []
    rng = random.Random(args.seed)

    if args.dry_run:
        client = None
    else:
        if KernelMcpNetlinkClient is None:
            raise RuntimeError(
                "KernelMcpNetlinkClient unavailable in this environment; "
                "use --dry-run for non-Linux hosts."
            )
        client = KernelMcpNetlinkClient()
        client.register_tool(
            tool_id=args.tool_id,
            name=args.tool_name,
            risk_flags=args.risk_flags,
            tool_hash=args.tool_hash,
        )
        client.register_agent(
            args.agent_id,
            pid=1,
            uid=0,
            binding_hash=args.binding_hash,
            binding_epoch=args.binding_epoch,
        )
        # Warmup at full path
        measure_mode_real(
            client,
            experiment_flags=0,
            requests=args.warmup_requests,
            agent_id=args.agent_id,
            tool_id=args.tool_id,
            tool_hash=args.tool_hash,
            binding_hash=args.binding_hash,
            binding_epoch=args.binding_epoch,
            req_start=10,
        )

    try:
        mode_names = [name for name, _ in MODES]
        for rep in range(args.reps):
            order = list(mode_names)
            rng.shuffle(order)
            for mode_name in order:
                flags = dict(MODES)[mode_name]
                if args.dry_run:
                    samples = measure_mode_dry(
                        mode=mode_name,
                        requests=args.requests,
                        seed=args.seed + rep * 97 + hash(mode_name) % 997,
                    )
                else:
                    samples = measure_mode_real(
                        client,
                        experiment_flags=flags,
                        requests=args.requests,
                        agent_id=args.agent_id,
                        tool_id=args.tool_id,
                        tool_hash=args.tool_hash,
                        binding_hash=args.binding_hash,
                        binding_epoch=args.binding_epoch,
                        req_start=1_000_000 + rep * 100_000 + len(per_mode[mode_name]),
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
            noop_samples = [max(0.006 + random.Random(args.seed + 7).gauss(0.0, 0.001), 0.0) for _ in range(args.noop_requests)]
        else:
            noop_samples = measure_noop_real(
                client, requests=args.noop_requests, req_start=9_000_000
            )
    finally:
        if client is not None:
            client.close()

    mode_summaries = [summarize(name, per_mode[name]) for name, _ in MODES]
    noop_summary = summarize("noop", noop_samples)

    # Stage deltas: skip_<stage> relative to full
    full_samples = per_mode["full"]
    stage_deltas: List[Dict[str, Any]] = []
    pairwise_rows: List[Dict[str, Any]] = []
    pvals_raw: List[float] = []
    mode_order: List[str] = []
    for name, _flags in MODES:
        if name == "full":
            continue
        skip_samples = per_mode[name]
        delta_mean, ci_lo, ci_hi = paired_bootstrap_delta_ci(
            full_samples, skip_samples, iters=args.bootstrap_iters, seed=args.seed
        )
        full_avg = statistics.fmean(full_samples) if full_samples else 0.0
        skip_avg = statistics.fmean(skip_samples) if skip_samples else 0.0
        ratio = (full_avg - skip_avg) / full_avg if full_avg > 0 else 0.0
        stage_label = name.replace("skip_", "")
        stage_deltas.append(
            {
                "stage": stage_label,
                "full_avg_ms": round(full_avg, 6),
                "skip_avg_ms": round(skip_avg, 6),
                "delta_ms": round(full_avg - skip_avg, 6),
                "delta_ratio": round(ratio, 6),
                "delta_bootstrap_mean_ms": delta_mean,
                "delta_ci_lo": ci_lo,
                "delta_ci_hi": ci_hi,
            }
        )
        t, p = welch_t(full_samples, skip_samples)
        pvals_raw.append(p)
        mode_order.append(name)
        pairwise_rows.append({"mode": name, "t": t, "p_raw": p})

    adj = benjamini_hochberg(pvals_raw)
    for row, p_bh in zip(pairwise_rows, adj):
        row["p_bh"] = p_bh

    summary = {
        "meta": {
            "reps": args.reps,
            "requests_per_cell": args.requests,
            "warmup_requests": args.warmup_requests,
            "agent_id": args.agent_id,
            "tool_id": args.tool_id,
            "dry_run": args.dry_run,
            "seed": args.seed,
            "bootstrap_iters": args.bootstrap_iters,
            "noop_requests": args.noop_requests,
        },
        "mode_summaries": mode_summaries,
        "stage_deltas": stage_deltas,
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
    write_csv(
        run_dir / "kernel_ablation_stage_deltas.csv",
        stage_deltas,
        ["stage", "full_avg_ms", "skip_avg_ms", "delta_ms", "delta_ratio", "delta_bootstrap_mean_ms", "delta_ci_lo", "delta_ci_hi"],
    )
    write_csv(
        run_dir / "kernel_ablation_pairwise_tests.csv",
        pairwise_rows,
        ["mode", "t", "p_raw", "p_bh"],
    )
    write_csv(
        run_dir / "kernel_ablation_noop.csv",
        [noop_summary],
        ["mode", "samples", "avg_ms", "std_ms", "ci95_ms", "p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"],
    )

    sample_rows: List[Dict[str, Any]] = []
    for name, _ in MODES:
        for idx, val in enumerate(per_mode[name], start=1):
            sample_rows.append({"mode": name, "sample_index": idx, "rtt_ms": round(val, 6)})
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

    generate_plots(run_dir, mode_summaries=mode_summaries, stage_deltas=stage_deltas)

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="E1 — Kernel path ablation microbenchmark")
    parser.add_argument("--output-dir", default="experiment-results/kernel-ablation")
    parser.add_argument("--reps", type=int, default=10)
    parser.add_argument("--requests", type=int, default=10000)
    parser.add_argument("--warmup-requests", type=int, default=1000)
    parser.add_argument("--noop-requests", type=int, default=2000)
    parser.add_argument("--bootstrap-iters", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=0xABCDEF)
    parser.add_argument("--agent-id", default="ablation-agent")
    parser.add_argument("--tool-id", type=int, default=9101)
    parser.add_argument("--tool-name", default="ablation_tool")
    parser.add_argument("--tool-hash", default="abcd1234")
    parser.add_argument("--binding-hash", type=int, default=0x1234)
    parser.add_argument("--binding-epoch", type=int, default=1)
    parser.add_argument("--risk-flags", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true", help="Stub netlink calls with synthetic samples; for macOS smoke tests.")
    parser.add_argument("--smoke", action="store_true", help="Short run for CI/smoke: 2 reps × 500 requests × 200 noop.")
    args = parser.parse_args()

    if args.smoke:
        args.reps = max(min(args.reps, 2), 2)
        args.requests = min(args.requests, 500)
        args.warmup_requests = min(args.warmup_requests, 100)
        args.noop_requests = min(args.noop_requests, 200)
        args.bootstrap_iters = min(args.bootstrap_iters, 200)

    run_dir = Path(args.output_dir) / time.strftime("run-%Y%m%d-%H%M%S", time.gmtime())
    run_dir.mkdir(parents=True, exist_ok=True)

    run_ablation(args, run_dir)

    print(f"[kernel-ablation] result dir: {run_dir}")
    print(f"[kernel-ablation] summary:    {run_dir / 'kernel_ablation_summary.json'}")
    print(f"[kernel-ablation] report:     {run_dir / 'kernel_ablation_report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
