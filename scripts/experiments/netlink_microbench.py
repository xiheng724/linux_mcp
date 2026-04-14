#!/usr/bin/env python3
"""Microbenchmark Generic Netlink round-trip latency for kernel_mcp."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from mcpd.netlink_client import KernelMcpNetlinkClient  # noqa: E402

EXPERIMENT_SKIP_LOOKUPS = 1 << 0


def maybe_import_plotting() -> Any:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except Exception:
        return None


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    k = (len(ordered) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return ordered[int(k)]
    return ordered[f] * (c - k) + ordered[c] * (k - f)


def ci95(stddev: float, n: int) -> float:
    if n <= 1:
        return 0.0
    return 1.96 * stddev / math.sqrt(n)


def summarize(label: str, samples_ms: List[float]) -> Dict[str, Any]:
    ordered = sorted(samples_ms)
    avg = statistics.fmean(ordered) if ordered else 0.0
    std = statistics.stdev(ordered) if len(ordered) > 1 else 0.0
    ci = ci95(std, len(ordered))
    return {
        "mode": label,
        "samples": len(ordered),
        "avg_ms": round(avg, 6),
        "std_ms": round(std, 6),
        "ci95_ms": round(ci, 6),
        "p50_ms": round(percentile(ordered, 0.50), 6),
        "p95_ms": round(percentile(ordered, 0.95), 6),
        "p99_ms": round(percentile(ordered, 0.99), 6),
        "min_ms": round(min(ordered) if ordered else 0.0, 6),
        "max_ms": round(max(ordered) if ordered else 0.0, 6),
    }


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def write_plot_status(run_dir: Path, *, enabled: bool, reason: str = "") -> None:
    payload = {"plots_generated": enabled, "reason": reason}
    (run_dir / "plots_status.json").write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def render_sampled(values: List[float], *, limit: int = 400) -> List[float]:
    if len(values) <= limit:
        return list(values)
    step = max(len(values) // limit, 1)
    return [values[idx] for idx in range(0, len(values), step)][:limit]


def generate_plots(run_dir: Path, *, bare_samples: List[float], full_samples: List[float]) -> None:
    plt = maybe_import_plotting()
    plots_dir = run_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    if plt is None:
        write_plot_status(run_dir, enabled=False, reason="matplotlib unavailable")
        return

    paired = [full - bare for bare, full in zip(bare_samples, full_samples)]
    sampled_bare = render_sampled(sorted(bare_samples))
    sampled_full = render_sampled(sorted(full_samples))
    sampled_paired = render_sampled(sorted(paired))

    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.boxplot([bare_samples, full_samples], labels=["bare", "full"], showfliers=True)
    ax.set_ylabel("RTT (ms)")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(plots_dir / "figure_netlink_rtt_boxplot.pdf")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.plot(range(1, len(sampled_bare) + 1), sampled_bare, label="bare", linewidth=1.5)
    ax.plot(range(1, len(sampled_full) + 1), sampled_full, label="full", linewidth=1.5)
    ax.set_xlabel("Sample rank (sampled)")
    ax.set_ylabel("RTT (ms)")
    ax.legend()
    ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(plots_dir / "figure_netlink_rtt_ordered.pdf")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.hist(sampled_paired, bins=min(40, max(len(sampled_paired) // 5, 10)), color="#4C78A8", alpha=0.85)
    ax.set_xlabel("full - bare (ms)")
    ax.set_ylabel("Count")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(plots_dir / "figure_lookup_overhead_hist.pdf")
    plt.close(fig)
    write_plot_status(run_dir, enabled=True)


def render_report(summary: Dict[str, Any]) -> str:
    bare = summary["bare"]
    full = summary["full"]
    diff = summary["lookup_overhead"]
    lines = [
        "# Generic Netlink Microbenchmark Report",
        "",
        "## Setup",
        "",
        f"- warmup_requests: {summary['meta']['warmup_requests']}",
        f"- measure_requests: {summary['meta']['measure_requests']}",
        f"- agent_id: `{summary['meta']['agent_id']}`",
        f"- tool_id: `{summary['meta']['tool_id']}`",
        "",
        "## Summary",
        "",
        "| mode | avg_ms | p95_ms | p99_ms | std_ms | 95% CI |",
        "|---|---:|---:|---:|---:|---:|",
        f"| bare | {bare['avg_ms']:.6f} | {bare['p95_ms']:.6f} | {bare['p99_ms']:.6f} | {bare['std_ms']:.6f} | +/- {bare['ci95_ms']:.6f} |",
        f"| full | {full['avg_ms']:.6f} | {full['p95_ms']:.6f} | {full['p99_ms']:.6f} | {full['std_ms']:.6f} | +/- {full['ci95_ms']:.6f} |",
        "",
        "## Derived Metrics",
        "",
        f"- `netlink_rtt_bare_ms = {bare['avg_ms']:.6f}`",
        f"- `netlink_rtt_full_ms = {full['avg_ms']:.6f}`",
        f"- `lookup_overhead_ms = {diff['avg_ms']:.6f}`",
        f"- `lookup_overhead_share_pct = {summary['lookup_share_pct']:.3f}%`",
        "",
        "解释：`bare` 只测 Generic Netlink 往返和最小命令处理；`full` 走正常 `TOOL_REQUEST` 路径并包含 tool/agent 查找与绑定校验。",
        "",
    ]
    return "\n".join(lines)


def is_unsupported_experiment_flag_error(exc: Exception) -> bool:
    text = str(exc)
    return "NLMSG_ERROR=-22" in text or "Invalid argument" in text


def raise_bare_support_error(exc: Exception) -> None:
    raise RuntimeError(
        "kernel bare benchmark path is not supported by the currently loaded kernel_mcp module. "
        "This experiment uses the new EXPERIMENT_FLAGS netlink attribute, so you likely need to rebuild "
        "and reload the kernel module before rerunning:\n"
        "  sudo bash scripts/build_kernel.sh\n"
        "  sudo bash scripts/unload_module.sh || true\n"
        "  sudo bash scripts/load_module.sh\n"
        f"original error: {exc}"
    ) from exc


def measure_mode(
    client: KernelMcpNetlinkClient,
    *,
    req_start: int,
    requests: int,
    agent_id: str,
    tool_id: int,
    tool_hash: str,
    binding_hash: int,
    binding_epoch: int,
    experiment_flags: int,
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
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if decision.decision != "ALLOW":
            raise RuntimeError(f"unexpected tool decision: {decision}")
        samples.append(elapsed_ms)
    return samples


def main() -> int:
    parser = argparse.ArgumentParser(description="Generic Netlink RTT microbenchmark")
    parser.add_argument("--output-dir", default="experiment-results/netlink-microbench")
    parser.add_argument("--warmup-requests", type=int, default=500)
    parser.add_argument("--measure-requests", type=int, default=10000)
    parser.add_argument("--agent-id", default="bench-agent")
    parser.add_argument("--tool-id", type=int, default=9001)
    parser.add_argument("--tool-name", default="bench_tool")
    parser.add_argument("--tool-hash", default="abcd1234")
    parser.add_argument("--binding-hash", type=int, default=0x1234)
    parser.add_argument("--binding-epoch", type=int, default=1)
    parser.add_argument("--risk-flags", type=int, default=0)
    args = parser.parse_args()

    run_dir = Path(args.output_dir) / time.strftime("run-%Y%m%d-%H%M%S", time.gmtime())
    run_dir.mkdir(parents=True, exist_ok=True)

    client = KernelMcpNetlinkClient()
    try:
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

        try:
            measure_mode(
                client,
                req_start=1,
                requests=1,
                agent_id=args.agent_id,
                tool_id=args.tool_id,
                tool_hash=args.tool_hash,
                binding_hash=args.binding_hash,
                binding_epoch=args.binding_epoch,
                experiment_flags=EXPERIMENT_SKIP_LOOKUPS,
            )
        except RuntimeError as exc:
            if is_unsupported_experiment_flag_error(exc):
                raise_bare_support_error(exc)
            raise

        measure_mode(
            client,
            req_start=10,
            requests=max(args.warmup_requests - 1, 0),
            agent_id=args.agent_id,
            tool_id=args.tool_id,
            tool_hash=args.tool_hash,
            binding_hash=args.binding_hash,
            binding_epoch=args.binding_epoch,
            experiment_flags=EXPERIMENT_SKIP_LOOKUPS,
        )
        measure_mode(
            client,
            req_start=100000,
            requests=args.warmup_requests,
            agent_id=args.agent_id,
            tool_id=args.tool_id,
            tool_hash=args.tool_hash,
            binding_hash=args.binding_hash,
            binding_epoch=args.binding_epoch,
            experiment_flags=0,
        )

        bare_samples = measure_mode(
            client,
            req_start=200000,
            requests=args.measure_requests,
            agent_id=args.agent_id,
            tool_id=args.tool_id,
            tool_hash=args.tool_hash,
            binding_hash=args.binding_hash,
            binding_epoch=args.binding_epoch,
            experiment_flags=EXPERIMENT_SKIP_LOOKUPS,
        )
        full_samples = measure_mode(
            client,
            req_start=300000,
            requests=args.measure_requests,
            agent_id=args.agent_id,
            tool_id=args.tool_id,
            tool_hash=args.tool_hash,
            binding_hash=args.binding_hash,
            binding_epoch=args.binding_epoch,
            experiment_flags=0,
        )
    finally:
        client.close()

    bare_summary = summarize("bare", bare_samples)
    full_summary = summarize("full", full_samples)
    paired_lookup = [full - bare for bare, full in zip(bare_samples, full_samples)]
    lookup_avg = statistics.fmean(paired_lookup) if paired_lookup else 0.0
    lookup_p95 = percentile(sorted(paired_lookup), 0.95) if paired_lookup else 0.0
    summary = {
        "meta": {
            "warmup_requests": args.warmup_requests,
            "measure_requests": args.measure_requests,
            "agent_id": args.agent_id,
            "tool_id": args.tool_id,
            "tool_name": args.tool_name,
            "tool_hash": args.tool_hash,
            "binding_hash": args.binding_hash,
            "binding_epoch": args.binding_epoch,
        },
        "bare": bare_summary,
        "full": full_summary,
        "lookup_overhead": {
            "avg_ms": round(lookup_avg, 6),
            "p95_ms": round(lookup_p95, 6),
        },
        "lookup_share_pct": round((lookup_avg / full_summary["avg_ms"]) * 100.0, 3)
        if full_summary["avg_ms"] > 0
        else 0.0,
    }

    sample_rows = [
        {"mode": "bare", "sample_index": idx, "rtt_ms": round(value, 6)}
        for idx, value in enumerate(bare_samples, start=1)
    ] + [
        {"mode": "full", "sample_index": idx, "rtt_ms": round(value, 6)}
        for idx, value in enumerate(full_samples, start=1)
    ]
    write_csv(run_dir / "netlink_microbench_samples.csv", sample_rows, ["mode", "sample_index", "rtt_ms"])
    write_csv(
        run_dir / "netlink_microbench_summary.csv",
        [
            {
                "mode": "bare",
                **bare_summary,
            },
            {
                "mode": "full",
                **full_summary,
            },
            {
                "mode": "lookup_overhead",
                "samples": args.measure_requests,
                "avg_ms": summary["lookup_overhead"]["avg_ms"],
                "std_ms": "",
                "ci95_ms": "",
                "p50_ms": "",
                "p95_ms": summary["lookup_overhead"]["p95_ms"],
                "p99_ms": "",
                "min_ms": "",
                "max_ms": "",
            },
        ],
        ["mode", "samples", "avg_ms", "std_ms", "ci95_ms", "p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"],
    )
    write_csv(
        run_dir / "netlink_lookup_overhead_samples.csv",
        [
            {
                "sample_index": idx,
                "bare_rtt_ms": round(bare, 6),
                "full_rtt_ms": round(full, 6),
                "lookup_overhead_ms": round(full - bare, 6),
            }
            for idx, (bare, full) in enumerate(zip(bare_samples, full_samples), start=1)
        ],
        ["sample_index", "bare_rtt_ms", "full_rtt_ms", "lookup_overhead_ms"],
    )
    (run_dir / "netlink_microbench_summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2),
        encoding="utf-8",
    )
    (run_dir / "netlink_microbench_report.md").write_text(render_report(summary), encoding="utf-8")
    generate_plots(run_dir, bare_samples=bare_samples, full_samples=full_samples)

    print(f"[netlink-microbench] result dir: {run_dir}")
    print(f"[netlink-microbench] summary:    {run_dir / 'netlink_microbench_summary.json'}")
    print(f"[netlink-microbench] report:     {run_dir / 'netlink_microbench_report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
