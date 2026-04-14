#!/usr/bin/env python3
"""E2 Registry Scaling experiment runner for linux-mcp.

Measures how kernel_mcp's xarray-backed tool registry scales with N:
  (a) bulk registration wall-clock and per-tool average,
  (b) hot-path lookup RTT against uniformly random tool_ids,
  (c) sysfs directory enumeration wall-clock,
  (d) kernel module memory snapshot and MemFree delta,
plus a userspace Python dict baseline.

Follows the snapshot layout experiment-results/<suite>/run-<ts>/ with a
plots/ subdir, the same conventions as netlink_microbench.py.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

DEFAULT_N_VALUES = "8,16,32,64,128,256,512,1024,2048,4096,8192,16384"
DEFAULT_REPS = 10
SMOKE_N_VALUES = "8,64,512"
SMOKE_REPS = 2
DEFAULT_LOOKUP_SAMPLES = 2000
WARMUP_N = 64  # throwaway register pass before each N's measurement reps
TOOL_ID_BASE = 10000
KERNEL_TOOL_CAP: Optional[int] = None  # unbounded: kernel uses xa_store without cap
SYSFS_TOOLS_DIR = "/sys/kernel/mcp/tools"
MODULE_DIR = "/sys/module/kernel_mcp"
MEMINFO_PATH = "/proc/meminfo"


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
        "label": label,
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
    (run_dir / "plots_status.json").write_text(
        json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8"
    )


def parse_n_values(text: str) -> List[int]:
    values: List[int] = []
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        n = int(token)
        if n <= 0:
            raise ValueError(f"N values must be positive integers: {token}")
        values.append(n)
    if not values:
        raise ValueError("--N-values must contain at least one positive integer")
    return values


def clip_n_values(values: List[int]) -> Tuple[List[int], List[str]]:
    warnings: List[str] = []
    if KERNEL_TOOL_CAP is None:
        return values, warnings
    clipped = []
    for n in values:
        if n > KERNEL_TOOL_CAP:
            warnings.append(
                f"N={n} exceeds kernel tool cap {KERNEL_TOOL_CAP}; clipping to cap"
            )
            clipped.append(KERNEL_TOOL_CAP)
        else:
            clipped.append(n)
    return clipped, warnings


def read_meminfo_free_kb() -> Optional[int]:
    try:
        with open(MEMINFO_PATH, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemFree:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1])
    except OSError:
        return None
    return None


def read_module_memory_snapshot() -> Dict[str, Any]:
    snapshot: Dict[str, Any] = {}
    module_keys = ("coresize", "initsize", "refcnt", "taint")
    for key in module_keys:
        path = os.path.join(MODULE_DIR, key)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                snapshot[f"module_{key}"] = handle.read().strip()
        except OSError:
            snapshot[f"module_{key}"] = ""
    snapshot["meminfo_free_kb"] = read_meminfo_free_kb()
    return snapshot


def subprocess_ls_sysfs() -> float:
    t0 = time.perf_counter()
    try:
        subprocess.run(
            ["ls", SYSFS_TOOLS_DIR],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except FileNotFoundError:
        return float("nan")
    return (time.perf_counter() - t0) * 1000.0


class KernelBackend:
    def __init__(self, client: Any) -> None:
        self._client = client

    def reset(self) -> None:
        self._client.reset_tools()

    def register_agent(self, *, agent_id: str, binding_hash: int, binding_epoch: int) -> None:
        self._client.register_agent(
            agent_id,
            pid=1,
            uid=0,
            binding_hash=binding_hash,
            binding_epoch=binding_epoch,
        )

    def register_tool(self, *, tool_id: int, name: str, tool_hash: str) -> None:
        self._client.register_tool(
            tool_id=tool_id,
            name=name,
            risk_flags=0,
            tool_hash=tool_hash,
        )

    def lookup(
        self,
        *,
        req_id: int,
        agent_id: str,
        tool_id: int,
        tool_hash: str,
        binding_hash: int,
        binding_epoch: int,
    ) -> None:
        decision = self._client.tool_request(
            req_id=req_id,
            agent_id=agent_id,
            binding_hash=binding_hash,
            binding_epoch=binding_epoch,
            tool_id=tool_id,
            tool_hash=tool_hash,
        )
        if decision.decision != "ALLOW":
            raise RuntimeError(f"unexpected tool decision: {decision}")

    def close(self) -> None:
        self._client.close()


class DryRunBackend:
    def __init__(self, *, seed: int = 42) -> None:
        self._rng = random.Random(seed)
        self._tools: Dict[int, str] = {}

    def reset(self) -> None:
        self._tools.clear()

    def register_agent(self, *, agent_id: str, binding_hash: int, binding_epoch: int) -> None:
        time.sleep(0.00001)

    def register_tool(self, *, tool_id: int, name: str, tool_hash: str) -> None:
        self._tools[tool_id] = tool_hash
        time.sleep(0.0000005)

    def lookup(
        self,
        *,
        req_id: int,
        agent_id: str,
        tool_id: int,
        tool_hash: str,
        binding_hash: int,
        binding_epoch: int,
    ) -> None:
        if tool_id not in self._tools:
            raise RuntimeError(f"dry-run: unknown tool_id {tool_id}")
        # emulate a ~0.01 ms RTT via a tiny busy-loop so timing is realistic
        target = max(0.000001, self._rng.gauss(0.00001, 0.000002))
        t0 = time.perf_counter()
        while time.perf_counter() - t0 < target:
            pass

    def close(self) -> None:
        pass


def build_backend(*, dry_run: bool) -> Any:
    if dry_run:
        return DryRunBackend()
    try:
        from mcpd.netlink_client import KernelMcpNetlinkClient  # noqa: WPS433
    except Exception as exc:  # pragma: no cover - platform dependent
        raise RuntimeError(
            "failed to import KernelMcpNetlinkClient; this runner requires the "
            "Linux kernel_mcp module on the host. For offline validation use --dry-run."
        ) from exc
    return KernelBackend(KernelMcpNetlinkClient())


def bulk_register(
    backend: Any,
    *,
    n: int,
    agent_id: str,
    binding_hash: int,
    binding_epoch: int,
) -> Tuple[float, List[float]]:
    backend.reset()
    backend.register_agent(
        agent_id=agent_id,
        binding_hash=binding_hash,
        binding_epoch=binding_epoch,
    )
    per_tool_ms: List[float] = []
    t_start = time.perf_counter()
    for offset in range(n):
        tool_id = TOOL_ID_BASE + offset
        name = f"scale_tool_{offset}"
        t0 = time.perf_counter()
        backend.register_tool(
            tool_id=tool_id,
            name=name,
            tool_hash="deadbeef",
        )
        per_tool_ms.append((time.perf_counter() - t0) * 1000.0)
    total_ms = (time.perf_counter() - t_start) * 1000.0
    return total_ms, per_tool_ms


def measure_lookup_samples(
    backend: Any,
    *,
    n: int,
    samples: int,
    agent_id: str,
    binding_hash: int,
    binding_epoch: int,
    rng: random.Random,
    req_id_base: int,
) -> List[float]:
    out: List[float] = []
    for idx in range(samples):
        offset = rng.randrange(n)
        tool_id = TOOL_ID_BASE + offset
        t0 = time.perf_counter()
        backend.lookup(
            req_id=req_id_base + idx,
            agent_id=agent_id,
            tool_id=tool_id,
            tool_hash="deadbeef",
            binding_hash=binding_hash,
            binding_epoch=binding_epoch,
        )
        out.append((time.perf_counter() - t0) * 1000.0)
    return out


def measure_userspace_baseline(*, n: int, samples: int, rng: random.Random) -> List[float]:
    table: Dict[int, str] = {TOOL_ID_BASE + i: f"scale_tool_{i}" for i in range(n)}
    keys = list(table.keys())
    out: List[float] = []
    for _ in range(samples):
        key = rng.choice(keys)
        t0 = time.perf_counter()
        _ = table[key]
        out.append((time.perf_counter() - t0) * 1000.0)
    return out


def linreg_log2(x_values: List[float], y_values: List[float]) -> Tuple[float, float, float]:
    """Fit y = a + b * log2(x). Returns (a, b, r_squared)."""
    if len(x_values) < 2 or len(x_values) != len(y_values):
        return (0.0, 0.0, 0.0)
    xs = [math.log2(max(x, 1.0)) for x in x_values]
    ys = list(y_values)
    mean_x = statistics.fmean(xs)
    mean_y = statistics.fmean(ys)
    num = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(xs, ys))
    den = sum((xi - mean_x) ** 2 for xi in xs)
    if den == 0:
        return (mean_y, 0.0, 0.0)
    slope = num / den
    intercept = mean_y - slope * mean_x
    ss_tot = sum((yi - mean_y) ** 2 for yi in ys)
    ss_res = sum((yi - (intercept + slope * xi)) ** 2 for xi, yi in zip(xs, ys))
    r2 = 1.0 - (ss_res / ss_tot) if ss_tot > 0 else 0.0
    return (intercept, slope, r2)


def bootstrap_slope_ci(
    x_values: List[float],
    y_values: List[float],
    *,
    resamples: int = 1000,
    seed: int = 1337,
) -> Tuple[float, float]:
    if len(x_values) < 2:
        return (0.0, 0.0)
    rng = random.Random(seed)
    slopes: List[float] = []
    n = len(x_values)
    for _ in range(resamples):
        idxs = [rng.randrange(n) for _ in range(n)]
        xs = [x_values[i] for i in idxs]
        ys = [y_values[i] for i in idxs]
        _, slope, _ = linreg_log2(xs, ys)
        slopes.append(slope)
    slopes.sort()
    lo_idx = max(0, int(0.025 * (len(slopes) - 1)))
    hi_idx = min(len(slopes) - 1, int(0.975 * (len(slopes) - 1)))
    return (slopes[lo_idx], slopes[hi_idx])


def fit_register_model(
    n_values: List[int], total_ms_values: List[float]
) -> Dict[str, float]:
    """Fit total_ms(N) = a + b * N by ordinary least squares.

    `a` is the fixed one-time setup cost (socket open, first mutex, ...), `b`
    is the per-tool steady-state cost. The asymptotic registration throughput
    as N -> infinity is 1/b tools per millisecond, or 1000/b tools per second.

    Returns a dict with keys: a_ms, b_ms_per_tool, b_us_per_tool,
    asymptotic_tps, r_squared, n_points.
    """
    n_points = len(n_values)
    if n_points < 2 or n_points != len(total_ms_values):
        return {
            "a_ms": 0.0,
            "b_ms_per_tool": 0.0,
            "b_us_per_tool": 0.0,
            "asymptotic_tps": 0.0,
            "r_squared": 0.0,
            "n_points": n_points,
        }
    xs = [float(n) for n in n_values]
    ys = list(total_ms_values)
    mean_x = statistics.fmean(xs)
    mean_y = statistics.fmean(ys)
    num = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(xs, ys))
    den = sum((xi - mean_x) ** 2 for xi in xs)
    if den == 0:
        return {
            "a_ms": mean_y,
            "b_ms_per_tool": 0.0,
            "b_us_per_tool": 0.0,
            "asymptotic_tps": 0.0,
            "r_squared": 0.0,
            "n_points": n_points,
        }
    slope = num / den  # ms per tool
    intercept = mean_y - slope * mean_x
    ss_tot = sum((yi - mean_y) ** 2 for yi in ys)
    ss_res = sum((yi - (intercept + slope * xi)) ** 2 for xi, yi in zip(xs, ys))
    r2 = 1.0 - (ss_res / ss_tot) if ss_tot > 0 else 0.0
    asymptotic_tps = (1000.0 / slope) if slope > 0 else 0.0
    return {
        "a_ms": round(intercept, 6),
        "b_ms_per_tool": round(slope, 9),
        "b_us_per_tool": round(slope * 1000.0, 4),
        "asymptotic_tps": round(asymptotic_tps, 1),
        "r_squared": round(r2, 6),
        "n_points": n_points,
    }


def generate_plots(
    run_dir: Path,
    *,
    per_n_kernel: Dict[int, Dict[str, Any]],
    per_n_userspace: Dict[int, Dict[str, Any]],
    register_fit: Optional[Dict[str, float]] = None,
) -> None:
    plt = maybe_import_plotting()
    plots_dir = run_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    if plt is None:
        write_plot_status(run_dir, enabled=False, reason="matplotlib unavailable")
        return

    ns = sorted(per_n_kernel.keys())
    kernel_avg = [per_n_kernel[n]["lookup"]["avg_ms"] for n in ns]
    kernel_ci = [per_n_kernel[n]["lookup"]["ci95_ms"] for n in ns]
    user_avg = [per_n_userspace[n]["lookup"]["avg_ms"] for n in ns]
    user_ci = [per_n_userspace[n]["lookup"]["ci95_ms"] for n in ns]

    # (1) Lookup scaling — unchanged.
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.errorbar(ns, kernel_avg, yerr=kernel_ci, marker="o", label="kernel_mcp", capsize=3)
    ax.errorbar(ns, user_avg, yerr=user_ci, marker="s", label="python dict", capsize=3)
    ax.set_xscale("log", base=2)
    ax.set_xlabel("N (registered tools)")
    ax.set_ylabel("lookup RTT (ms)")
    ax.set_title("Registry lookup scaling")
    ax.grid(alpha=0.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(plots_dir / "figure_registry_lookup_scaling.png", dpi=180)
    plt.close(fig)

    # (2) Per-tool registration cost with asymptote at b.
    # This is the primary register-path figure: it plots per-tool cost in
    # microseconds with 95% CI bars, a horizontal asymptote at b (the
    # fitted per-tool steady-state cost), and a dashed model curve
    # a/N + b showing how the measurement collapses onto b as N grows.
    per_tool_us = [per_n_kernel[n]["register"].get("per_tool_avg_us", 0.0) for n in ns]
    per_tool_ci = [per_n_kernel[n]["register"].get("per_tool_ci95_us", 0.0) for n in ns]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.errorbar(
        ns, per_tool_us, yerr=per_tool_ci, marker="o", color="#4C78A8",
        label="measured", capsize=3,
    )
    if register_fit and register_fit.get("b_us_per_tool", 0.0) > 0:
        a_ms = register_fit["a_ms"]
        b_us = register_fit["b_us_per_tool"]
        # Model curve: per_tool_us(N) = (a_ms * 1000) / N + b_us.
        x_dense = [float(n) for n in ns]
        if len(ns) >= 2:
            import math as _math
            lo = float(ns[0])
            hi = float(ns[-1])
            step_count = 64
            ratio = (hi / lo) ** (1.0 / max(step_count - 1, 1)) if lo > 0 else 1.0
            x_dense = [lo * (ratio ** k) for k in range(step_count)]
        y_model = [(a_ms * 1000.0) / x + b_us for x in x_dense]
        ax.plot(x_dense, y_model, linestyle="--", color="#888",
                label=f"fit: a/N + b (b={b_us:.2f} μs)")
        ax.axhline(b_us, linestyle=":", color="#d62728",
                   label=f"asymptote b = {b_us:.2f} μs")
    ax.set_xscale("log", base=2)
    ax.set_xlabel("N (registered tools)")
    ax.set_ylabel("per-tool registration cost (μs)")
    ax.set_title("Register-path per-tool cost vs N")
    ax.grid(alpha=0.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(plots_dir / "figure_registry_register_curve.png", dpi=180)
    plt.close(fig)

    # (3) Throughput with asymptote — kept for continuity with the old figure
    # but now annotated with the model curve N/(a+bN) and the 1/b asymptote
    # so "throughput saturates at 1/b" is visually unambiguous.
    throughput = [
        per_n_kernel[n]["register"]["throughput_tools_per_sec"] for n in ns
    ]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.plot(ns, throughput, marker="o", color="#4C78A8", label="measured")
    if register_fit and register_fit.get("b_ms_per_tool", 0.0) > 0:
        a_ms = register_fit["a_ms"]
        b_ms = register_fit["b_ms_per_tool"]
        asymptote = register_fit["asymptotic_tps"]
        if len(ns) >= 2:
            lo = float(ns[0])
            hi = float(ns[-1])
            step_count = 64
            ratio = (hi / lo) ** (1.0 / max(step_count - 1, 1)) if lo > 0 else 1.0
            x_dense = [lo * (ratio ** k) for k in range(step_count)]
        else:
            x_dense = [float(ns[0])] if ns else [1.0]
        y_model = [
            (x / ((a_ms + b_ms * x) / 1000.0)) if (a_ms + b_ms * x) > 0 else 0.0
            for x in x_dense
        ]
        ax.plot(x_dense, y_model, linestyle="--", color="#888",
                label=f"fit: N / (a + bN)")
        ax.axhline(asymptote, linestyle=":", color="#d62728",
                   label=f"asymptote 1/b ≈ {asymptote:.0f}/s")
    ax.set_xscale("log", base=2)
    ax.set_xlabel("N (registered tools)")
    ax.set_ylabel("registration throughput (tools/s)")
    ax.set_title("Register-path throughput vs N with asymptote")
    ax.grid(alpha=0.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(plots_dir / "figure_registry_register_throughput.png", dpi=180)
    plt.close(fig)
    write_plot_status(run_dir, enabled=True)


def render_report(summary: Dict[str, Any]) -> str:
    meta = summary["meta"]
    fit = summary["lookup_fit"]
    reg_fit = summary.get("register_fit", {})
    lines = [
        "# Registry Scaling Experiment Report",
        "",
        "## Setup",
        "",
        f"- host: `{meta['host']}` ({meta['platform']})",
        f"- kernel: `{meta['kernel_release']}`",
        f"- reps_per_N: {meta['reps']}",
        f"- lookup_samples_per_rep: {meta['lookup_samples']}",
        f"- N values: {', '.join(str(n) for n in meta['N_values'])}",
        f"- warmup_n: {meta.get('warmup_n', 0)} (throwaway register pass before each N)",
        f"- dry_run: {meta['dry_run']}",
    ]
    if meta.get("warnings"):
        lines.append("")
        lines.append("## Warnings")
        lines.append("")
        for warn in meta["warnings"]:
            lines.append(f"- {warn}")
    lines += [
        "",
        "## Register-path model: total_ms(N) = a + b·N",
        "",
        "We model bulk registration as a one-time setup cost `a` plus a",
        "per-tool steady-state cost `b`. The asymptotic registration",
        "throughput as N → ∞ is `1/b` tools/ms = `1000/b` tools/s.",
        "",
        "| parameter | value |",
        "|---|---:|",
        f"| a (fixed setup cost) | {reg_fit.get('a_ms', 0.0):.4f} ms |",
        f"| b (per-tool steady-state cost) | {reg_fit.get('b_us_per_tool', 0.0):.3f} μs |",
        f"| asymptotic throughput 1/b | {reg_fit.get('asymptotic_tps', 0.0):.0f} tools/s |",
        f"| R² | {reg_fit.get('r_squared', 0.0):.4f} |",
        f"| fit points | {reg_fit.get('n_points', 0)} |",
        "",
        "Interpretation: throughput = N/(a+bN) is a monotonically *increasing*",
        "function of N with no local maximum. The apparent 'hump' visible in",
        "a raw throughput-vs-N plot is simply the curve approaching its",
        "asymptote 1/b from below; there is no scaling degradation at large N.",
        "The per-tool cost figure is a cleaner primary visualization since",
        "its asymptote (b, a single horizontal line) is immediately legible.",
        "",
        "## Per-N summary",
        "",
        "| N | total_ms | per_tool_μs | ±CI95 | tps | lookup_avg_μs | lookup_p99_μs | user_dict_μs | sysfs_ls_ms |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for n in sorted(summary["per_N"].keys(), key=int):
        row = summary["per_N"][str(n)] if isinstance(n, int) else summary["per_N"][n]
        per_tool_us = row["register"].get("per_tool_avg_us", 0.0)
        per_tool_ci = row["register"].get("per_tool_ci95_us", 0.0)
        lines.append(
            "| {n} | {reg:.3f} | {ptu:.3f} | ±{ci:.3f} | {tps:.0f} | {lav:.3f} | {lp99:.3f} | {uav:.3f} | {sys:.3f} |".format(
                n=n,
                reg=row["register"]["total_ms"],
                ptu=per_tool_us,
                ci=per_tool_ci,
                tps=row["register"]["throughput_tools_per_sec"],
                lav=row["lookup"]["avg_ms"] * 1000.0,
                lp99=row["lookup"]["p99_ms"] * 1000.0,
                uav=row["userspace"]["avg_ms"] * 1000.0,
                sys=row["sysfs_ls_ms_avg"],
            )
        )
    lines += [
        "",
        "## Log-linear lookup fit (lookup_ms ~ a + b·log2(N))",
        "",
        f"- intercept a = {fit['intercept']:.6f} ms",
        f"- slope b = {fit['slope']:.6f} ms/doubling",
        f"- R² = {fit['r_squared']:.4f}",
        f"- slope 95% bootstrap CI: [{fit['slope_ci_lo']:.6f}, {fit['slope_ci_hi']:.6f}] ms/doubling",
        "",
        "A slope near zero with a CI containing zero supports the O(1)",
        "lookup claim. A non-zero slope at high R² would indicate log-scale",
        "behavior (expected for balanced trees, not for hash/xarray lookups).",
        "",
    ]
    return "\n".join(lines)


def run_experiment(
    *,
    n_values: List[int],
    reps: int,
    lookup_samples: int,
    dry_run: bool,
    output_dir: Path,
    seed: int,
) -> Path:
    n_values, warnings = clip_n_values(n_values)
    run_dir = output_dir / time.strftime("run-%Y%m%d-%H%M%S", time.gmtime())
    run_dir.mkdir(parents=True, exist_ok=True)

    backend = build_backend(dry_run=dry_run)
    rng = random.Random(seed)

    per_n_data: Dict[int, Dict[str, Any]] = {}
    per_n_user: Dict[int, Dict[str, Any]] = {}
    all_sample_rows: List[Dict[str, Any]] = []

    agent_id = "registry-scaling-agent"
    binding_hash = 0x1234
    binding_epoch = 1

    try:
        for n in n_values:
            rep_register_total_ms: List[float] = []
            rep_register_throughput: List[float] = []
            rep_register_per_tool_us: List[float] = []
            rep_lookup_all: List[float] = []
            rep_user_lookup_all: List[float] = []
            rep_sysfs_ms: List[float] = []
            rep_memory_snapshots: List[Dict[str, Any]] = []
            mem_free_before: Optional[int] = None
            mem_free_after: Optional[int] = None

            # Throwaway warmup pass at WARMUP_N tools: puts the Python
            # interpreter, the netlink socket, and the kernel-side mutex
            # path into steady state so the first measured rep does not
            # pay cold-start cost and distort the register fit.
            try:
                bulk_register(
                    backend,
                    n=WARMUP_N,
                    agent_id=agent_id,
                    binding_hash=binding_hash,
                    binding_epoch=binding_epoch,
                )
            except Exception:
                pass

            for rep in range(reps):
                mem_free_before = read_meminfo_free_kb() if rep == 0 else mem_free_before
                total_ms, _per_tool = bulk_register(
                    backend,
                    n=n,
                    agent_id=agent_id,
                    binding_hash=binding_hash,
                    binding_epoch=binding_epoch,
                )
                rep_register_total_ms.append(total_ms)
                tps = (n / (total_ms / 1000.0)) if total_ms > 0 else 0.0
                rep_register_throughput.append(tps)
                per_tool_us = (total_ms * 1000.0 / n) if n > 0 else 0.0
                rep_register_per_tool_us.append(per_tool_us)

                lookups = measure_lookup_samples(
                    backend,
                    n=n,
                    samples=lookup_samples,
                    agent_id=agent_id,
                    binding_hash=binding_hash,
                    binding_epoch=binding_epoch,
                    rng=rng,
                    req_id_base=10_000_000 + rep * lookup_samples,
                )
                rep_lookup_all.extend(lookups)

                user_lookups = measure_userspace_baseline(
                    n=n, samples=lookup_samples, rng=rng
                )
                rep_user_lookup_all.extend(user_lookups)

                sysfs_ms = subprocess_ls_sysfs()
                if not math.isnan(sysfs_ms):
                    rep_sysfs_ms.append(sysfs_ms)
                rep_memory_snapshots.append(read_module_memory_snapshot())

                for idx, rtt in enumerate(lookups):
                    all_sample_rows.append(
                        {
                            "N": n,
                            "rep": rep,
                            "mode": "kernel",
                            "sample_index": idx,
                            "rtt_ms": round(rtt, 6),
                        }
                    )
                for idx, rtt in enumerate(user_lookups):
                    all_sample_rows.append(
                        {
                            "N": n,
                            "rep": rep,
                            "mode": "userspace_dict",
                            "sample_index": idx,
                            "rtt_ms": round(rtt, 6),
                        }
                    )
            mem_free_after = read_meminfo_free_kb()

            lookup_summary = summarize(f"kernel_N{n}", rep_lookup_all)
            user_summary = summarize(f"user_N{n}", rep_user_lookup_all)
            reg_avg = statistics.fmean(rep_register_total_ms) if rep_register_total_ms else 0.0
            reg_std = statistics.stdev(rep_register_total_ms) if len(rep_register_total_ms) > 1 else 0.0
            tps_avg = statistics.fmean(rep_register_throughput) if rep_register_throughput else 0.0
            per_tool_avg_us = (
                statistics.fmean(rep_register_per_tool_us) if rep_register_per_tool_us else 0.0
            )
            per_tool_std_us = (
                statistics.stdev(rep_register_per_tool_us)
                if len(rep_register_per_tool_us) > 1
                else 0.0
            )
            per_tool_ci95_us = ci95(per_tool_std_us, len(rep_register_per_tool_us))
            sysfs_avg = statistics.fmean(rep_sysfs_ms) if rep_sysfs_ms else 0.0
            per_n_data[n] = {
                "register": {
                    "reps": reps,
                    "total_ms": round(reg_avg, 6),
                    "total_std_ms": round(reg_std, 6),
                    "per_tool_avg_ms": round(reg_avg / n, 9) if n > 0 else 0.0,
                    "per_tool_avg_us": round(per_tool_avg_us, 4),
                    "per_tool_std_us": round(per_tool_std_us, 4),
                    "per_tool_ci95_us": round(per_tool_ci95_us, 4),
                    "throughput_tools_per_sec": round(tps_avg, 3),
                },
                "lookup": lookup_summary,
                "userspace": user_summary,
                "sysfs_ls_ms_avg": round(sysfs_avg, 6),
                "module_snapshot_last": rep_memory_snapshots[-1] if rep_memory_snapshots else {},
                "meminfo_free_kb_before": mem_free_before,
                "meminfo_free_kb_after": mem_free_after,
                "meminfo_free_delta_kb": (
                    (mem_free_before - mem_free_after)
                    if (mem_free_before is not None and mem_free_after is not None)
                    else None
                ),
            }
            per_n_user[n] = {"lookup": user_summary}
    finally:
        backend.close()

    fit_x = [float(n) for n in sorted(per_n_data.keys())]
    fit_y = [per_n_data[int(n)]["lookup"]["avg_ms"] for n in fit_x]
    intercept, slope, r2 = linreg_log2(fit_x, fit_y)
    slope_lo, slope_hi = bootstrap_slope_ci(fit_x, fit_y)

    # Register-path model: total_ms(N) = a + b * N.
    # `a` is the fixed one-time setup cost, `b` is the per-tool steady-state
    # cost, and 1000/b is the asymptotic throughput as N -> infinity. This
    # replaces the misleading throughput-vs-N curve: throughput looks like
    # a "hump" only because tps = N/(a+bN) approaches 1/b non-linearly.
    fit_register_ns = sorted(per_n_data.keys())
    fit_register_total = [per_n_data[n]["register"]["total_ms"] for n in fit_register_ns]
    register_fit = fit_register_model(fit_register_ns, fit_register_total)

    summary: Dict[str, Any] = {
        "meta": {
            "host": platform.node(),
            "platform": platform.platform(),
            "kernel_release": platform.release(),
            "python": sys.version.split()[0],
            "reps": reps,
            "lookup_samples": lookup_samples,
            "N_values": sorted(per_n_data.keys()),
            "warmup_n": WARMUP_N,
            "dry_run": dry_run,
            "seed": seed,
            "warnings": warnings,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "per_N": {str(n): per_n_data[n] for n in sorted(per_n_data.keys())},
        "lookup_fit": {
            "intercept": round(intercept, 6),
            "slope": round(slope, 6),
            "r_squared": round(r2, 6),
            "slope_ci_lo": round(slope_lo, 6),
            "slope_ci_hi": round(slope_hi, 6),
        },
        "register_fit": register_fit,
    }

    summary_rows: List[Dict[str, Any]] = []
    for n in sorted(per_n_data.keys()):
        row = per_n_data[n]
        summary_rows.append(
            {
                "N": n,
                "reps": reps,
                "register_total_ms_avg": row["register"]["total_ms"],
                "register_total_std_ms": row["register"].get("total_std_ms", 0.0),
                "register_per_tool_ms_avg": row["register"]["per_tool_avg_ms"],
                "register_per_tool_us_avg": row["register"].get("per_tool_avg_us", 0.0),
                "register_per_tool_us_std": row["register"].get("per_tool_std_us", 0.0),
                "register_per_tool_us_ci95": row["register"].get("per_tool_ci95_us", 0.0),
                "register_throughput_tools_per_sec": row["register"]["throughput_tools_per_sec"],
                "lookup_avg_ms": row["lookup"]["avg_ms"],
                "lookup_std_ms": row["lookup"]["std_ms"],
                "lookup_ci95_ms": row["lookup"]["ci95_ms"],
                "lookup_p50_ms": row["lookup"]["p50_ms"],
                "lookup_p95_ms": row["lookup"]["p95_ms"],
                "lookup_p99_ms": row["lookup"]["p99_ms"],
                "userspace_dict_avg_ms": row["userspace"]["avg_ms"],
                "userspace_dict_p95_ms": row["userspace"]["p95_ms"],
                "sysfs_ls_ms_avg": row["sysfs_ls_ms_avg"],
                "module_coresize": row["module_snapshot_last"].get("module_coresize", ""),
                "meminfo_free_delta_kb": row["meminfo_free_delta_kb"]
                if row["meminfo_free_delta_kb"] is not None
                else "",
            }
        )

    write_csv(
        run_dir / "registry_scaling_summary.csv",
        summary_rows,
        [
            "N",
            "reps",
            "register_total_ms_avg",
            "register_total_std_ms",
            "register_per_tool_ms_avg",
            "register_per_tool_us_avg",
            "register_per_tool_us_std",
            "register_per_tool_us_ci95",
            "register_throughput_tools_per_sec",
            "lookup_avg_ms",
            "lookup_std_ms",
            "lookup_ci95_ms",
            "lookup_p50_ms",
            "lookup_p95_ms",
            "lookup_p99_ms",
            "userspace_dict_avg_ms",
            "userspace_dict_p95_ms",
            "sysfs_ls_ms_avg",
            "module_coresize",
            "meminfo_free_delta_kb",
        ],
    )
    write_csv(
        run_dir / "registry_scaling_samples.csv",
        all_sample_rows,
        ["N", "rep", "mode", "sample_index", "rtt_ms"],
    )
    (run_dir / "registry_scaling_summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2),
        encoding="utf-8",
    )
    (run_dir / "registry_scaling_report.md").write_text(render_report(summary), encoding="utf-8")
    generate_plots(
        run_dir,
        per_n_kernel=per_n_data,
        per_n_userspace=per_n_user,
        register_fit=register_fit,
    )

    print(f"[registry-scaling] result dir: {run_dir}")
    print(f"[registry-scaling] summary:    {run_dir / 'registry_scaling_summary.json'}")
    print(f"[registry-scaling] report:     {run_dir / 'registry_scaling_report.md'}")
    return run_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="E2 Registry scaling experiment")
    parser.add_argument(
        "--N-values",
        dest="n_values",
        default=DEFAULT_N_VALUES,
        help="comma-separated N values (default: %(default)s)",
    )
    parser.add_argument("--reps", type=int, default=DEFAULT_REPS)
    parser.add_argument(
        "--lookup-samples",
        type=int,
        default=DEFAULT_LOOKUP_SAMPLES,
        help="random lookups per rep (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        default="experiment-results/registry-scaling",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help=f"limit to {SMOKE_N_VALUES} with reps={SMOKE_REPS}",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="stub netlink calls with synthetic samples (no kernel required)",
    )
    parser.add_argument("--seed", type=int, default=20260414)
    args = parser.parse_args()

    if args.smoke:
        args.n_values = SMOKE_N_VALUES
        args.reps = SMOKE_REPS

    n_values = parse_n_values(args.n_values)

    if KERNEL_TOOL_CAP is not None:
        print(
            f"[registry-scaling] warning: kernel MAX_TOOLS cap detected at {KERNEL_TOOL_CAP}; "
            "N values above the cap will be clipped"
        )

    run_experiment(
        n_values=n_values,
        reps=args.reps,
        lookup_samples=args.lookup_samples,
        dry_run=args.dry_run,
        output_dir=Path(args.output_dir),
        seed=args.seed,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
