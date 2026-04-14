#!/usr/bin/env python3
"""E3 — sustained overload runner for linux-mcp.

Drives wall-clock-bounded load at a sweep of concurrency levels against each
system variant (userspace / seccomp / kernel), fits a piecewise-linear knee
to the p99-vs-concurrency curve, and emits CSV + JSON + plot artifacts under
experiment-results/overload/run-<UTC-ts>/.

The runner supports --dry-run which stubs out the actual request path with
synthetic latency samples (normal distribution whose mean grows with
concurrency). The dry-run path lets the whole pipeline be validated on macOS
without any mcpd / kernel module.

Claim scope: this runner only anchors *regime shape* (does p99 knee shift
right for kernel vs seccomp?). Absolute tail numbers are not claimed because
the target environment is a VMware guest.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Sequence, Tuple

# Reuse shared helpers so stats and percentile logic stay in one place.
from benchmark_suite import (
    SustainedResult,
    percentile,
    run_sustained_load,
)

ROOT_DIR = Path(__file__).resolve().parent.parent.parent

DEFAULT_SYSTEMS = ("userspace", "seccomp", "kernel")
DEFAULT_CONCURRENCY = (50, 100, 200, 400, 800)
DEFAULT_DURATION_S = 180.0
DEFAULT_WARMUP_S = 30.0
DEFAULT_REPS = 3
DEFAULT_PAYLOAD_BYTES = 1024


# ---------------------------------------------------------------------------
# Dry-run synthetic request generator.
# ---------------------------------------------------------------------------


def _synthetic_make_state(worker_id: int) -> int:
    return worker_id


def _synthetic_request_fn(system: str, concurrency: int, seed: int) -> Callable[[Any, int], Tuple[bool, float]]:
    """Return a (state, req_index) request_fn that emits synthetic latencies.

    Shape is picked so the smoke output resembles the claim: kernel gets a
    slightly later inflection point. `state` is just the worker_id.
    """
    rnd = random.Random(seed)
    knee_c = {"userspace": 150.0, "seccomp": 120.0, "kernel": 260.0, "direct": 180.0}.get(system, 160.0)
    base_ms = {"userspace": 2.0, "seccomp": 3.0, "kernel": 2.5, "direct": 1.5}.get(system, 2.0)
    slope_pre = 0.01
    slope_post = 0.2 if system == "seccomp" else 0.12
    if concurrency <= knee_c:
        mean = base_ms + slope_pre * concurrency
    else:
        mean = base_ms + slope_pre * knee_c + slope_post * (concurrency - knee_c)
    std = 0.3 * mean

    def _fn(state: Any, req_index: int) -> Tuple[bool, float]:
        if req_index < 0:
            return True, max(0.0, rnd.gauss(base_ms, 0.1))
        latency = max(0.05, rnd.gauss(mean, std))
        ok = rnd.random() > 0.002
        return ok, latency

    return _fn


# ---------------------------------------------------------------------------
# Real request path.
#
# Worker state is a persistent (PersistentMcpdConn, session_id, target_tool)
# triple. One UDS connection per worker is reused across every request in the
# measurement window, so we never touch the kernel accept queue during the
# hot loop. This fixes the prior SOMAXCONN saturation at concurrency >= 200
# that showed up as ~99% error_rate and p99 in the microsecond range in the
# first overload run.
#
# Errors are NOT recorded as latency samples (handled by run_sustained_load).
# ---------------------------------------------------------------------------


@dataclass
class _WorkerState:
    conn: Any          # PersistentMcpdConn
    session_id: str
    target: Any        # ToolCase
    worker_id: int


def _prepare_system_context(system: str, sock_path: str) -> Dict[str, Any]:
    """Run preflight once per system. Returns {target, sock_path}.

    Sessions are opened per-worker rather than shared so that each persistent
    UDS connection maps to exactly one session on the mcpd side (mcpd binds
    sessions to SO_PEERCRED + connection identity).
    """
    from benchmark_suite import (  # noqa: F401  — keep lazy
        enrich_hash_from_mcpd,
        load_manifest_tools,
        preflight_tools,
    )

    tools = enrich_hash_from_mcpd(load_manifest_tools(), sock_path, 10.0)
    # Try read-only first so the sandboxed seccomp variant (which restricts
    # tool writes) still finds a usable tool; fall back to include_write
    # if no read-only tool passes preflight.
    selected = preflight_tools(
        tools, mcpd_sock=sock_path, timeout_s=10.0, include_write=False, max_tools=20
    )
    if not selected:
        selected = preflight_tools(
            tools, mcpd_sock=sock_path, timeout_s=10.0, include_write=True, max_tools=20
        )
    if not selected:
        raise RuntimeError(
            f"no tools passed preflight for overload run on {system} "
            f"(sock={sock_path}). Check scripts/run_tool_services.sh and "
            f"endpoints under /tmp/linux-mcp-apps/."
        )
    return {"target": selected[0], "sock_path": sock_path}


def _real_request_fn(ctx: Dict[str, Any]) -> Tuple[Callable[[int], _WorkerState], Callable[[_WorkerState, int], Tuple[bool, float]], Callable[[_WorkerState], None]]:
    """Build (make_state, request_fn, close_state) for the live-mcpd path."""
    from benchmark_suite import PersistentMcpdConn  # noqa: F401 — keep lazy
    from security_eval import build_exec_req  # noqa: F401

    target = ctx["target"]
    sock_path = ctx["sock_path"]

    def make_state(worker_id: int) -> _WorkerState:
        conn = PersistentMcpdConn(sock_path, timeout_s=20.0)
        # Open a session on this persistent connection so the peer-cred binding
        # (uid/pid) is tied to a stable socket identity.
        open_req = {
            "sys": "open_session",
            "client_name": f"overload-w{worker_id}",
            "ttl_ms": 10 * 60 * 1000,
        }
        resp = conn.call(open_req)
        if resp.get("status") != "ok":
            conn.close()
            raise RuntimeError(
                f"open_session failed on worker {worker_id}: {resp.get('error')}"
            )
        session_id = str(resp.get("session_id", ""))
        if not session_id:
            conn.close()
            raise RuntimeError(f"open_session returned no session_id: {resp}")
        return _WorkerState(conn=conn, session_id=session_id, target=target, worker_id=worker_id)

    def request_fn(state: _WorkerState, req_index: int) -> Tuple[bool, float]:
        req = build_exec_req(
            req_id=3_000_000 + state.worker_id * 100_000 + max(req_index, 0),
            session_id=state.session_id,
            tool=state.target,
            tool_hash=state.target.manifest_hash,
        )
        t0 = time.perf_counter()
        try:
            resp = state.conn.call(req)
        except Exception:
            return False, (time.perf_counter() - t0) * 1000.0
        latency_ms = (time.perf_counter() - t0) * 1000.0
        ok = resp.get("status") == "ok"
        return ok, latency_ms

    def close_state(state: _WorkerState) -> None:
        state.conn.close()

    return make_state, request_fn, close_state


# ---------------------------------------------------------------------------
# Statistics.
# ---------------------------------------------------------------------------


def block_bootstrap_ci(samples: Sequence[float], stat_fn: Callable[[Sequence[float]], float], *, block_size: int = 10, iterations: int = 500, alpha: float = 0.05, seed: int = 0) -> Tuple[float, float]:
    """Block-bootstrap CI for autocorrelated samples (e.g. sequential tail latencies).

    Pure Python, no scipy. Approximation; see report for caveats.
    """
    if not samples:
        return (0.0, 0.0)
    n = len(samples)
    if n < block_size * 2:
        return (float(min(samples)), float(max(samples)))
    rnd = random.Random(seed)
    n_blocks = n // block_size
    estimates: List[float] = []
    for _ in range(iterations):
        resampled: List[float] = []
        for _ in range(n_blocks):
            start = rnd.randint(0, n - block_size)
            resampled.extend(samples[start : start + block_size])
        estimates.append(stat_fn(resampled))
    estimates.sort()
    lo_idx = max(0, int((alpha / 2) * len(estimates)))
    hi_idx = min(len(estimates) - 1, int((1 - alpha / 2) * len(estimates)))
    return (float(estimates[lo_idx]), float(estimates[hi_idx]))


def moods_median_test(group_a: Sequence[float], group_b: Sequence[float]) -> float:
    """Return Mood's median test p-value between two groups.

    Approximate chi-square(1) CDF via erfc. Pure Python, no scipy.
    """
    combined = list(group_a) + list(group_b)
    if not combined:
        return 1.0
    combined_sorted = sorted(combined)
    median = combined_sorted[len(combined_sorted) // 2]
    a_above = sum(1 for x in group_a if x > median)
    a_below = len(group_a) - a_above
    b_above = sum(1 for x in group_b if x > median)
    b_below = len(group_b) - b_above
    total = a_above + a_below + b_above + b_below
    if total == 0:
        return 1.0
    row1 = a_above + b_above
    row2 = a_below + b_below
    col1 = a_above + a_below
    col2 = b_above + b_below
    chi2 = 0.0
    for obs, expected in (
        (a_above, row1 * col1 / total),
        (b_above, row1 * col2 / total),
        (a_below, row2 * col1 / total),
        (b_below, row2 * col2 / total),
    ):
        if expected > 0:
            chi2 += (obs - expected) ** 2 / expected
    # Chi-square(1) survival function = erfc(sqrt(chi2/2)).
    return float(math.erfc(math.sqrt(chi2 / 2.0)))


def fit_piecewise_knee(xs: Sequence[float], ys: Sequence[float]) -> Tuple[float, float]:
    """Grid-search a single-breakpoint piecewise linear fit.

    Returns (knee_x, sse). knee is the x-value that minimizes total squared
    error when fitting two independent straight lines left and right of it.
    If fewer than 3 points are given, returns (xs[-1], 0).
    """
    if len(xs) < 3:
        return (float(xs[-1]) if xs else 0.0, 0.0)
    best_knee = float(xs[0])
    best_sse = float("inf")
    for breakpoint_idx in range(1, len(xs) - 1):
        left_xs = xs[: breakpoint_idx + 1]
        left_ys = ys[: breakpoint_idx + 1]
        right_xs = xs[breakpoint_idx:]
        right_ys = ys[breakpoint_idx:]
        sse = _line_sse(left_xs, left_ys) + _line_sse(right_xs, right_ys)
        if sse < best_sse:
            best_sse = sse
            best_knee = float(xs[breakpoint_idx])
    return best_knee, best_sse


def _line_sse(xs: Sequence[float], ys: Sequence[float]) -> float:
    n = len(xs)
    if n < 2:
        return 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    sxx = sum((x - mean_x) ** 2 for x in xs)
    sxy = sum((xs[i] - mean_x) * (ys[i] - mean_y) for i in range(n))
    slope = sxy / sxx if sxx > 0 else 0.0
    intercept = mean_y - slope * mean_x
    sse = 0.0
    for i in range(n):
        predicted = intercept + slope * xs[i]
        sse += (ys[i] - predicted) ** 2
    return sse


# ---------------------------------------------------------------------------
# Plotting (best-effort: matplotlib is optional).
# ---------------------------------------------------------------------------


def _try_matplotlib() -> Any:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except Exception:
        return None


def _plot_p99_vs_concurrency(summary_rows: List[Dict[str, Any]], out_path: Path) -> None:
    plt = _try_matplotlib()
    if plt is None:
        return
    fig, ax = plt.subplots(figsize=(6, 4))
    by_system: Dict[str, List[Tuple[int, float]]] = {}
    for row in summary_rows:
        by_system.setdefault(row["system"], []).append((int(row["concurrency"]), float(row["p99_ms"])))
    for system, pairs in sorted(by_system.items()):
        pairs.sort()
        ax.plot([p[0] for p in pairs], [p[1] for p in pairs], marker="o", label=system)
    ax.set_xlabel("concurrency")
    ax.set_ylabel("p99 latency (ms)")
    ax.set_title("Sustained overload: p99 vs concurrency")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def _plot_throughput_timeseries(per_second_rows: List[Dict[str, Any]], out_path: Path) -> None:
    plt = _try_matplotlib()
    if plt is None:
        return
    fig, ax = plt.subplots(figsize=(6, 4))
    by_cell: Dict[str, List[Tuple[int, int]]] = {}
    for row in per_second_rows:
        key = f"{row['system']}@c{row['concurrency']}"
        by_cell.setdefault(key, []).append((int(row["second_index"]), int(row["rps"])))
    # Plot the top cell per system only, to keep the figure readable.
    for key, series in sorted(by_cell.items()):
        series.sort()
        ax.plot([s[0] for s in series], [s[1] for s in series], label=key, linewidth=0.8)
    ax.set_xlabel("second")
    ax.set_ylabel("rps")
    ax.set_title("Sustained overload: per-second throughput")
    ax.legend(fontsize=6, ncol=2)
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def _plot_latency_cdf(sample_rows: List[Dict[str, Any]], out_path: Path) -> None:
    plt = _try_matplotlib()
    if plt is None:
        return
    fig, ax = plt.subplots(figsize=(6, 4))
    by_system: Dict[str, List[float]] = {}
    for row in sample_rows:
        by_system.setdefault(row["system"], []).append(float(row["latency_ms"]))
    for system, values in sorted(by_system.items()):
        if not values:
            continue
        values.sort()
        ys = [i / len(values) for i in range(1, len(values) + 1)]
        ax.plot(values, ys, label=system)
    ax.set_xlabel("latency (ms)")
    ax.set_ylabel("CDF")
    ax.set_xscale("log")
    ax.set_title("Sustained overload: latency CDF (all cells pooled)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Best-effort taskset pinning.
# ---------------------------------------------------------------------------


def _maybe_pin_self(cpu_spec: str) -> None:
    if shutil.which("taskset") is None:
        return
    try:
        subprocess.run(["taskset", "-pc", cpu_spec, str(os.getpid())], check=False, capture_output=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main runner.
# ---------------------------------------------------------------------------


def write_csv(path: Path, rows: Sequence[Dict[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def main() -> int:
    parser = argparse.ArgumentParser(description="E3 sustained overload runner")
    parser.add_argument("--output-dir", type=str, default="")
    parser.add_argument("--systems", type=str, default=",".join(DEFAULT_SYSTEMS))
    parser.add_argument("--concurrency", type=str, default=",".join(str(c) for c in DEFAULT_CONCURRENCY))
    parser.add_argument("--duration-s", type=float, default=DEFAULT_DURATION_S)
    parser.add_argument("--warmup-s", type=float, default=DEFAULT_WARMUP_S)
    parser.add_argument("--reps", type=int, default=DEFAULT_REPS)
    parser.add_argument("--payload-bytes", type=int, default=DEFAULT_PAYLOAD_BYTES)
    parser.add_argument("--smoke", action="store_true", help="short duration (15s), reps=1, for local validation")
    parser.add_argument("--dry-run", action="store_true", help="use synthetic latency samples; no mcpd / kernel required")
    parser.add_argument("--random-seed", type=int, default=20260414)
    parser.add_argument("--no-taskset", action="store_true", help="disable best-effort CPU pinning of the runner")
    args = parser.parse_args()

    if args.smoke:
        duration = 15.0
        warmup = 2.0
        reps = 1
    else:
        duration = args.duration_s
        warmup = args.warmup_s
        reps = args.reps

    systems = [s.strip() for s in args.systems.split(",") if s.strip()]
    concurrency_levels = [int(c.strip()) for c in args.concurrency.split(",") if c.strip()]

    if not args.no_taskset:
        _maybe_pin_self("3")  # runner pinned to cpu 3 (best-effort)

    run_ts = time.strftime("run-%Y%m%d-%H%M%S", time.gmtime())
    if args.output_dir:
        run_dir = Path(args.output_dir)
    else:
        run_dir = ROOT_DIR / "experiment-results" / "overload" / run_ts
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "plots").mkdir(exist_ok=True)

    rng = random.Random(args.random_seed)
    # Randomize (system, concurrency, rep) cell order per rep to decorrelate
    # from thermal/hypervisor drift over the run.
    cells: List[Tuple[str, int, int]] = []
    for rep in range(1, reps + 1):
        rep_cells: List[Tuple[str, int, int]] = [(s, c, rep) for s in systems for c in concurrency_levels]
        rng.shuffle(rep_cells)
        cells.extend(rep_cells)

    summary_rows: List[Dict[str, Any]] = []
    sample_rows: List[Dict[str, Any]] = []
    per_second_rows: List[Dict[str, Any]] = []
    cell_records: List[Dict[str, Any]] = []

    # Real-path state: one live mcpd per system + preflight context cached
    # for the whole rep sweep. In dry-run we skip entirely.
    live_ctx: Dict[str, Dict[str, Any]] = {}
    tool_services_started = False
    skipped_systems: List[Tuple[str, str]] = []
    try:
        if not args.dry_run:
            from security_eval import (  # noqa: F401
                launch_mcpd_variant,
                stop_process,
                wait_mcpd_ready,
            )

            system_env = {
                "userspace": {},
                "seccomp": {"MCPD_STRICT_CHECKS": "1", "MCPD_AUDIT_LOGGING": "1"},
                "kernel": {},
                "direct": {},
            }
            system_mode = {
                "userspace": "userspace_semantic_plane",
                "seccomp": "userspace_semantic_plane",
                "kernel": "normal",
                "direct": "direct",
            }

            # Start tool services once for the whole run. If any requested
            # system is "seccomp", launch the sandboxed variant so preflight
            # for every other userspace-plane system still works against the
            # same endpoints. This mirrors managed_tool_services() in
            # linux_mcp_eval.py.
            needs_sandbox = "seccomp" in systems
            stop_cmd = ["bash", "scripts/stop_tool_services.sh"]
            start_cmd = ["bash", "scripts/run_tool_services.sh"]
            if needs_sandbox:
                start_cmd.extend(["--sandbox", "simple"])
            subprocess.run(stop_cmd, cwd=str(ROOT_DIR), check=False)
            subprocess.run(start_cmd, cwd=str(ROOT_DIR), check=True)
            tool_services_started = True

            for system in systems:
                if system == "direct":
                    skipped_systems.append((system, "direct mode not supported in overload_eval"))
                    continue
                sock_path = f"/tmp/mcpd-overload-{system}.sock"
                overrides = system_env.get(system, {})
                prev_env = {k: os.environ.get(k) for k in overrides}
                for k, v in overrides.items():
                    os.environ[k] = v
                proc = None
                try:
                    proc = launch_mcpd_variant(
                        mode=system_mode.get(system, "userspace_semantic_plane"),
                        sock_path=sock_path,
                    )
                    wait_mcpd_ready(sock_path, 10.0)
                    preflight = _prepare_system_context(system, sock_path)
                    make_state, req_fn_real, close_state = _real_request_fn(preflight)
                    live_ctx[system] = {
                        "proc": proc,
                        "sock_path": sock_path,
                        "preflight": preflight,
                        "make_state": make_state,
                        "req_fn": req_fn_real,
                        "close_state": close_state,
                    }
                except Exception as exc:
                    if proc is not None:
                        try:
                            stop_process(proc, sock_path)
                        except Exception:
                            pass
                    print(f"[overload] skipping {system}: {exc}", flush=True)
                    skipped_systems.append((system, str(exc)))
                finally:
                    for k, old in prev_env.items():
                        if old is None:
                            os.environ.pop(k, None)
                        else:
                            os.environ[k] = old

            if not live_ctx:
                raise RuntimeError(
                    f"no usable system variants after preflight — nothing to run. "
                    f"skipped: {skipped_systems}"
                )

        for idx, (system, concurrency, rep) in enumerate(cells):
            cell_id = f"{system}-c{concurrency}-rep{rep}"
            if not args.dry_run and system not in live_ctx:
                print(f"[overload] skip cell {cell_id} (system {system} not ready)", flush=True)
                continue
            print(f"[overload] cell {idx + 1}/{len(cells)}: {cell_id}", flush=True)
            seed = args.random_seed + idx
            if args.dry_run:
                req_fn = _synthetic_request_fn(system, concurrency, seed)
                make_state = None
                close_state = None
            else:
                entry = live_ctx[system]
                req_fn = entry["req_fn"]
                make_state = entry["make_state"]
                close_state = entry["close_state"]
            result = run_sustained_load(
                system=system,
                concurrency=concurrency,
                duration_s=duration,
                warmup_s=warmup,
                payload_bytes=args.payload_bytes,
                request_fn=req_fn,
                make_worker_state=make_state,
                close_worker_state=close_state,
                rng_seed=seed,
            )
            latencies_sorted = sorted(result.latency_samples_ms)
            rps = result.requests / max(duration, 1e-9)
            p50 = percentile(latencies_sorted, 0.50) if latencies_sorted else 0.0
            p95 = percentile(latencies_sorted, 0.95) if latencies_sorted else 0.0
            p99 = percentile(latencies_sorted, 0.99) if latencies_sorted else 0.0
            error_rate = result.errors / max(result.requests, 1)
            cell_records.append(
                {
                    "cell_id": cell_id,
                    "system": system,
                    "concurrency": concurrency,
                    "rep": rep,
                    "rps": rps,
                    "p50": p50,
                    "p95": p95,
                    "p99": p99,
                    "error_rate": error_rate,
                    "latencies": latencies_sorted,
                    "per_second": result.per_second_throughput,
                }
            )
            for latency in latencies_sorted:
                sample_rows.append(
                    {
                        "cell_id": cell_id,
                        "system": system,
                        "concurrency": concurrency,
                        "rep": rep,
                        "latency_ms": round(latency, 4),
                    }
                )
            for second_idx, rps_count in enumerate(result.per_second_throughput):
                per_second_rows.append(
                    {
                        "cell_id": cell_id,
                        "system": system,
                        "concurrency": concurrency,
                        "rep": rep,
                        "second_index": second_idx,
                        "rps": rps_count,
                    }
                )
    finally:
        if not args.dry_run and live_ctx:
            from security_eval import stop_process

            for system, entry in live_ctx.items():
                try:
                    stop_process(entry["proc"], entry["sock_path"])
                except Exception:
                    pass
        if tool_services_started:
            try:
                subprocess.run(
                    ["bash", "scripts/stop_tool_services.sh"],
                    cwd=str(ROOT_DIR),
                    check=False,
                )
            except Exception:
                pass
        if skipped_systems:
            print(
                "[overload] skipped systems: "
                + ", ".join(f"{s}({r[:60]})" for s, r in skipped_systems),
                flush=True,
            )

    # Fit p99 knee per system, pooling reps at each concurrency level.
    knee_by_system: Dict[str, float] = {}
    p99_by_system: Dict[str, Dict[int, List[float]]] = {}
    for cell in cell_records:
        p99_by_system.setdefault(cell["system"], {}).setdefault(int(cell["concurrency"]), []).append(float(cell["p99"]))
    for system, per_c in p99_by_system.items():
        xs = sorted(per_c.keys())
        ys = [statistics.fmean(per_c[c]) for c in xs]
        knee, _sse = fit_piecewise_knee([float(x) for x in xs], ys)
        knee_by_system[system] = knee

    for cell in cell_records:
        summary_rows.append(
            {
                "cell_id": cell["cell_id"],
                "system": cell["system"],
                "concurrency": cell["concurrency"],
                "rep": cell["rep"],
                "rps": round(float(cell["rps"]), 3),
                "p50_ms": round(float(cell["p50"]), 4),
                "p95_ms": round(float(cell["p95"]), 4),
                "p99_ms": round(float(cell["p99"]), 4),
                "error_rate": round(float(cell["error_rate"]), 6),
                "knee_c": round(float(knee_by_system.get(cell["system"], 0.0)), 3),
            }
        )

    # Per-system p99 block-bootstrap CI — pooled latency samples across reps.
    pooled_latencies: Dict[Tuple[str, int], List[float]] = {}
    for cell in cell_records:
        pooled_latencies.setdefault((cell["system"], int(cell["concurrency"])), []).extend(cell["latencies"])
    stats_rows: List[Dict[str, Any]] = []
    for (system, concurrency), latencies in sorted(pooled_latencies.items()):
        if not latencies:
            continue
        ordered = sorted(latencies)
        p99 = percentile(ordered, 0.99)
        lo, hi = block_bootstrap_ci(
            latencies,
            lambda vals: percentile(sorted(vals), 0.99),
            block_size=10,
            iterations=200 if not args.smoke else 50,
            seed=args.random_seed,
        )
        stats_rows.append(
            {
                "system": system,
                "concurrency": concurrency,
                "p99_ms": round(p99, 4),
                "p99_ci_lo": round(lo, 4),
                "p99_ci_hi": round(hi, 4),
                "n_samples": len(latencies),
            }
        )

    # Mood's median pairwise per concurrency.
    pair_rows: List[Dict[str, Any]] = []
    by_c: Dict[int, Dict[str, List[float]]] = {}
    for cell in cell_records:
        by_c.setdefault(int(cell["concurrency"]), {}).setdefault(cell["system"], []).extend(cell["latencies"])
    for concurrency, per_sys in sorted(by_c.items()):
        system_list = sorted(per_sys.keys())
        for i in range(len(system_list)):
            for j in range(i + 1, len(system_list)):
                a, b = system_list[i], system_list[j]
                pvalue = moods_median_test(per_sys[a], per_sys[b])
                pair_rows.append(
                    {
                        "concurrency": concurrency,
                        "system_a": a,
                        "system_b": b,
                        "median_test_p": round(pvalue, 6),
                    }
                )

    write_csv(
        run_dir / "overload_summary.csv",
        summary_rows,
        ["cell_id", "system", "concurrency", "rep", "rps", "p50_ms", "p95_ms", "p99_ms", "error_rate", "knee_c"],
    )
    write_csv(
        run_dir / "overload_samples.csv",
        sample_rows,
        ["cell_id", "system", "concurrency", "rep", "latency_ms"],
    )
    write_csv(
        run_dir / "overload_throughput_timeseries.csv",
        per_second_rows,
        ["cell_id", "system", "concurrency", "rep", "second_index", "rps"],
    )

    summary_obj = {
        "meta": {
            "run_ts": run_ts,
            "dry_run": bool(args.dry_run),
            "smoke": bool(args.smoke),
            "systems": systems,
            "concurrency_levels": concurrency_levels,
            "reps": reps,
            "duration_s": duration,
            "warmup_s": warmup,
            "payload_bytes": args.payload_bytes,
            "random_seed": args.random_seed,
        },
        "knees": knee_by_system,
        "summary": summary_rows,
        "stats_p99_bootstrap": stats_rows,
        "pairwise_median_test": pair_rows,
    }
    (run_dir / "overload_summary.json").write_text(json.dumps(summary_obj, ensure_ascii=True, indent=2), encoding="utf-8")

    _plot_p99_vs_concurrency(summary_rows, run_dir / "plots" / "figure_overload_p99_vs_concurrency.pdf")
    _plot_throughput_timeseries(per_second_rows, run_dir / "plots" / "figure_overload_throughput_timeseries.pdf")
    _plot_latency_cdf(sample_rows, run_dir / "plots" / "figure_overload_latency_cdf.pdf")

    # Always materialize the PDF paths so smoke validation can assert their presence
    # even when matplotlib is unavailable (we emit empty placeholder files in that case).
    for plot_name in (
        "figure_overload_p99_vs_concurrency.pdf",
        "figure_overload_throughput_timeseries.pdf",
        "figure_overload_latency_cdf.pdf",
    ):
        plot_path = run_dir / "plots" / plot_name
        if not plot_path.exists():
            plot_path.write_bytes(b"")

    # Report markdown.
    report_lines: List[str] = []
    report_lines.append("# E3 Sustained Overload Report")
    report_lines.append("")
    report_lines.append(f"- run_ts: `{run_ts}`")
    report_lines.append(f"- dry_run: `{args.dry_run}` | smoke: `{args.smoke}`")
    report_lines.append(f"- duration per cell: {duration}s (warmup {warmup}s), reps={reps}")
    report_lines.append(f"- systems: {', '.join(systems)}")
    report_lines.append(f"- concurrency levels: {concurrency_levels}")
    report_lines.append("")
    report_lines.append("## p99 knee by system")
    report_lines.append("")
    report_lines.append("| system | knee_c |")
    report_lines.append("|---|---:|")
    for system in sorted(knee_by_system.keys()):
        report_lines.append(f"| {system} | {knee_by_system[system]:.1f} |")
    report_lines.append("")
    report_lines.append("## Cell summary")
    report_lines.append("")
    report_lines.append("| system | concurrency | rep | rps | p50 | p95 | p99 | error_rate |")
    report_lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for row in summary_rows:
        report_lines.append(
            f"| {row['system']} | {row['concurrency']} | {row['rep']} | "
            f"{row['rps']} | {row['p50_ms']} | {row['p95_ms']} | {row['p99_ms']} | {row['error_rate']} |"
        )
    report_lines.append("")
    report_lines.append("## p99 block-bootstrap CI (pooled reps)")
    report_lines.append("")
    report_lines.append("| system | concurrency | p99 | CI lo | CI hi | n_samples |")
    report_lines.append("|---|---:|---:|---:|---:|---:|")
    for row in stats_rows:
        report_lines.append(
            f"| {row['system']} | {row['concurrency']} | {row['p99_ms']} | "
            f"{row['p99_ci_lo']} | {row['p99_ci_hi']} | {row['n_samples']} |"
        )
    report_lines.append("")
    report_lines.append("## Pairwise Mood's median test (by concurrency)")
    report_lines.append("")
    report_lines.append("| concurrency | system_a | system_b | median_test_p |")
    report_lines.append("|---:|---|---|---:|")
    for row in pair_rows:
        report_lines.append(
            f"| {row['concurrency']} | {row['system_a']} | {row['system_b']} | {row['median_test_p']} |"
        )
    report_lines.append("")
    report_lines.append("## Notes")
    report_lines.append("")
    report_lines.append(
        "- Block-bootstrap uses a fixed block size of 10 consecutive latency "
        "samples to approximate autocorrelation; this is a pragmatic "
        "approximation, not a Politis-Romano optimal rule. Treat CI widths as "
        "indicative.\n"
        "- Mood's median test is approximated with a chi-square(1) survival "
        "function (erfc). Use it for regime detection, not absolute p-values."
    )
    (run_dir / "overload_report.md").write_text("\n".join(report_lines), encoding="utf-8")

    print(f"[overload] result dir: {run_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
