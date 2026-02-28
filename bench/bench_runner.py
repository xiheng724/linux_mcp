#!/usr/bin/env python3
"""Phase 5 benchmark runner for linux-mcp."""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import re
import socket
import statistics
import struct
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
SOCK_PATH = "/tmp/mcpd.sock"

DECISION_RE = re.compile(
    r"decision=(?P<decision>[A-Z]+)\s+wait_ms=(?P<wait>\d+)\s+tokens_left=(?P<tokens>\d+)\s+reason=(?P<reason>.+)$"
)


def run_cmd(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def parse_decision(stdout: str) -> Tuple[str, int, int, str]:
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    if not lines:
        raise ValueError("empty decision output")
    m = DECISION_RE.search(lines[-1])
    if not m:
        raise ValueError(f"unexpected decision output: {lines[-1]}")
    return (
        m.group("decision"),
        int(m.group("wait")),
        int(m.group("tokens")),
        m.group("reason"),
    )


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(conn: socket.socket) -> bytes:
    header = recv_exact(conn, 4)
    (length,) = struct.unpack(">I", header)
    if length <= 0:
        raise ValueError("invalid frame length")
    return recv_exact(conn, length)


def send_frame(conn: socket.socket, payload: bytes) -> None:
    conn.sendall(struct.pack(">I", len(payload)))
    conn.sendall(payload)


def uds_exec(req: Dict[str, Any]) -> Dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.connect(SOCK_PATH)
        body = json.dumps(req, ensure_ascii=True).encode("utf-8")
        send_frame(conn, body)
        resp_raw = recv_frame(conn)
    resp = json.loads(resp_raw.decode("utf-8"))
    if not isinstance(resp, dict):
        raise ValueError("invalid response type")
    return resp


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    arr = sorted(values)
    if len(arr) == 1:
        return float(arr[0])
    rank = (p / 100.0) * (len(arr) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(arr) - 1)
    frac = rank - lo
    return float(arr[lo] + (arr[hi] - arr[lo]) * frac)


def worker_main(
    idx: int,
    requests: int,
    tool: str,
    burn_ms: int,
    out_q: mp.Queue,
) -> None:
    agent_id = f"a{idx + 1}"
    tool_id = 2 if tool == "cpu_burn" else 1
    req_records: List[Dict[str, Any]] = []
    decision_counts = {"ALLOW": 0, "DENY": 0, "DEFER": 0}
    ok_count = 0
    deny_count = 0
    err_count = 0
    worker_start = time.perf_counter()

    try:
        run_cmd(["./client/bin/genl_register_agent", "--id", agent_id], check=True)
        for req_idx in range(1, requests + 1):
            req_id = (idx + 1) * 1_000_000 + req_idx
            req_start = time.perf_counter()
            defer_before = 0
            control_total_ms = 0.0

            while True:
                t0 = time.perf_counter()
                proc = run_cmd(
                    [
                        "./client/bin/genl_tool_request",
                        "--agent",
                        agent_id,
                        "--tool",
                        str(tool_id),
                        "--n",
                        "1",
                    ],
                    check=True,
                )
                control_total_ms += (time.perf_counter() - t0) * 1000.0
                decision, wait_ms, _tokens_left, reason = parse_decision(proc.stdout)
                decision_counts[decision] = decision_counts.get(decision, 0) + 1

                if decision == "DEFER":
                    defer_before += 1
                    time.sleep(wait_ms / 1000.0)
                    continue

                if decision == "DENY":
                    deny_count += 1
                    req_records.append(
                        {
                            "agent_id": agent_id,
                            "req_id": req_id,
                            "status": "deny",
                            "decision": decision,
                            "reason": reason,
                            "t_control_ms": control_total_ms,
                            "t_data_ms": 0.0,
                            "t_end_to_end_ms": (time.perf_counter() - req_start) * 1000.0,
                            "defers_before_decision": defer_before,
                        }
                    )
                    break

                payload: Dict[str, Any]
                if tool_id == 2:
                    payload = {"ms": burn_ms}
                    tool_name = "cpu_burn"
                    app_id = "settings_app"
                else:
                    payload = {"echo": f"{agent_id}-{req_idx}"}
                    tool_name = "echo"
                    app_id = "utility_app"

                t1 = time.perf_counter()
                resp = uds_exec(
                    {
                        "req_id": req_id,
                        "agent_id": agent_id,
                        "app_id": app_id,
                        "tool_id": tool_id,
                        "tool_name": tool_name,
                        "payload": payload,
                    }
                )
                t_data_ms = (time.perf_counter() - t1) * 1000.0
                e2e_ms = (time.perf_counter() - req_start) * 1000.0
                status = str(resp.get("status", "error"))
                if status == "ok":
                    ok_count += 1
                else:
                    err_count += 1

                req_records.append(
                    {
                        "agent_id": agent_id,
                        "req_id": req_id,
                        "status": status,
                        "decision": "ALLOW",
                        "reason": reason,
                        "t_control_ms": control_total_ms,
                        "t_data_ms": t_data_ms,
                        "t_end_to_end_ms": e2e_ms,
                        "defers_before_decision": defer_before,
                    }
                )
                break
    except Exception as exc:  # noqa: BLE001
        out_q.put({"agent_id": agent_id, "error": str(exc)})
        return

    worker_end = time.perf_counter()
    out_q.put(
        {
            "agent_id": agent_id,
            "error": "",
            "worker_runtime_s": worker_end - worker_start,
            "ok_count": ok_count,
            "deny_count": deny_count,
            "error_count": err_count,
            "decision_counts": decision_counts,
            "requests": req_records,
        }
    )


def read_sysfs_agent(agent_id: str) -> Dict[str, Any]:
    base = Path("/sys/kernel/mcp/agents") / agent_id
    out: Dict[str, Any] = {"allow": 0, "deny": 0, "defer": 0, "last_reason": ""}
    try:
        out["allow"] = int((base / "allow").read_text(encoding="utf-8").strip())
        out["deny"] = int((base / "deny").read_text(encoding="utf-8").strip())
        out["defer"] = int((base / "defer").read_text(encoding="utf-8").strip())
        out["last_reason"] = (base / "last_reason").read_text(encoding="utf-8").strip()
    except Exception:  # noqa: BLE001
        out["last_reason"] = "unavailable"
    return out


def build_agent_summary(worker: Dict[str, Any], sysfs: Dict[str, Any]) -> Dict[str, Any]:
    rows = worker["requests"]
    ok_rows = [r for r in rows if r["status"] == "ok"]
    e2e_vals = [float(r["t_end_to_end_ms"]) for r in ok_rows]
    data_vals = [float(r["t_data_ms"]) for r in ok_rows]

    runtime_s = float(worker["worker_runtime_s"])
    throughput = (len(ok_rows) / runtime_s) if runtime_s > 0 else 0.0

    return {
        "agent_id": worker["agent_id"],
        "worker_runtime_s": runtime_s,
        "ok_count": worker["ok_count"],
        "deny_count": worker["deny_count"],
        "error_count": worker["error_count"],
        "throughput_ops_s": throughput,
        "latency_end_to_end_ms": {
            "p50": percentile(e2e_vals, 50),
            "p95": percentile(e2e_vals, 95),
            "p99": percentile(e2e_vals, 99),
        },
        "latency_data_ms": {
            "p50": percentile(data_vals, 50),
            "p95": percentile(data_vals, 95),
            "p99": percentile(data_vals, 99),
        },
        "sysfs": sysfs,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agents", type=int, default=10)
    parser.add_argument("--requests", type=int, default=50)
    parser.add_argument("--tool", choices=["cpu_burn", "echo"], default="cpu_burn")
    parser.add_argument("--burn-ms", type=int, default=50)
    parser.add_argument("--out", default="results/phase5_run.json")
    args = parser.parse_args()

    if args.agents <= 0 or args.requests <= 0:
        raise SystemExit("agents/requests must be > 0")

    out_q: mp.Queue = mp.Queue()
    procs: List[mp.Process] = []

    print(
        f"[bench] start agents={args.agents} requests={args.requests} tool={args.tool} burn_ms={args.burn_ms}",
        flush=True,
    )

    t0 = time.perf_counter()
    for i in range(args.agents):
        p = mp.Process(
            target=worker_main,
            args=(i, args.requests, args.tool, args.burn_ms, out_q),
            daemon=False,
        )
        p.start()
        procs.append(p)

    worker_results: List[Dict[str, Any]] = []
    for _ in range(args.agents):
        worker_results.append(out_q.get())

    for p in procs:
        p.join()

    wall_s = time.perf_counter() - t0

    errors = [w for w in worker_results if w.get("error")]
    if errors:
        print("[bench] worker errors detected:", flush=True)
        for e in errors:
            print(f"  {e['agent_id']}: {e['error']}", flush=True)
        return 2

    all_requests: List[Dict[str, Any]] = []
    agent_summaries: List[Dict[str, Any]] = []

    for w in sorted(worker_results, key=lambda x: x["agent_id"]):
        all_requests.extend(w["requests"])
        sysfs = read_sysfs_agent(w["agent_id"])
        agent_summaries.append(build_agent_summary(w, sysfs))

    allow_counts = [a["sysfs"]["allow"] for a in agent_summaries]
    mean_allow = statistics.mean(allow_counts) if allow_counts else 0.0
    stdev_allow = statistics.pstdev(allow_counts) if allow_counts else 0.0
    fairness_cv = (stdev_allow / mean_allow) if mean_allow > 0 else 0.0

    result = {
        "meta": {
            "ts_epoch_s": int(time.time()),
            "agents": args.agents,
            "requests_per_agent": args.requests,
            "tool": args.tool,
            "burn_ms": args.burn_ms,
            "wall_clock_s": wall_s,
            "hostname": socket.gethostname(),
            "pid": os.getpid(),
        },
        "fairness": {
            "allow_mean": mean_allow,
            "allow_stdev": stdev_allow,
            "allow_cv": fairness_cv,
        },
        "agents": agent_summaries,
        "requests": all_requests,
    }

    out_path = ROOT / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=True), encoding="utf-8")

    print("[bench] summary", flush=True)
    print("agent   ok   deny   thr(ops/s)   e2e_p95(ms)   sysfs_allow sysfs_defer", flush=True)
    for a in agent_summaries:
        print(
            f"{a['agent_id']:<6} {a['ok_count']:<4} {a['deny_count']:<6} "
            f"{a['throughput_ops_s']:<11.2f} {a['latency_end_to_end_ms']['p95']:<12.2f} "
            f"{a['sysfs']['allow']:<10} {a['sysfs']['defer']}",
            flush=True,
        )
    print(f"[bench] wall_clock_s={wall_s:.3f} fairness_cv={fairness_cv:.4f}", flush=True)
    print(f"[bench] wrote {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
