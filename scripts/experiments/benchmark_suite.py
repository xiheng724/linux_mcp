#!/usr/bin/env python3
"""High-volume experiment suite for linux-mcp.

This runner provides multiple comparative experiments:
- mcpd path vs direct tool endpoint path
- single-thread vs high-concurrency sweeps
- negative/security control requests

Outputs:
- scenario-level CSV files under the result directory
- summary.json with aggregate latency/throughput/success metrics
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import random
import socket
import statistics
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


DEFAULT_MCPD_SOCK = "/tmp/mcpd.sock"
MAX_MSG_SIZE = 16 * 1024 * 1024
MUTATING_TAGS = {"filesystem_write", "system_mutation"}


@dataclass(frozen=True)
class ToolCase:
    app_id: str
    app_name: str
    tool_id: int
    tool_name: str
    operation: str
    endpoint: str
    risk_tags: Tuple[str, ...]
    manifest_hash: str
    payloads: Tuple[Dict[str, Any], ...]


def send_frame(conn: socket.socket, payload: bytes, *, max_msg_size: int = MAX_MSG_SIZE) -> None:
    if len(payload) > max_msg_size:
        raise ValueError("payload too large")
    conn.sendall(struct.pack(">I", len(payload)))
    conn.sendall(payload)


def recv_exact(conn: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = conn.recv(n - len(out))
        if not chunk:
            raise ConnectionError("peer closed")
        out.extend(chunk)
    return bytes(out)


def recv_frame(conn: socket.socket, *, max_msg_size: int = MAX_MSG_SIZE) -> bytes:
    header = recv_exact(conn, 4)
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > max_msg_size:
        raise ValueError(f"invalid frame length: {length}")
    return recv_exact(conn, length)


def rpc_call(sock_path: str, req: Dict[str, Any], timeout_s: float) -> Dict[str, Any]:
    payload = json.dumps(req, ensure_ascii=True).encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout_s)
        conn.connect(sock_path)
        send_frame(conn, payload)
        raw = recv_frame(conn)
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError("response is not JSON object")
    return obj


class PersistentMcpdConn:
    """Long-lived mcpd RPC connection for sustained-load workers.

    The mcpd server multiplexes requests over a single connection
    (see mcpd/server.py:_handle_connection which loops on recv_frame),
    so reusing one socket avoids the SOMAXCONN bottleneck that bites
    fresh-connect-per-request load patterns at concurrency >= 200.
    """

    def __init__(self, sock_path: str, timeout_s: float) -> None:
        self._sock_path = sock_path
        self._timeout_s = timeout_s
        self._conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._conn.settimeout(timeout_s)
        self._conn.connect(sock_path)

    def call(self, req: Dict[str, Any]) -> Dict[str, Any]:
        payload = json.dumps(req, ensure_ascii=True).encode("utf-8")
        send_frame(self._conn, payload)
        raw = recv_frame(self._conn)
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            raise RuntimeError("response is not JSON object")
        return obj

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


def load_manifest_tools(manifest_glob: str = "tool-app/manifests/*.json") -> List[ToolCase]:
    out: List[ToolCase] = []
    for path in sorted(glob.glob(manifest_glob)):
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        app_id = str(raw.get("app_id", ""))
        app_name = str(raw.get("app_name", ""))
        endpoint = str(raw.get("endpoint", ""))
        tools = raw.get("tools", [])
        if not isinstance(tools, list):
            continue
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            tool_id = tool.get("tool_id")
            if isinstance(tool_id, bool) or not isinstance(tool_id, int):
                continue
            name = str(tool.get("name", ""))
            operation = str(tool.get("operation", ""))
            risk_tags_raw = tool.get("risk_tags", [])
            risk_tags: Tuple[str, ...] = tuple(
                x for x in risk_tags_raw if isinstance(x, str) and x
            )
            examples = tool.get("examples", [])
            payloads: List[Dict[str, Any]] = []
            if isinstance(examples, list):
                for ex in examples:
                    if not isinstance(ex, dict):
                        continue
                    payload = ex.get("payload")
                    if isinstance(payload, dict):
                        payloads.append(payload)
            if not payloads:
                payloads = [{}]
            out.append(
                ToolCase(
                    app_id=app_id,
                    app_name=app_name,
                    tool_id=tool_id,
                    tool_name=name,
                    operation=operation,
                    endpoint=endpoint,
                    risk_tags=risk_tags,
                    manifest_hash="",
                    payloads=tuple(payloads),
                )
            )
    return out


def enrich_hash_from_mcpd(tools: List[ToolCase], mcpd_sock: str, timeout_s: float) -> List[ToolCase]:
    resp = rpc_call(mcpd_sock, {"sys": "list_tools"}, timeout_s)
    if resp.get("status") != "ok":
        raise RuntimeError(f"list_tools failed: {resp.get('error', 'unknown error')}")
    raw_tools = resp.get("tools", [])
    if not isinstance(raw_tools, list):
        raise RuntimeError("list_tools response missing tools list")
    by_id: Dict[int, str] = {}
    for item in raw_tools:
        if not isinstance(item, dict):
            continue
        tool_id = item.get("tool_id")
        tool_hash = item.get("hash", "")
        if isinstance(tool_id, int) and isinstance(tool_hash, str):
            by_id[tool_id] = tool_hash

    out: List[ToolCase] = []
    for tool in tools:
        out.append(
            ToolCase(
                app_id=tool.app_id,
                app_name=tool.app_name,
                tool_id=tool.tool_id,
                tool_name=tool.tool_name,
                operation=tool.operation,
                endpoint=tool.endpoint,
                risk_tags=tool.risk_tags,
                manifest_hash=by_id.get(tool.tool_id, ""),
                payloads=tool.payloads,
            )
        )
    return out


def is_mutating(tool: ToolCase) -> bool:
    return any(tag in MUTATING_TAGS for tag in tool.risk_tags)


def open_session(sock_path: str, timeout_s: float, client_name: str) -> Tuple[str, str]:
    req = {"sys": "open_session", "client_name": client_name, "ttl_ms": 10 * 60 * 1000}
    resp = rpc_call(sock_path, req, timeout_s)
    if resp.get("status") != "ok":
        raise RuntimeError(f"open_session failed: {resp.get('error', 'unknown error')}")
    session_id = resp.get("session_id", "")
    agent_id = resp.get("agent_id", "")
    if not isinstance(session_id, str) or not session_id:
        raise RuntimeError(f"invalid open_session response session_id: {resp}")
    if not isinstance(agent_id, str) or not agent_id:
        raise RuntimeError(f"invalid open_session response agent_id: {resp}")
    return session_id, agent_id


def call_tool_direct(tool: ToolCase, payload: Dict[str, Any], timeout_s: float, req_id: int) -> Dict[str, Any]:
    req = {"req_id": req_id, "operation": tool.operation, "payload": payload}
    return rpc_call(tool.endpoint, req, timeout_s)


def call_tool_via_mcpd(
    tool: ToolCase,
    payload: Dict[str, Any],
    timeout_s: float,
    req_id: int,
    mcpd_sock: str,
    session_id: str,
    include_hash: bool,
) -> Dict[str, Any]:
    req: Dict[str, Any] = {
        "kind": "tool:exec",
        "req_id": req_id,
        "session_id": session_id,
        "app_id": tool.app_id,
        "tool_id": tool.tool_id,
        "payload": payload,
    }
    if include_hash and tool.manifest_hash:
        req["tool_hash"] = tool.manifest_hash
    return rpc_call(mcpd_sock, req, timeout_s)


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    k = (len(values) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return values[int(k)]
    return values[f] * (c - k) + values[c] * (k - f)


def summarize_rows(rows: List[Dict[str, Any]], scenario: str) -> Dict[str, Any]:
    if not rows:
        return {
            "scenario": scenario,
            "requests": 0,
            "ok": 0,
            "error": 0,
            "success_rate": 0.0,
            "throughput_rps": 0.0,
            "latency_ms": {"avg": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0},
        }

    latencies = sorted(float(row["latency_ms"]) for row in rows)
    ok_count = sum(1 for row in rows if row.get("status") == "ok")
    total = len(rows)
    elapsed_s = max(float(row["end_ts"]) for row in rows) - min(float(row["start_ts"]) for row in rows)
    throughput = total / elapsed_s if elapsed_s > 0 else 0.0

    return {
        "scenario": scenario,
        "requests": total,
        "ok": ok_count,
        "error": total - ok_count,
        "success_rate": round(ok_count / total, 6),
        "throughput_rps": round(throughput, 3),
        "latency_ms": {
            "avg": round(statistics.fmean(latencies), 3),
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
        },
    }


def preflight_tools(
    tools: List[ToolCase],
    *,
    mcpd_sock: str,
    timeout_s: float,
    include_write: bool,
    max_tools: int,
) -> List[ToolCase]:
    filtered = [tool for tool in tools if include_write or not is_mutating(tool)]
    session_id, _agent_id = open_session(mcpd_sock, timeout_s, "bench-preflight")
    valid: List[ToolCase] = []

    for tool in filtered:
        payload = dict(tool.payloads[0])
        direct_ok = False
        mcpd_ok = False

        try:
            direct_resp = call_tool_direct(tool, payload, timeout_s, req_id=1)
            direct_ok = direct_resp.get("status") == "ok"
        except Exception:
            direct_ok = False

        try:
            mcpd_resp = call_tool_via_mcpd(
                tool,
                payload,
                timeout_s,
                req_id=1,
                mcpd_sock=mcpd_sock,
                session_id=session_id,
                include_hash=True,
            )
            mcpd_ok = mcpd_resp.get("status") == "ok"
        except Exception:
            mcpd_ok = False

        if direct_ok and mcpd_ok:
            valid.append(tool)
        if len(valid) >= max_tools:
            break

    return valid


def run_worker(
    *,
    mode: str,
    worker_id: int,
    request_count: int,
    tools: List[ToolCase],
    mcpd_sock: str,
    timeout_s: float,
    rng_seed: int,
    include_hash: bool,
) -> List[Dict[str, Any]]:
    rnd = random.Random(rng_seed)
    out: List[Dict[str, Any]] = []
    session_id = ""

    if mode == "mcpd":
        session_id, _agent_id = open_session(mcpd_sock, timeout_s, f"bench-worker-{worker_id}")

    for idx in range(request_count):
        tool = rnd.choice(tools)
        payload = dict(rnd.choice(tool.payloads))
        req_id = int(time.time_ns() & 0x7FFFFFFF)
        start = time.perf_counter()
        start_ts = time.time()
        status = "error"
        decision = ""
        error = ""

        try:
            if mode == "mcpd":
                resp = call_tool_via_mcpd(
                    tool,
                    payload,
                    timeout_s,
                    req_id=req_id,
                    mcpd_sock=mcpd_sock,
                    session_id=session_id,
                    include_hash=include_hash,
                )
            elif mode == "direct":
                resp = call_tool_direct(tool, payload, timeout_s, req_id=req_id)
            else:
                raise ValueError(f"unsupported mode: {mode}")

            status = str(resp.get("status", "error"))
            decision = str(resp.get("decision", ""))
            error = str(resp.get("error", ""))
        except Exception as exc:
            error = str(exc)

        latency_ms = (time.perf_counter() - start) * 1000.0
        out.append(
            {
                "worker": worker_id,
                "request_index": idx,
                "mode": mode,
                "tool_id": tool.tool_id,
                "tool_name": tool.tool_name,
                "status": status,
                "decision": decision,
                "error": error,
                "latency_ms": round(latency_ms, 3),
                "start_ts": round(start_ts, 6),
                "end_ts": round(time.time(), 6),
            }
        )

    return out


def run_scenario(
    *,
    scenario_name: str,
    mode: str,
    tools: List[ToolCase],
    concurrency: int,
    total_requests: int,
    mcpd_sock: str,
    timeout_s: float,
    include_hash: bool,
    seed: int,
) -> List[Dict[str, Any]]:
    if concurrency <= 0:
        raise ValueError("concurrency must be positive")
    if total_requests <= 0:
        return []

    base = total_requests // concurrency
    rem = total_requests % concurrency

    futures = []
    out: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for worker_id in range(concurrency):
            count = base + (1 if worker_id < rem else 0)
            if count <= 0:
                continue
            futures.append(
                pool.submit(
                    run_worker,
                    mode=mode,
                    worker_id=worker_id,
                    request_count=count,
                    tools=tools,
                    mcpd_sock=mcpd_sock,
                    timeout_s=timeout_s,
                    rng_seed=seed + worker_id,
                    include_hash=include_hash,
                )
            )
        for fut in as_completed(futures):
            out.extend(fut.result())

    for row in out:
        row["scenario"] = scenario_name
        row["concurrency"] = concurrency

    return out


@dataclass
class SustainedResult:
    system: str
    concurrency: int
    duration_s: float
    warmup_s: float
    payload_bytes: int
    requests: int
    errors: int
    latency_samples_ms: List[float]
    per_second_throughput: List[int]
    start_ts: float
    end_ts: float


def run_sustained_load(
    *,
    system: str,
    concurrency: int,
    duration_s: float,
    warmup_s: float,
    payload_bytes: int,
    request_fn: Any,
    make_worker_state: Any = None,
    close_worker_state: Any = None,
    reservoir_cap: int = 5000,
    rng_seed: int = 0,
) -> SustainedResult:
    """Drive wall-clock-bounded load.

    Protocol:

    - `make_worker_state(worker_id) -> state` is called once per worker before
      the measurement window opens. It can (for example) open a persistent UDS
      connection, open a session, or return None if no state is needed.
    - `request_fn(state, req_index) -> (status_ok: bool, latency_ms: float)` is
      called repeatedly in the hot loop. The same `state` is passed every call,
      enabling connection pooling per worker. `req_index = -1` is the warmup
      tick (latency is not recorded).
    - `close_worker_state(state)` is called once per worker after the loop
      exits (best-effort; exceptions are swallowed).

    Only samples where `status_ok is True` are entered into the latency
    reservoir — errors are counted in the `errors` counter but do NOT pollute
    the latency distribution. This is critical: under connection saturation,
    errors return in tens of microseconds and would otherwise push p50/p95
    toward that floor and mask the real tail.

    Back-compat shim: if `request_fn` accepts only `(worker_id, req_index)`
    (the legacy overload_eval.py dry-run stub), the helper detects it via
    signature inspection and wraps it automatically.
    """
    if concurrency <= 0:
        raise ValueError("concurrency must be positive")

    # Legacy signature detection: _synthetic_request_fn in the dry-run path
    # returns a closure with (worker_id, req_index). We wrap it so it fits
    # the (state, req_index) protocol used below.
    import inspect
    try:
        sig_params = list(inspect.signature(request_fn).parameters.values())
        legacy = len(sig_params) >= 2 and sig_params[0].name in ("worker_id", "wid")
    except (TypeError, ValueError):
        legacy = False
    if legacy:
        _legacy_fn = request_fn
        def request_fn(state, req_index):  # type: ignore[no-redef]
            worker_id = state if isinstance(state, int) else 0
            return _legacy_fn(worker_id, req_index)
        if make_worker_state is None:
            def make_worker_state(wid):  # type: ignore[no-redef]
                return wid

    reservoir: List[float] = []
    reservoir_seen = 0
    reservoir_lock = __import__("threading").Lock()

    per_second_bucket_count = max(int(math.ceil(duration_s)), 1)
    per_second: List[int] = [0] * per_second_bucket_count
    errors_total = 0
    requests_total = 0
    errors_lock = __import__("threading").Lock()

    barrier = __import__("threading").Barrier(concurrency)
    start_ref = time.perf_counter() + 0.05  # small slack so all workers see the same t0

    def _worker(worker_id: int) -> None:
        nonlocal errors_total, requests_total, reservoir_seen
        local_rnd = random.Random(rng_seed + worker_id + 1)
        state = None
        if make_worker_state is not None:
            try:
                state = make_worker_state(worker_id)
            except Exception:
                state = None
        try:
            barrier.wait()
            measure_start = start_ref + warmup_s
            measure_end = measure_start + duration_s
            # Spin until measurement window opens. Warmup ticks use req_index=-1
            # and their latency is never recorded.
            while time.perf_counter() < measure_start:
                try:
                    request_fn(state, -1)
                except Exception:
                    pass
            req_index = 0
            while True:
                now = time.perf_counter()
                if now >= measure_end:
                    break
                try:
                    status_ok, latency_ms = request_fn(state, req_index)
                except Exception:
                    status_ok = False
                    latency_ms = (time.perf_counter() - now) * 1000.0
                bucket_idx = int(now - measure_start)
                with errors_lock:
                    requests_total += 1
                    if not status_ok:
                        errors_total += 1
                    elif 0 <= bucket_idx < per_second_bucket_count:
                        # Count only successful requests in the per-second
                        # throughput so rps reflects real work, not error churn.
                        per_second[bucket_idx] += 1
                # Only record latency for successful requests. Error latencies
                # from connection refusals / timeouts would otherwise compress
                # the reservoir toward the fail-fast floor and mask the tail.
                if status_ok:
                    with reservoir_lock:
                        reservoir_seen += 1
                        if len(reservoir) < reservoir_cap:
                            reservoir.append(latency_ms)
                        else:
                            j = local_rnd.randint(0, reservoir_seen - 1)
                            if j < reservoir_cap:
                                reservoir[j] = latency_ms
                req_index += 1
        finally:
            if close_worker_state is not None and state is not None:
                try:
                    close_worker_state(state)
                except Exception:
                    pass

    threads = [
        __import__("threading").Thread(target=_worker, args=(wid,), daemon=True)
        for wid in range(concurrency)
    ]
    t_wall_start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    t_wall_end = time.time()

    return SustainedResult(
        system=system,
        concurrency=concurrency,
        duration_s=duration_s,
        warmup_s=warmup_s,
        payload_bytes=payload_bytes,
        requests=requests_total,
        errors=errors_total,
        latency_samples_ms=reservoir,
        per_second_throughput=per_second,
        start_ts=t_wall_start,
        end_ts=t_wall_end,
    )


def run_negative_controls(
    *,
    tool: ToolCase,
    mcpd_sock: str,
    timeout_s: float,
    repeats: int,
) -> Dict[str, Any]:
    session_id, _agent_id = open_session(mcpd_sock, timeout_s, "bench-negative")
    payload = dict(tool.payloads[0])
    cases = {
        "invalid_session": {
            "kind": "tool:exec",
            "req_id": 1,
            "session_id": "invalid-session-id",
            "app_id": tool.app_id,
            "tool_id": tool.tool_id,
            "payload": payload,
        },
        "invalid_tool_id": {
            "kind": "tool:exec",
            "req_id": 1,
            "session_id": session_id,
            "app_id": tool.app_id,
            "tool_id": 999999,
            "payload": payload,
        },
        "hash_mismatch": {
            "kind": "tool:exec",
            "req_id": 1,
            "session_id": session_id,
            "app_id": tool.app_id,
            "tool_id": tool.tool_id,
            "tool_hash": "deadbeef",
            "payload": payload,
        },
    }

    summary: Dict[str, Any] = {}
    for case_name, req in cases.items():
        error_count = 0
        deny_count = 0
        defer_count = 0
        durations: List[float] = []
        for i in range(repeats):
            req["req_id"] = i + 1
            t0 = time.perf_counter()
            try:
                resp = rpc_call(mcpd_sock, req, timeout_s)
            except Exception:
                resp = {"status": "error", "error": "rpc exception"}
            durations.append((time.perf_counter() - t0) * 1000.0)

            if resp.get("status") == "error":
                error_count += 1
            decision = str(resp.get("decision", ""))
            if decision == "DENY":
                deny_count += 1
            if decision == "DEFER":
                defer_count += 1

        summary[case_name] = {
            "repeats": repeats,
            "error_rate": round(error_count / repeats, 6),
            "deny_rate": round(deny_count / repeats, 6),
            "defer_rate": round(defer_count / repeats, 6),
            "latency_ms_avg": round(statistics.fmean(durations), 3),
            "latency_ms_p95": round(percentile(sorted(durations), 0.95), 3),
        }

    return summary


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    fields = [
        "scenario",
        "mode",
        "concurrency",
        "worker",
        "request_index",
        "tool_id",
        "tool_name",
        "status",
        "decision",
        "error",
        "latency_ms",
        "start_ts",
        "end_ts",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})


def parse_concurrency(raw: str) -> List[int]:
    out: List[int] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        value = int(token)
        if value <= 0:
            raise ValueError("concurrency must be positive")
        out.append(value)
    if not out:
        raise ValueError("empty concurrency list")
    return out


def ensure_prerequisites(sock_path: str, timeout_s: float) -> None:
    resp = rpc_call(sock_path, {"sys": "list_apps"}, timeout_s)
    if resp.get("status") != "ok":
        raise RuntimeError(f"mcpd not ready: {resp.get('error', 'unknown error')}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run large-scale comparative experiments for linux-mcp")
    parser.add_argument("--mcpd-sock", default=DEFAULT_MCPD_SOCK)
    parser.add_argument("--timeout-s", type=float, default=10.0)
    parser.add_argument("--output-dir", type=str, default="experiment-results")
    parser.add_argument("--requests", type=int, default=4000, help="requests per scenario")
    parser.add_argument("--concurrency", type=str, default="1,4,8,16,32")
    parser.add_argument("--negative-repeats", type=int, default=500)
    parser.add_argument("--max-tools", type=int, default=20)
    parser.add_argument("--include-write-tools", action="store_true")
    parser.add_argument("--seed", type=int, default=20260403)
    parser.add_argument("--skip-direct", action="store_true")
    args = parser.parse_args()

    out_root = Path(args.output_dir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    run_ts = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    run_dir = out_root / f"run-{run_ts}"
    run_dir.mkdir(parents=True, exist_ok=True)

    ensure_prerequisites(args.mcpd_sock, args.timeout_s)

    tools = load_manifest_tools()
    tools = enrich_hash_from_mcpd(tools, args.mcpd_sock, args.timeout_s)
    selected = preflight_tools(
        tools,
        mcpd_sock=args.mcpd_sock,
        timeout_s=args.timeout_s,
        include_write=args.include_write_tools,
        max_tools=args.max_tools,
    )

    if not selected:
        raise RuntimeError(
            "no tools passed preflight on both direct and mcpd path; check tool services and mcpd logs"
        )

    conc_list = parse_concurrency(args.concurrency)

    all_summaries: List[Dict[str, Any]] = []
    meta = {
        "run_ts": run_ts,
        "requests_per_scenario": args.requests,
        "concurrency": conc_list,
        "negative_repeats": args.negative_repeats,
        "selected_tools": [
            {
                "tool_id": t.tool_id,
                "tool_name": t.tool_name,
                "app_id": t.app_id,
                "risk_tags": list(t.risk_tags),
            }
            for t in selected
        ],
    }

    scenarios: List[Tuple[str, str, int]] = []
    if not args.skip_direct:
        for c in conc_list:
            scenarios.append((f"direct_c{c}", "direct", c))
    for c in conc_list:
        scenarios.append((f"mcpd_c{c}", "mcpd", c))

    for scenario_name, mode, concurrency in scenarios:
        rows = run_scenario(
            scenario_name=scenario_name,
            mode=mode,
            tools=selected,
            concurrency=concurrency,
            total_requests=args.requests,
            mcpd_sock=args.mcpd_sock,
            timeout_s=args.timeout_s,
            include_hash=True,
            seed=args.seed,
        )
        write_csv(run_dir / f"{scenario_name}.csv", rows)
        summary = summarize_rows(rows, scenario_name)
        summary["mode"] = mode
        summary["concurrency"] = concurrency
        all_summaries.append(summary)
        print(
            f"[scenario] {scenario_name} requests={summary['requests']} success_rate={summary['success_rate']:.3f} "
            f"p95={summary['latency_ms']['p95']:.2f}ms throughput={summary['throughput_rps']:.1f}rps",
            flush=True,
        )

    negative = run_negative_controls(
        tool=selected[0],
        mcpd_sock=args.mcpd_sock,
        timeout_s=args.timeout_s,
        repeats=args.negative_repeats,
    )

    result = {
        "meta": meta,
        "summaries": all_summaries,
        "negative_controls": negative,
    }
    (run_dir / "summary.json").write_text(
        json.dumps(result, ensure_ascii=True, indent=2), encoding="utf-8"
    )

    print(f"[done] result_dir={run_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
