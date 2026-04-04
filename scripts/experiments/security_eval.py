#!/usr/bin/env python3
"""Security-oriented evaluation runner for linux-mcp."""

from __future__ import annotations

import argparse
import contextlib
import csv
import json
import os
import statistics
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterator, List, Sequence, Tuple

from benchmark_suite import (
    DEFAULT_MCPD_SOCK,
    ToolCase,
    call_tool_direct,
    enrich_hash_from_mcpd,
    ensure_prerequisites,
    load_manifest_tools,
    open_session,
    parse_concurrency,
    percentile,
    preflight_tools,
    rpc_call,
)

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
HIGH_RISK_TAGS = {
    "filesystem_delete",
    "device_control",
    "external_network",
    "privileged",
    "irreversible",
}
SYSFS_ROOT = Path("/sys/kernel/mcp")


def summarize_durations_ms(values: Sequence[float]) -> Dict[str, float]:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return {"avg": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}
    return {
        "avg": round(statistics.fmean(ordered), 3),
        "p50": round(percentile(ordered, 0.50), 3),
        "p95": round(percentile(ordered, 0.95), 3),
        "p99": round(percentile(ordered, 0.99), 3),
    }


def write_csv(path: Path, rows: Sequence[Dict[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def parse_percent_list(raw: str) -> List[int]:
    out: List[int] = []
    for part in raw.split(","):
        text = part.strip()
        if not text:
            continue
        value = int(text)
        if value < 0 or value > 100:
            raise ValueError("malicious percentages must be between 0 and 100")
        out.append(value)
    if not out:
        raise ValueError("at least one malicious percentage is required")
    return out


def choose_safe_tool(tools: Sequence[ToolCase]) -> ToolCase | None:
    for tool in tools:
        if not any(tag in HIGH_RISK_TAGS for tag in tool.risk_tags):
            return tool
    return None


def choose_risky_tool(tools: Sequence[ToolCase]) -> ToolCase | None:
    for tool in tools:
        if any(tag in HIGH_RISK_TAGS for tag in tool.risk_tags):
            return tool
    return None


def open_session_details(sock_path: str, timeout_s: float, client_name: str, ttl_ms: int = 10 * 60 * 1000) -> Dict[str, Any]:
    last_error = "unknown error"
    for _ in range(3):
        resp = rpc_call(
            sock_path,
            {"sys": "open_session", "client_name": client_name, "ttl_ms": ttl_ms},
            timeout_s,
        )
        if resp.get("status") == "ok":
            return {
                "session_id": str(resp.get("session_id", "")),
                "agent_id": str(resp.get("agent_id", "")),
                "binding_hash": int(resp.get("binding_hash", 0)),
                "binding_epoch": int(resp.get("binding_epoch", 0)),
                "ttl_ms": int(resp.get("ttl_ms", ttl_ms)),
            }
        last_error = str(resp.get("error", "unknown error"))
        time.sleep(0.05)
    raise RuntimeError(f"open_session failed: {last_error}")


def invoke_mcpd_subprocess(
    *,
    sock_path: str,
    timeout_s: float,
    req: Dict[str, Any],
) -> tuple[Dict[str, Any], float]:
    helper = (
        "import json, socket, struct, sys, time\n"
        "sock_path = sys.argv[1]\n"
        "timeout_s = float(sys.argv[2])\n"
        "req = json.loads(sys.argv[3])\n"
        "t0 = time.perf_counter()\n"
        "with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:\n"
        "    conn.settimeout(timeout_s)\n"
        "    conn.connect(sock_path)\n"
        "    raw = json.dumps(req, ensure_ascii=True).encode('utf-8')\n"
        "    conn.sendall(struct.pack('>I', len(raw)))\n"
        "    conn.sendall(raw)\n"
        "    hdr = conn.recv(4)\n"
        "    if len(hdr) != 4:\n"
        "        raise RuntimeError('short header')\n"
        "    (length,) = struct.unpack('>I', hdr)\n"
        "    data = b''\n"
        "    while len(data) < length:\n"
        "        chunk = conn.recv(length - len(data))\n"
        "        if not chunk:\n"
        "            raise RuntimeError('short body')\n"
        "        data += chunk\n"
        "resp = json.loads(data.decode('utf-8'))\n"
        "print(json.dumps({'latency_ms': (time.perf_counter() - t0) * 1000.0, 'resp': resp}, ensure_ascii=True))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", helper, sock_path, str(timeout_s), json.dumps(req, ensure_ascii=True)],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return ({"status": "error", "error": proc.stderr.strip() or proc.stdout.strip() or "subprocess rpc failed"}, 0.0)
    obj = json.loads(proc.stdout.strip())
    return (obj.get("resp", {}), float(obj.get("latency_ms", 0.0)))


def read_kernel_agent_dirs() -> List[str]:
    agent_dir = SYSFS_ROOT / "agents"
    if not agent_dir.is_dir():
        return []
    return sorted(path.name for path in agent_dir.iterdir() if path.is_dir())


def sysfs_snapshot_for_agent(agent_id: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    base = SYSFS_ROOT / "agents" / agent_id
    if not base.is_dir():
        return out
    for child in sorted(base.iterdir()):
        if child.is_file():
            try:
                out[child.name] = child.read_text(encoding="utf-8").strip()
            except Exception:
                out[child.name] = ""
    return out


def find_working_approval_tool(
    *,
    sock_path: str,
    timeout_s: float,
    tools: Sequence[ToolCase],
) -> ToolCase | None:
    for tool in tools:
        if not any(tag in HIGH_RISK_TAGS for tag in tool.risk_tags):
            continue
        try:
            direct_resp = call_tool_direct(tool, dict(tool.payloads[0]), timeout_s, 90000 + tool.tool_id)
            if direct_resp.get("status") != "ok":
                continue
            details = open_session_details(sock_path, timeout_s, f"security-risky-{tool.tool_id}")
            req_id = 90000 + tool.tool_id
            ticket_id = get_ticket_for_risky_tool(
                sock_path=sock_path,
                timeout_s=timeout_s,
                session_id=details["session_id"],
                tool=tool,
                req_id=req_id,
            )
            if ticket_id <= 0:
                continue
            approval_resp = approval_decide(
                sock_path=sock_path,
                timeout_s=timeout_s,
                ticket_id=ticket_id,
                decision="approve",
                operator=str(details["agent_id"]),
                agent_id=str(details["agent_id"]),
                ttl_ms=1000,
                binding_hash=int(details["binding_hash"]),
                binding_epoch=int(details["binding_epoch"]),
            )
            if approval_resp.get("status") != "ok":
                continue
            resp, _ = invoke_mcpd(
                sock_path=sock_path,
                timeout_s=timeout_s,
                req=build_exec_req(
                    req_id=req_id,
                    session_id=str(details["session_id"]),
                    tool=tool,
                    tool_hash=tool.manifest_hash,
                    approval_ticket_id=ticket_id,
                ),
            )
            if resp.get("status") == "ok":
                return tool
        except Exception:
            continue
    return None


def alternate_app_id(tools: Sequence[ToolCase], tool: ToolCase) -> str:
    for item in tools:
        if item.app_id != tool.app_id:
            return item.app_id
    return f"{tool.app_id}-wrong"


def alternate_hash(tools: Sequence[ToolCase], tool: ToolCase) -> str:
    for item in tools:
        if item.tool_id != tool.tool_id and item.manifest_hash:
            return item.manifest_hash
    return "deadbeef"


def launch_mcpd_variant(*, mode: str, sock_path: str, attack_profile: str = "") -> subprocess.Popen[str]:
    env = os.environ.copy()
    env["MCPD_EXPERIMENT_MODE"] = mode
    env["MCPD_SOCK_PATH"] = sock_path
    env["MCPD_TRACE_TIMING"] = "1"
    if attack_profile:
        env["MCPD_ATTACK_PROFILE"] = attack_profile
    else:
        env.pop("MCPD_ATTACK_PROFILE", None)
    return subprocess.Popen(  # noqa: S603
        [sys.executable, "-u", "mcpd/server.py"],
        cwd=ROOT_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def wait_mcpd_ready(sock_path: str, timeout_s: float) -> None:
    deadline = time.time() + timeout_s
    last_error = ""
    while time.time() < deadline:
        time.sleep(0.1)
        try:
            resp = rpc_call(sock_path, {"sys": "list_apps"}, 1.0)
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            continue
        if resp.get("status") == "ok":
            return
        last_error = str(resp.get("error", "mcpd not ready"))
    raise RuntimeError(f"mcpd variant startup timed out: {last_error}")


def stop_process(proc: subprocess.Popen[str], sock_path: str) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5.0)
    Path(sock_path).unlink(missing_ok=True)


@contextlib.contextmanager
def managed_mcpd_variant(
    *,
    mode: str,
    sock_path: str,
    timeout_s: float,
    attack_profile: str = "",
) -> Iterator[None]:
    proc = launch_mcpd_variant(mode=mode, sock_path=sock_path, attack_profile=attack_profile)
    try:
        wait_mcpd_ready(sock_path, timeout_s)
        yield
    finally:
        stop_process(proc, sock_path)


def invoke_mcpd(
    *,
    sock_path: str,
    timeout_s: float,
    req: Dict[str, Any],
) -> tuple[Dict[str, Any], float]:
    t0 = time.perf_counter()
    try:
        resp = rpc_call(sock_path, req, timeout_s)
    except Exception as exc:  # noqa: BLE001
        resp = {"status": "error", "error": str(exc)}
    latency_ms = (time.perf_counter() - t0) * 1000.0
    return resp, latency_ms


def build_exec_req(
    *,
    req_id: int,
    session_id: str,
    tool: ToolCase,
    payload: Dict[str, Any] | None = None,
    app_id: str | None = None,
    tool_hash: str | None = None,
    approval_ticket_id: int | None = None,
) -> Dict[str, Any]:
    req: Dict[str, Any] = {
        "kind": "tool:exec",
        "req_id": req_id,
        "session_id": session_id,
        "app_id": app_id or tool.app_id,
        "tool_id": tool.tool_id,
        "payload": dict(payload if payload is not None else tool.payloads[0]),
    }
    if tool_hash is not None:
        req["tool_hash"] = tool_hash
    if approval_ticket_id is not None:
        req["approval_ticket_id"] = approval_ticket_id
    return req


def approval_decide(
    *,
    sock_path: str,
    timeout_s: float,
    ticket_id: int,
    decision: str,
    operator: str,
    agent_id: str,
    ttl_ms: int,
    binding_hash: int = 0,
    binding_epoch: int = 0,
) -> Dict[str, Any]:
    req = {
        "sys": "approval_decide",
        "ticket_id": ticket_id,
        "decision": decision,
        "operator": operator,
        "agent_id": agent_id,
        "reason": f"security-eval-{decision}",
        "ttl_ms": ttl_ms,
    }
    if binding_hash > 0:
        req["binding_hash"] = binding_hash
    if binding_epoch > 0:
        req["binding_epoch"] = binding_epoch
    return rpc_call(sock_path, req, timeout_s)


def open_short_ttl_session(*, sock_path: str, timeout_s: float, client_name: str, ttl_ms: int) -> tuple[str, str]:
    details = open_session_details(sock_path, timeout_s, client_name, ttl_ms)
    return str(details["session_id"]), str(details["agent_id"])


def get_ticket_for_risky_tool(
    *,
    sock_path: str,
    timeout_s: float,
    session_id: str,
    tool: ToolCase,
    req_id: int,
) -> int:
    resp, _ = invoke_mcpd(
        sock_path=sock_path,
        timeout_s=timeout_s,
        req=build_exec_req(req_id=req_id, session_id=session_id, tool=tool, tool_hash=tool.manifest_hash),
    )
    return int(resp.get("ticket_id", 0))


def make_attack_row(
    *,
    scenario_group: str,
    attack_case: str,
    mode: str,
    attack_profile: str,
    resp: Dict[str, Any],
    latency_ms: float,
    expected_reject: bool = True,
) -> Dict[str, Any]:
    unauthorized_success = resp.get("status") == "ok"
    decision = str(resp.get("decision", ""))
    return {
        "scenario_group": scenario_group,
        "attack_case": attack_case,
        "mode": mode,
        "attack_profile": attack_profile,
        "status": resp.get("status", ""),
        "decision": decision,
        "error": str(resp.get("error", "")),
        "latency_ms": round(latency_ms, 3),
        "unauthorized_success": 1 if unauthorized_success else 0,
        "expected_reject": 1 if expected_reject else 0,
        "invariant_violated": 1 if expected_reject and unauthorized_success else 0,
    }


def summarize_attack_rows(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[tuple[str, str, str], List[Dict[str, Any]]] = {}
    for row in rows:
        key = (
            str(row.get("scenario_group", "")),
            str(row.get("attack_case", "")),
            str(row.get("mode", "")),
        )
        groups.setdefault(key, []).append(row)
    out: List[Dict[str, Any]] = []
    for key, items in sorted(groups.items()):
        lats = [float(item.get("latency_ms", 0.0)) for item in items]
        unauthorized = sum(int(item.get("unauthorized_success", 0)) for item in items)
        violated = sum(int(item.get("invariant_violated", 0)) for item in items)
        out.append(
            {
                "scenario_group": key[0],
                "attack_case": key[1],
                "mode": key[2],
                "attempts": len(items),
                "policy_violation_rate": round(unauthorized / max(len(items), 1), 6),
                "bypass_success_rate": round(unauthorized / max(len(items), 1), 6),
                "forgery_acceptance_rate": round(unauthorized / max(len(items), 1), 6),
                "detection_rate": round((len(items) - unauthorized) / max(len(items), 1), 6),
                "reject_rate": round((len(items) - unauthorized) / max(len(items), 1), 6),
                "invariant_violation_count": violated,
                "reject_latency_avg_ms": round(statistics.fmean(lats), 3) if lats else 0.0,
                "reject_latency_p95_ms": round(percentile(sorted(lats), 0.95), 3) if lats else 0.0,
            }
        )
    return out


def scenario_session_forgery(
    *,
    sock_path: str,
    timeout_s: float,
    mode: str,
    attack_profile: str,
    safe_tool: ToolCase,
    repeats: int,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for i in range(repeats):
        fake_req = build_exec_req(
            req_id=10000 + i,
            session_id=f"forged-session-{i}",
            tool=safe_tool,
            tool_hash=safe_tool.manifest_hash,
        )
        fake_resp, fake_lat = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=fake_req)
        rows.append(
            make_attack_row(
                scenario_group="A",
                attack_case="fake_session_id",
                mode=mode,
                attack_profile=attack_profile,
                resp=fake_resp,
                latency_ms=fake_lat,
            )
        )
        expired_session, _agent_id = open_short_ttl_session(
            sock_path=sock_path,
            timeout_s=timeout_s,
            client_name=f"security-expired-{i}",
            ttl_ms=1,
        )
        time.sleep(0.01)
        expired_req = build_exec_req(
            req_id=11000 + i,
            session_id=expired_session,
            tool=safe_tool,
            tool_hash=safe_tool.manifest_hash,
        )
        expired_resp, expired_lat = invoke_mcpd(
            sock_path=sock_path,
            timeout_s=timeout_s,
            req=expired_req,
        )
        rows.append(
            make_attack_row(
                scenario_group="A",
                attack_case="expired_session",
                mode=mode,
                attack_profile=attack_profile,
                resp=expired_resp,
                latency_ms=expired_lat,
            )
        )
        stolen = open_session_details(sock_path, timeout_s, f"security-stolen-{i}")
        stolen_req = build_exec_req(
            req_id=12000 + i,
            session_id=str(stolen["session_id"]),
            tool=safe_tool,
            tool_hash=safe_tool.manifest_hash,
        )
        stolen_resp, stolen_lat = invoke_mcpd_subprocess(
            sock_path=sock_path,
            timeout_s=timeout_s,
            req=stolen_req,
        )
        rows.append(
            make_attack_row(
                scenario_group="A",
                attack_case="session_token_theft",
                mode=mode,
                attack_profile=attack_profile,
                resp=stolen_resp,
                latency_ms=stolen_lat,
            )
        )
    return rows


def scenario_approval_forgery(
    *,
    sock_path: str,
    timeout_s: float,
    mode: str,
    attack_profile: str,
    risky_tool: ToolCase | None,
    all_tools: Sequence[ToolCase],
    repeats: int,
) -> List[Dict[str, Any]]:
    if risky_tool is None:
        return []
    rows: List[Dict[str, Any]] = []
    alternate_tool = next(
        (
            tool
            for tool in all_tools
            if tool.tool_id != risky_tool.tool_id and any(tag in HIGH_RISK_TAGS for tag in tool.risk_tags)
        ),
        None,
    )
    for i in range(repeats):
        details = open_session_details(sock_path, timeout_s, f"security-approval-{i}")
        session_id = str(details["session_id"])
        agent_id = str(details["agent_id"])
        forged_req = build_exec_req(
            req_id=20000 + i,
            session_id=session_id,
            tool=risky_tool,
            tool_hash=risky_tool.manifest_hash,
            approval_ticket_id=999000 + i,
        )
        forged_resp, forged_lat = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=forged_req)
        rows.append(
            make_attack_row(
                scenario_group="B",
                attack_case="forged_approval_ticket",
                mode=mode,
                attack_profile=attack_profile,
                resp=forged_resp,
                latency_ms=forged_lat,
            )
        )

        ticket_id = get_ticket_for_risky_tool(
            sock_path=sock_path,
            timeout_s=timeout_s,
            session_id=session_id,
            tool=risky_tool,
            req_id=21000 + i,
        )
        cross_details = open_session_details(sock_path, timeout_s, f"security-approval-cross-{i}")
        session2 = str(cross_details["session_id"])
        cross_req = build_exec_req(
            req_id=22000 + i,
            session_id=session2,
            tool=risky_tool,
            tool_hash=risky_tool.manifest_hash,
            approval_ticket_id=ticket_id,
        )
        cross_resp, cross_lat = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=cross_req)
        rows.append(
            make_attack_row(
                scenario_group="B",
                attack_case="cross_agent_ticket_reuse",
                mode=mode,
                attack_profile=attack_profile,
                resp=cross_resp,
                latency_ms=cross_lat,
            )
        )
        if alternate_tool is not None:
            cross_tool_req = build_exec_req(
                req_id=22500 + i,
                session_id=session_id,
                tool=alternate_tool,
                app_id=alternate_tool.app_id,
                tool_hash=alternate_tool.manifest_hash,
                approval_ticket_id=ticket_id,
            )
            cross_tool_resp, cross_tool_lat = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=cross_tool_req)
            rows.append(
                make_attack_row(
                    scenario_group="B",
                    attack_case="cross_tool_ticket_reuse",
                    mode=mode,
                    attack_profile=attack_profile,
                    resp=cross_tool_resp,
                    latency_ms=cross_tool_lat,
                )
            )

        ticket_id = get_ticket_for_risky_tool(
            sock_path=sock_path,
            timeout_s=timeout_s,
            session_id=session_id,
            tool=risky_tool,
            req_id=23000 + i,
        )
        approval_decide(
            sock_path=sock_path,
            timeout_s=timeout_s,
            ticket_id=ticket_id,
            decision="approve",
            operator=agent_id,
            agent_id=agent_id,
            ttl_ms=1,
            binding_hash=int(details["binding_hash"]),
            binding_epoch=int(details["binding_epoch"]),
        )
        time.sleep(0.02)
        expired_req = build_exec_req(
            req_id=24000 + i,
            session_id=session_id,
            tool=risky_tool,
            tool_hash=risky_tool.manifest_hash,
            approval_ticket_id=ticket_id,
        )
        expired_resp, expired_lat = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=expired_req)
        rows.append(
            make_attack_row(
                scenario_group="B",
                attack_case="expired_ticket_replay",
                mode=mode,
                attack_profile=attack_profile,
                resp=expired_resp,
                latency_ms=expired_lat,
            )
        )

        ticket_id = get_ticket_for_risky_tool(
            sock_path=sock_path,
            timeout_s=timeout_s,
            session_id=session_id,
            tool=risky_tool,
            req_id=25000 + i,
        )
        approval_decide(
            sock_path=sock_path,
            timeout_s=timeout_s,
            ticket_id=ticket_id,
            decision="deny",
            operator=agent_id,
            agent_id=agent_id,
            ttl_ms=1000,
            binding_hash=int(details["binding_hash"]),
            binding_epoch=int(details["binding_epoch"]),
        )
        deny_req = build_exec_req(
            req_id=26000 + i,
            session_id=session_id,
            tool=risky_tool,
            tool_hash=risky_tool.manifest_hash,
            approval_ticket_id=ticket_id,
        )
        deny_resp, deny_lat = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=deny_req)
        rows.append(
            make_attack_row(
                scenario_group="B",
                attack_case="denied_ticket_reuse",
                mode=mode,
                attack_profile=attack_profile,
                resp=deny_resp,
                latency_ms=deny_lat,
            )
        )
    return rows


def scenario_metadata_tampering(
    *,
    sock_path: str,
    timeout_s: float,
    mode: str,
    attack_profile: str,
    safe_tool: ToolCase,
    all_tools: Sequence[ToolCase],
    repeats: int,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    wrong_app_id = alternate_app_id(all_tools, safe_tool)
    stale_hash = alternate_hash(all_tools, safe_tool)
    for i in range(repeats):
        session_id, _agent_id = open_session(sock_path, timeout_s, f"security-meta-{i}")
        hash_req = build_exec_req(
            req_id=30000 + i,
            session_id=session_id,
            tool=safe_tool,
            tool_hash="deadbeef",
        )
        hash_resp, hash_lat = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=hash_req)
        rows.append(
            make_attack_row(
                scenario_group="C",
                attack_case="hash_mismatch",
                mode=mode,
                attack_profile=attack_profile,
                resp=hash_resp,
                latency_ms=hash_lat,
            )
        )

        wrong_app_req = build_exec_req(
            req_id=31000 + i,
            session_id=session_id,
            tool=safe_tool,
            app_id=wrong_app_id,
            tool_hash=safe_tool.manifest_hash,
        )
        wrong_app_resp, wrong_app_lat = invoke_mcpd(
            sock_path=sock_path,
            timeout_s=timeout_s,
            req=wrong_app_req,
        )
        rows.append(
            make_attack_row(
                scenario_group="C",
                attack_case="wrong_app_binding",
                mode=mode,
                attack_profile=attack_profile,
                resp=wrong_app_resp,
                latency_ms=wrong_app_lat,
            )
        )

        stale_req = build_exec_req(
            req_id=32000 + i,
            session_id=session_id,
            tool=safe_tool,
            tool_hash=stale_hash,
        )
        stale_resp, stale_lat = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=stale_req)
        rows.append(
            make_attack_row(
                scenario_group="C",
                attack_case="stale_catalog_replay",
                mode=mode,
                attack_profile=attack_profile,
                resp=stale_resp,
                latency_ms=stale_lat,
            )
        )
    return rows


def scenario_toctou(
    *,
    sock_path: str,
    timeout_s: float,
    mode: str,
    attack_profile: str,
    risky_tool: ToolCase | None,
    all_tools: Sequence[ToolCase],
    repeats: int,
) -> List[Dict[str, Any]]:
    if risky_tool is None:
        return []
    rows: List[Dict[str, Any]] = []
    alternate_tool = next(
        (
            tool
            for tool in all_tools
            if tool.tool_id != risky_tool.tool_id and any(tag in HIGH_RISK_TAGS for tag in tool.risk_tags)
        ),
        None,
    )
    for i in range(repeats):
        details = open_session_details(sock_path, timeout_s, f"security-toctou-{i}")
        session_id = str(details["session_id"])
        agent_id = str(details["agent_id"])
        binding_hash = int(details["binding_hash"])
        binding_epoch = int(details["binding_epoch"])
        ticket_id = get_ticket_for_risky_tool(
            sock_path=sock_path,
            timeout_s=timeout_s,
            session_id=session_id,
            tool=risky_tool,
            req_id=33000 + i,
        )
        if ticket_id <= 0:
            continue
        approval_resp = approval_decide(
            sock_path=sock_path,
            timeout_s=timeout_s,
            ticket_id=ticket_id,
            decision="approve",
            operator=agent_id,
            agent_id=agent_id,
            ttl_ms=1000,
            binding_hash=binding_hash,
            binding_epoch=binding_epoch,
        )
        if approval_resp.get("status") != "ok":
            rows.append(
                make_attack_row(
                    scenario_group="E",
                    attack_case="approval_after_crash_state_missing",
                    mode=mode,
                    attack_profile=attack_profile,
                    resp=approval_resp,
                    latency_ms=0.0,
                )
            )
            continue

        bad_hash_req = build_exec_req(
            req_id=33000 + i,
            session_id=session_id,
            tool=risky_tool,
            tool_hash=alternate_hash(all_tools, risky_tool),
            approval_ticket_id=ticket_id,
        )
        bad_hash_resp, bad_hash_lat = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=bad_hash_req)
        rows.append(
            make_attack_row(
                scenario_group="E",
                attack_case="toctou_hash_mismatch_after_approval",
                mode=mode,
                attack_profile=attack_profile,
                resp=bad_hash_resp,
                latency_ms=bad_hash_lat,
            )
        )

        if alternate_tool is not None:
            bad_tool_req = build_exec_req(
                req_id=33000 + i,
                session_id=session_id,
                tool=alternate_tool,
                tool_hash=alternate_tool.manifest_hash,
                approval_ticket_id=ticket_id,
            )
            bad_tool_resp, bad_tool_lat = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=bad_tool_req)
            rows.append(
                make_attack_row(
                    scenario_group="E",
                    attack_case="toctou_tool_swap_after_approval",
                    mode=mode,
                    attack_profile=attack_profile,
                    resp=bad_tool_resp,
                    latency_ms=bad_tool_lat,
                )
            )
    return rows


def scenario_compromised_mediator(
    *,
    sock_path: str,
    timeout_s: float,
    mode: str,
    attack_profile: str,
    safe_tool: ToolCase,
    risky_tool: ToolCase | None,
    repeats: int,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for i in range(repeats):
        bad_session_req = build_exec_req(
            req_id=40000 + i,
            session_id=f"compromised-session-{i}",
            tool=safe_tool,
            tool_hash="deadbeef",
        )
        bad_session_resp, bad_session_lat = invoke_mcpd(
            sock_path=sock_path,
            timeout_s=timeout_s,
            req=bad_session_req,
        )
        rows.append(
            make_attack_row(
                scenario_group="D",
                attack_case="invalid_session_hash_bypass",
                mode=mode,
                attack_profile=attack_profile,
                resp=bad_session_resp,
                latency_ms=bad_session_lat,
            )
        )
        if risky_tool is None:
            continue
        risky_req = build_exec_req(
            req_id=41000 + i,
            session_id=f"compromised-risky-{i}",
            tool=risky_tool,
            tool_hash=risky_tool.manifest_hash,
            approval_ticket_id=888000 + i,
        )
        risky_resp, risky_lat = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=risky_req)
        rows.append(
            make_attack_row(
                scenario_group="D",
                attack_case="approval_required_bypass",
                mode=mode,
                attack_profile=attack_profile,
                resp=risky_resp,
                latency_ms=risky_lat,
            )
        )
    return rows


def scenario_direct_bypass(
    *,
    timeout_s: float,
    safe_tool: ToolCase,
    risky_tool: ToolCase | None,
    forwarder_sock: str,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for case_name, tool in (("direct_safe_tool", safe_tool), ("direct_risky_tool", risky_tool)):
        if tool is None:
            continue
        t0 = time.perf_counter()
        try:
            resp = call_tool_direct(tool, dict(tool.payloads[0]), timeout_s, 50000 + tool.tool_id)
        except Exception as exc:  # noqa: BLE001
            resp = {"status": "error", "error": str(exc)}
        rows.append(
            make_attack_row(
                scenario_group="E1",
                attack_case=case_name,
                mode="direct",
                attack_profile="",
                resp=resp,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )
        )
    fake_req = build_exec_req(
        req_id=51000,
        session_id="forwarder-bypass-session",
        tool=safe_tool,
    )
    fake_resp, fake_lat = invoke_mcpd(sock_path=forwarder_sock, timeout_s=timeout_s, req=fake_req)
    rows.append(
        make_attack_row(
            scenario_group="E1",
            attack_case="forwarder_fake_session",
            mode="forwarder_only",
            attack_profile="",
            resp=fake_resp,
            latency_ms=fake_lat,
        )
    )
    return rows


def _mixed_worker(
    *,
    worker_id: int,
    request_count: int,
    legit_session_id: str,
    legit_tool: ToolCase,
    risky_tool: ToolCase | None,
    malicious_pct: int,
    sock_path: str,
    timeout_s: float,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    malicious_every = 0 if malicious_pct <= 0 else max(int(round(100 / malicious_pct)), 1)
    for i in range(request_count):
        req_id = 60000 + worker_id * 100000 + i
        is_malicious = malicious_every > 0 and (i % malicious_every == 0)
        if is_malicious:
            if risky_tool is not None and i % 2 == 0:
                req = build_exec_req(
                    req_id=req_id,
                    session_id=f"mixed-malicious-{worker_id}-{i}",
                    tool=risky_tool,
                    tool_hash=risky_tool.manifest_hash,
                    approval_ticket_id=777000 + i,
                )
                attack_case = "approval_bypass"
            else:
                req = build_exec_req(
                    req_id=req_id,
                    session_id=f"mixed-malicious-{worker_id}-{i}",
                    tool=legit_tool,
                    tool_hash="deadbeef",
                )
                attack_case = "session_or_hash_bypass"
            resp, latency_ms = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=req)
            out.append(
                {
                    "category": "malicious",
                    "attack_case": attack_case,
                    "status": resp.get("status", ""),
                    "latency_ms": round(latency_ms, 3),
                    "accepted": 1 if resp.get("status") == "ok" else 0,
                }
            )
        else:
            req = build_exec_req(
                req_id=req_id,
                session_id=legit_session_id,
                tool=legit_tool,
                tool_hash=legit_tool.manifest_hash,
            )
            resp, latency_ms = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=req)
            out.append(
                {
                    "category": "legit",
                    "attack_case": "",
                    "status": resp.get("status", ""),
                    "latency_ms": round(latency_ms, 3),
                    "accepted": 1 if resp.get("status") == "ok" else 0,
                }
            )
    return out


def mixed_attack_under_load(
    *,
    sock_path: str,
    timeout_s: float,
    mode: str,
    attack_profile: str,
    safe_tool: ToolCase,
    risky_tool: ToolCase | None,
    requests: int,
    malicious_pct: int,
    concurrency: int,
) -> Dict[str, Any]:
    session_id, _agent_id = open_session(sock_path, timeout_s, f"security-mixed-{mode}-{malicious_pct}")
    base = requests // concurrency
    rem = requests % concurrency
    rows: List[Dict[str, Any]] = []
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = []
        for worker_id in range(concurrency):
            count = base + (1 if worker_id < rem else 0)
            if count <= 0:
                continue
            futures.append(
                pool.submit(
                    _mixed_worker,
                    worker_id=worker_id,
                    request_count=count,
                    legit_session_id=session_id,
                    legit_tool=safe_tool,
                    risky_tool=risky_tool,
                    malicious_pct=malicious_pct,
                    sock_path=sock_path,
                    timeout_s=timeout_s,
                )
            )
        for fut in as_completed(futures):
            rows.extend(fut.result())
    elapsed_s = max(time.perf_counter() - started, 1e-9)
    legit = [row for row in rows if row["category"] == "legit"]
    malicious = [row for row in rows if row["category"] == "malicious"]
    all_latencies = [float(row["latency_ms"]) for row in legit]
    return {
        "mode": mode,
        "attack_profile": attack_profile,
        "malicious_pct": malicious_pct,
        "requests": requests,
        "concurrency": concurrency,
        "legit_throughput_rps": round(len(legit) / elapsed_s, 3) if legit else 0.0,
        "legit_success_rate": round(sum(row["accepted"] for row in legit) / max(len(legit), 1), 6),
        "legit_p95_ms": round(percentile(sorted(all_latencies), 0.95), 3) if all_latencies else 0.0,
        "attack_acceptance_rate": round(sum(row["accepted"] for row in malicious) / max(len(malicious), 1), 6) if malicious else 0.0,
        "attack_count": len(malicious),
    }


def build_invariant_summary(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_mode: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        by_mode.setdefault(str(row.get("mode", "")), []).append(row)
    out: List[Dict[str, Any]] = []
    for mode, items in sorted(by_mode.items()):
        if mode in {"direct", "forwarder_only"}:
            out.append(
                {
                    "mode": mode,
                    "I1_unauthorized_blocked": "no",
                    "I2_approval_required_enforced": "no",
                    "I3_session_binding_enforced": "no",
                    "I4_metadata_integrity_enforced": "no",
                    "I5_compromise_contained": "no",
                    "preserved_invariants_ratio": 0.0,
                }
            )
            continue
        group_a = [row for row in items if row.get("scenario_group") == "A"]
        group_b = [row for row in items if row.get("scenario_group") == "B"]
        group_c = [row for row in items if row.get("scenario_group") == "C"]
        group_d = [row for row in items if row.get("scenario_group") == "D"]
        group_e = [row for row in items if row.get("scenario_group") == "E"]
        unauthorized = any(int(row.get("unauthorized_success", 0)) for row in items if row.get("scenario_group") in {"A", "B", "C", "D", "E"})
        out.append(
            {
                "mode": mode,
                "I1_unauthorized_blocked": "yes" if not unauthorized else "no",
                "I2_approval_required_enforced": "yes" if not any(int(row.get("unauthorized_success", 0)) for row in group_b) else "no",
                "I3_session_binding_enforced": "yes" if not any(int(row.get("unauthorized_success", 0)) for row in group_a) else "no",
                "I4_metadata_integrity_enforced": "yes" if not any(int(row.get("unauthorized_success", 0)) for row in group_c) else "no",
                "I5_compromise_contained": "yes" if not any(int(row.get("unauthorized_success", 0)) for row in group_d + group_e) else "no",
                "preserved_invariants_ratio": round(
                    sum(
                        1
                        for key in (
                            not unauthorized,
                            not any(int(row.get("unauthorized_success", 0)) for row in group_b),
                            not any(int(row.get("unauthorized_success", 0)) for row in group_a),
                            not any(int(row.get("unauthorized_success", 0)) for row in group_c),
                            not any(int(row.get("unauthorized_success", 0)) for row in group_d + group_e),
                        )
                        if key
                    )
                    / 5.0,
                    3,
                ),
            }
        )
    return out


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def semantic_fingerprint(tool: ToolCase, manifest: Dict[str, Any], tool_obj: Dict[str, Any]) -> str:
    semantic_view = {
        "app_id": manifest.get("app_id", ""),
        "tool_id": tool.tool_id,
        "name": tool_obj.get("name", ""),
        "operation": tool_obj.get("operation", ""),
        "risk_tags": sorted(str(tag) for tag in tool_obj.get("risk_tags", []) if isinstance(tag, str)),
        "input_schema": tool_obj.get("input_schema", {}),
        "approval_policy": tool_obj.get("approval_policy", {}),
    }
    return _canonical_json(semantic_view)


def _load_manifest_pair(tool: ToolCase) -> tuple[Dict[str, Any], Dict[str, Any]]:
    for manifest_path in sorted((ROOT_DIR / "tool-app" / "manifests").glob("*.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("app_id") != tool.app_id:
            continue
        for item in manifest.get("tools", []):
            if isinstance(item, dict) and int(item.get("tool_id", -1)) == tool.tool_id:
                return manifest, item
    raise RuntimeError(f"manifest entry not found for tool_id={tool.tool_id}")


def run_semantic_tampering(tool: ToolCase | None) -> Dict[str, Any]:
    if tool is None:
        return {"status": "skipped", "reason": "no tool available"}
    manifest, tool_obj = _load_manifest_pair(tool)
    baseline = semantic_fingerprint(tool, manifest, tool_obj)
    mutations: List[Tuple[str, str, Dict[str, Any]]] = [
        ("benign", "risk_tag_reorder", {"risk_tags": list(reversed(tool_obj.get("risk_tags", [])))}),
        ("benign", "example_reorder", {"examples": list(reversed(tool_obj.get("examples", [])))}),
        ("benign", "description_whitespace", {"description": f"  {tool_obj.get('description', '')}  "}),
        ("adversarial", "risk_downgrade", {"risk_tags": [tag for tag in tool_obj.get("risk_tags", []) if tag != "external_network"]}),
        ("adversarial", "approval_removed", {"approval_policy": {}}),
        ("adversarial", "operation_swap", {"operation": f"{tool_obj.get('operation', '')}_tampered"}),
    ]
    rows: List[Dict[str, Any]] = []
    tp = fp = tn = fn = 0
    for kind, name, patch in mutations:
        mutated = json.loads(json.dumps(tool_obj))
        mutated.update(patch)
        changed = semantic_fingerprint(tool, manifest, mutated) != baseline
        expected_detect = kind == "adversarial"
        if expected_detect and changed:
            outcome = "tp"
            tp += 1
        elif expected_detect and not changed:
            outcome = "fn"
            fn += 1
        elif not expected_detect and changed:
            outcome = "fp"
            fp += 1
        else:
            outcome = "tn"
            tn += 1
        rows.append(
            {
                "tool_id": tool.tool_id,
                "tool_name": tool.tool_name,
                "mutation_kind": kind,
                "mutation_name": name,
                "detected": 1 if changed else 0,
                "expected_detect": 1 if expected_detect else 0,
                "outcome": outcome,
            }
        )
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    bypass = fn / max(tp + fn, 1)
    return {
        "status": "ok",
        "tool_id": tool.tool_id,
        "tool_name": tool.tool_name,
        "rows": rows,
        "summary": {
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "false_positive_rate": round(fp / max(fp + tn, 1), 6),
            "false_negative_rate": round(fn / max(tp + fn, 1), 6),
            "bypass_success_rate": round(bypass, 6),
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
        },
    }


def run_daemon_compromise(
    *,
    kernel_sock_path: str,
    timeout_s: float,
    risky_tool: ToolCase | None,
) -> List[Dict[str, Any]]:
    if risky_tool is None:
        return []
    rows: List[Dict[str, Any]] = []
    kernel_variant_sock = "/tmp/mcpd-kernel-crash-security.sock"
    userspace_variant_sock = "/tmp/mcpd-userspace-crash-security.sock"
    variant_specs = [
        ("kernel", "normal", kernel_variant_sock),
        ("userspace", "userspace_semantic_plane", userspace_variant_sock),
    ]
    for mode_label, variant_mode, sock_path in variant_specs:
        proc = launch_mcpd_variant(mode=variant_mode, sock_path=sock_path)
        try:
            wait_mcpd_ready(sock_path, max(10.0, timeout_s))
            details = open_session_details(sock_path, timeout_s, f"daemon-crash-{mode_label}")
            session_id = str(details["session_id"])
            agent_id = str(details["agent_id"])
            ticket_id = get_ticket_for_risky_tool(
                sock_path=sock_path,
                timeout_s=timeout_s,
                session_id=session_id,
                tool=risky_tool,
                req_id=70000,
            )
            pre_agents = read_kernel_agent_dirs()
            stop_process(proc, sock_path)
            proc = launch_mcpd_variant(mode=variant_mode, sock_path=sock_path)
            wait_mcpd_ready(sock_path, max(10.0, timeout_s))
            post_agents = read_kernel_agent_dirs()
            t0 = time.perf_counter()
            approval_resp = approval_decide(
                sock_path=sock_path,
                timeout_s=timeout_s,
                ticket_id=ticket_id,
                decision="approve",
                operator=agent_id,
                agent_id=agent_id,
                ttl_ms=1000,
                binding_hash=int(details["binding_hash"]),
                binding_epoch=int(details["binding_epoch"]),
            )
            approval_latency_ms = (time.perf_counter() - t0) * 1000.0
            replay_req = build_exec_req(
                req_id=70000,
                session_id=session_id,
                tool=risky_tool,
                tool_hash=risky_tool.manifest_hash,
                approval_ticket_id=ticket_id,
            )
            replay_resp, replay_latency = invoke_mcpd(sock_path=sock_path, timeout_s=timeout_s, req=replay_req)
            rows.append(
                {
                    "mode": mode_label,
                    "scenario": "daemon_crash",
                    "ticket_id": ticket_id,
                    "approval_state_preserved": 1 if approval_resp.get("status") == "ok" else 0,
                    "session_state_preserved": 1 if replay_resp.get("status") == "ok" else 0,
                    "approval_error": str(approval_resp.get("error", "")),
                    "replay_error": str(replay_resp.get("error", "")),
                    "approval_latency_ms": round(approval_latency_ms, 3),
                    "replay_latency_ms": round(replay_latency, 3),
                    "pre_crash_agent_visible": 1 if agent_id in pre_agents else 0,
                    "post_crash_agent_visible": 1 if agent_id in post_agents else 0,
                }
            )
        finally:
            stop_process(proc, sock_path)
    return rows


def build_mechanism_ablation(
    attack_rows: Sequence[Dict[str, Any]],
    daemon_rows: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    mappings = [
        ("agent_binding", "A", "mcpd", "userspace_tamper_session"),
        ("approval_token", "B", "mcpd", "userspace_tamper_approval"),
        ("semantic_hash", "C", "mcpd", "userspace_tamper_metadata"),
        ("toctou_binding", "E", "mcpd", "userspace_tamper_approval"),
    ]
    for mechanism, group, baseline_mode, ablated_mode in mappings:
        base = [row for row in attack_rows if row.get("scenario_group") == group and row.get("mode") == baseline_mode]
        ablated = [row for row in attack_rows if row.get("scenario_group") == group and row.get("mode") == ablated_mode]
        if not base or not ablated:
            continue
        base_rate = sum(int(row.get("unauthorized_success", 0)) for row in base) / max(len(base), 1)
        ablated_rate = sum(int(row.get("unauthorized_success", 0)) for row in ablated) / max(len(ablated), 1)
        out.append(
            {
                "mechanism": mechanism,
                "baseline_mode": baseline_mode,
                "ablated_mode": ablated_mode,
                "baseline_attack_success_rate": round(base_rate, 6),
                "ablated_attack_success_rate": round(ablated_rate, 6),
                "delta": round(ablated_rate - base_rate, 6),
            }
        )
    if daemon_rows:
        by_mode = {row["mode"]: row for row in daemon_rows}
        kernel_row = by_mode.get("kernel")
        userspace_row = by_mode.get("userspace")
        if kernel_row and userspace_row:
            out.append(
                {
                    "mechanism": "kernel_state",
                    "baseline_mode": "kernel",
                    "ablated_mode": "userspace",
                    "baseline_attack_success_rate": round(1.0 - float(kernel_row.get("approval_state_preserved", 0)), 6),
                    "ablated_attack_success_rate": round(1.0 - float(userspace_row.get("approval_state_preserved", 0)), 6),
                    "delta": round(float(kernel_row.get("approval_state_preserved", 0)) - float(userspace_row.get("approval_state_preserved", 0)), 6),
                }
            )
    return out


def run_observability(
    *,
    kernel_sock_path: str,
    timeout_s: float,
    safe_tool: ToolCase,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for label, mode, sock_path in (
        ("kernel", "normal", "/tmp/mcpd-kernel-observe.sock"),
        ("userspace", "userspace_semantic_plane", "/tmp/mcpd-userspace-observe.sock"),
    ):
        proc = launch_mcpd_variant(mode=mode, sock_path=sock_path)
        try:
            wait_mcpd_ready(sock_path, max(10.0, timeout_s))
            details = open_session_details(sock_path, timeout_s, f"observe-{label}")
            resp, _ = invoke_mcpd(
                sock_path=sock_path,
                timeout_s=timeout_s,
                req=build_exec_req(
                    req_id=80000,
                    session_id=str(details["session_id"]),
                    tool=safe_tool,
                    tool_hash=safe_tool.manifest_hash,
                ),
            )
            reason_ok = 1 if resp.get("status") == "ok" and resp.get("decision", "ALLOW") == "ALLOW" else 0
            pre_state = sysfs_snapshot_for_agent(str(details["agent_id"]))
            stop_process(proc, sock_path)
            post_state = sysfs_snapshot_for_agent(str(details["agent_id"]))
            rows.append(
                {
                    "mode": label,
                    "independent_audit": 1 if label == "kernel" else 0,
                    "state_introspection": 1 if pre_state else 0,
                    "post_crash_visibility": 1 if post_state else 0,
                    "root_cause_success_rate": float(reason_ok),
                }
            )
        finally:
            try:
                stop_process(proc, sock_path)
            except Exception:
                pass
    return rows


def render_report(summary: Dict[str, Any]) -> str:
    attack_summary = summary.get("attack_summary", [])
    invariants = summary.get("invariant_summary", [])
    mixed = summary.get("mixed_attack", [])
    semantic = summary.get("semantic_tampering", {})
    daemon_rows = summary.get("daemon_compromise", [])
    observability_rows = summary.get("observability", [])
    ablation_rows = summary.get("mechanism_ablation", [])
    lines: List[str] = []
    lines.append("# linux-mcp Security Evaluation Report")
    lines.append("")
    lines.append("## Threat Model Scope")
    lines.append("")
    lines.append("- Local userspace adversary can tamper with userspace semantic state, forge sessions, replay approval tickets, and send malformed RPCs.")
    lines.append("- The kernel-backed mode keeps kernel arbitration state trusted; the userspace baseline exposes optional attack profiles to simulate mediator compromise.")
    lines.append("- Direct endpoint bypass is reported separately because the current demo does not isolate tool endpoints behind kernel-only mediation.")
    lines.append("")
    lines.append("## Attack Summary")
    lines.append("")
    lines.append("| group | case | mode | attempts | bypass_success_rate | detection_rate | reject_p95_ms |")
    lines.append("|---|---|---|---:|---:|---:|---:|")
    for item in attack_summary:
        lines.append(
            f"| {item.get('scenario_group','')} | {item.get('attack_case','')} | {item.get('mode','')} | {item.get('attempts',0)} | "
            f"{float(item.get('bypass_success_rate',0.0))*100:.2f}% | {float(item.get('detection_rate',0.0))*100:.2f}% | "
            f"{float(item.get('reject_latency_p95_ms',0.0)):.2f} |"
        )
    lines.append("")
    if isinstance(semantic, dict) and semantic.get("status") == "ok":
        semantic_summary = semantic.get("summary", {})
        lines.append("## Semantic Tampering")
        lines.append("")
        lines.append("| precision | recall | false_positive_rate | false_negative_rate | bypass_success_rate |")
        lines.append("|---:|---:|---:|---:|---:|")
        lines.append(
            f"| {float(semantic_summary.get('precision', 0.0))*100:.2f}% | {float(semantic_summary.get('recall', 0.0))*100:.2f}% | "
            f"{float(semantic_summary.get('false_positive_rate', 0.0))*100:.2f}% | {float(semantic_summary.get('false_negative_rate', 0.0))*100:.2f}% | "
            f"{float(semantic_summary.get('bypass_success_rate', 0.0))*100:.2f}% |"
        )
        lines.append("")
    lines.append("## Invariant Summary")
    lines.append("")
    lines.append("| mode | I1 | I2 | I3 | I4 | I5 | preserved_ratio |")
    lines.append("|---|---|---|---|---|---|---:|")
    for item in invariants:
        lines.append(
            f"| {item.get('mode','')} | {item.get('I1_unauthorized_blocked','')} | {item.get('I2_approval_required_enforced','')} | "
            f"{item.get('I3_session_binding_enforced','')} | {item.get('I4_metadata_integrity_enforced','')} | "
            f"{item.get('I5_compromise_contained','')} | {item.get('preserved_invariants_ratio',0.0):.3f} |"
        )
    lines.append("")
    lines.append("## Daemon Compromise")
    lines.append("")
    lines.append("| mode | approval_state_preserved | session_state_preserved | post_crash_agent_visible | approval_error | replay_error |")
    lines.append("|---|---:|---:|---:|---|---|")
    for item in daemon_rows:
        lines.append(
            f"| {item.get('mode','')} | {item.get('approval_state_preserved',0)} | {item.get('session_state_preserved',0)} | "
            f"{item.get('post_crash_agent_visible',0)} | {item.get('approval_error','')} | {item.get('replay_error','')} |"
        )
    lines.append("")
    lines.append("## Mechanism Ablation")
    lines.append("")
    lines.append("| mechanism | baseline_mode | ablated_mode | baseline_attack_success_rate | ablated_attack_success_rate | delta |")
    lines.append("|---|---|---|---:|---:|---:|")
    for item in ablation_rows:
        lines.append(
            f"| {item.get('mechanism','')} | {item.get('baseline_mode','')} | {item.get('ablated_mode','')} | "
            f"{float(item.get('baseline_attack_success_rate',0.0))*100:.2f}% | {float(item.get('ablated_attack_success_rate',0.0))*100:.2f}% | "
            f"{float(item.get('delta',0.0))*100:.2f}% |"
        )
    lines.append("")
    lines.append("## Mixed Attack Under Load")
    lines.append("")
    lines.append("| mode | malicious_pct | legit_throughput_rps | legit_p95_ms | attack_acceptance_rate |")
    lines.append("|---|---:|---:|---:|---:|")
    for item in mixed:
        lines.append(
            f"| {item.get('mode','')} | {item.get('malicious_pct',0)} | {item.get('legit_throughput_rps',0.0)} | "
            f"{item.get('legit_p95_ms',0.0)} | {float(item.get('attack_acceptance_rate',0.0))*100:.2f}% |"
        )
    lines.append("")
    lines.append("## Observability")
    lines.append("")
    lines.append("| mode | independent_audit | state_introspection | post_crash_visibility | root_cause_success_rate |")
    lines.append("|---|---:|---:|---:|---:|")
    for item in observability_rows:
        lines.append(
            f"| {item.get('mode','')} | {item.get('independent_audit',0)} | {item.get('state_introspection',0)} | "
            f"{item.get('post_crash_visibility',0)} | {float(item.get('root_cause_success_rate',0.0))*100:.2f}% |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Security evaluation runner for linux-mcp")
    parser.add_argument("--mcpd-sock", type=str, default=DEFAULT_MCPD_SOCK)
    parser.add_argument("--timeout-s", type=float, default=5.0)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--mixed-requests", type=int, default=500)
    parser.add_argument("--mixed-concurrency", type=int, default=8)
    parser.add_argument("--mixed-malicious-pct", type=str, default="0,5,10,20")
    parser.add_argument("--max-tools", type=int, default=20)
    parser.add_argument("--output-dir", type=str, default="experiment-results/security")
    args = parser.parse_args()

    ensure_prerequisites(args.mcpd_sock, args.timeout_s)
    tools = enrich_hash_from_mcpd(load_manifest_tools(), args.mcpd_sock, args.timeout_s)
    selected = preflight_tools(
        tools,
        mcpd_sock=args.mcpd_sock,
        timeout_s=args.timeout_s,
        include_write=False,
        max_tools=args.max_tools,
    )
    if not selected:
        raise RuntimeError("no tools passed preflight for security evaluation")
    safe_tool = choose_safe_tool(selected) or selected[0]
    risky_tool = find_working_approval_tool(
        sock_path=args.mcpd_sock,
        timeout_s=args.timeout_s,
        tools=tools,
    )

    run_ts = time.strftime("run-%Y%m%d-%H%M%S", time.gmtime())
    run_dir = ROOT_DIR / args.output_dir / run_ts
    run_dir.mkdir(parents=True, exist_ok=True)

    all_attack_rows: List[Dict[str, Any]] = []
    variant_specs = [
        ("mcpd", args.mcpd_sock, "", ""),
        ("userspace_semantic_plane", "/tmp/mcpd-userspace-security.sock", "userspace_semantic_plane", ""),
        ("userspace_tamper_session", "/tmp/mcpd-userspace-security-session.sock", "userspace_semantic_plane", "tamper_session"),
        ("userspace_tamper_approval", "/tmp/mcpd-userspace-security-approval.sock", "userspace_semantic_plane", "tamper_approval"),
        ("userspace_tamper_metadata", "/tmp/mcpd-userspace-security-metadata.sock", "userspace_semantic_plane", "tamper_metadata"),
        ("userspace_compromised", "/tmp/mcpd-userspace-security-compromised.sock", "userspace_semantic_plane", "compromised_userspace"),
    ]

    for label, sock_path, mode, attack_profile in variant_specs:
        ctx = (
            contextlib.nullcontext()
            if not mode
            else managed_mcpd_variant(
                mode=mode,
                sock_path=sock_path,
                timeout_s=max(10.0, args.timeout_s),
                attack_profile=attack_profile,
            )
        )
        active_sock = args.mcpd_sock if not mode else sock_path
        with ctx:
            if label in {"mcpd", "userspace_semantic_plane", "userspace_tamper_session"}:
                all_attack_rows.extend(
                    scenario_session_forgery(
                        sock_path=active_sock,
                        timeout_s=args.timeout_s,
                        mode=label,
                        attack_profile=attack_profile,
                        safe_tool=safe_tool,
                        repeats=args.repeats,
                    )
                )
            if label in {"mcpd", "userspace_semantic_plane", "userspace_tamper_approval"}:
                all_attack_rows.extend(
                    scenario_approval_forgery(
                        sock_path=active_sock,
                        timeout_s=args.timeout_s,
                        mode=label,
                        attack_profile=attack_profile,
                        risky_tool=risky_tool,
                        all_tools=tools,
                        repeats=args.repeats,
                    )
                )
            if label in {"mcpd", "userspace_semantic_plane", "userspace_tamper_metadata"}:
                all_attack_rows.extend(
                    scenario_metadata_tampering(
                        sock_path=active_sock,
                        timeout_s=args.timeout_s,
                        mode=label,
                        attack_profile=attack_profile,
                        safe_tool=safe_tool,
                        all_tools=tools,
                        repeats=args.repeats,
                    )
                )
            if label in {"mcpd", "userspace_semantic_plane", "userspace_tamper_approval"}:
                all_attack_rows.extend(
                    scenario_toctou(
                        sock_path=active_sock,
                        timeout_s=args.timeout_s,
                        mode=label,
                        attack_profile=attack_profile,
                        risky_tool=risky_tool,
                        all_tools=tools,
                        repeats=args.repeats,
                    )
                )
            if label in {"mcpd", "userspace_semantic_plane", "userspace_compromised"}:
                all_attack_rows.extend(
                    scenario_compromised_mediator(
                        sock_path=active_sock,
                        timeout_s=args.timeout_s,
                        mode=label,
                        attack_profile=attack_profile,
                        safe_tool=safe_tool,
                        risky_tool=risky_tool,
                        repeats=args.repeats,
                    )
                )

    mixed_rows: List[Dict[str, Any]] = []
    mixed_pcts = parse_percent_list(args.mixed_malicious_pct)
    for label, sock_path, mode, attack_profile in (
        ("mcpd", args.mcpd_sock, "", ""),
        ("userspace_semantic_plane", "/tmp/mcpd-userspace-security-mixed.sock", "userspace_semantic_plane", ""),
        ("userspace_compromised", "/tmp/mcpd-userspace-security-mixed-compromised.sock", "userspace_semantic_plane", "compromised_userspace"),
    ):
        ctx = (
            contextlib.nullcontext()
            if not mode
            else managed_mcpd_variant(
                mode=mode,
                sock_path=sock_path,
                timeout_s=max(10.0, args.timeout_s),
                attack_profile=attack_profile,
            )
        )
        active_sock = args.mcpd_sock if not mode else sock_path
        with ctx:
            for malicious_pct in mixed_pcts:
                mixed_rows.append(
                    mixed_attack_under_load(
                        sock_path=active_sock,
                        timeout_s=args.timeout_s,
                        mode=label,
                        attack_profile=attack_profile,
                        safe_tool=safe_tool,
                        risky_tool=risky_tool,
                        requests=args.mixed_requests,
                        malicious_pct=malicious_pct,
                        concurrency=args.mixed_concurrency,
                    )
                )

    with managed_mcpd_variant(
        mode="forwarder_only",
        sock_path="/tmp/mcpd-forwarder-security.sock",
        timeout_s=max(10.0, args.timeout_s),
    ):
        all_attack_rows.extend(
            scenario_direct_bypass(
                timeout_s=args.timeout_s,
                safe_tool=safe_tool,
                risky_tool=risky_tool,
                forwarder_sock="/tmp/mcpd-forwarder-security.sock",
            )
        )

    attack_summary = summarize_attack_rows(all_attack_rows)
    invariant_summary = build_invariant_summary(all_attack_rows)
    semantic = run_semantic_tampering(risky_tool or safe_tool)
    daemon_rows = run_daemon_compromise(
        kernel_sock_path=args.mcpd_sock,
        timeout_s=args.timeout_s,
        risky_tool=risky_tool,
    )
    observability_rows = run_observability(
        kernel_sock_path=args.mcpd_sock,
        timeout_s=args.timeout_s,
        safe_tool=safe_tool,
    )
    ablation_rows = build_mechanism_ablation(all_attack_rows, daemon_rows)
    result = {
        "meta": {
            "run_ts": run_ts,
            "repeats": args.repeats,
            "mixed_requests": args.mixed_requests,
            "mixed_concurrency": args.mixed_concurrency,
            "mixed_malicious_pct": mixed_pcts,
            "safe_tool": {
                "tool_id": safe_tool.tool_id,
                "tool_name": safe_tool.tool_name,
                "app_id": safe_tool.app_id,
            },
            "risky_tool": (
                {
                    "tool_id": risky_tool.tool_id,
                    "tool_name": risky_tool.tool_name,
                    "app_id": risky_tool.app_id,
                }
                if risky_tool is not None
                else {}
            ),
        },
        "attack_rows": all_attack_rows,
        "attack_summary": attack_summary,
        "invariant_summary": invariant_summary,
        "mixed_attack": mixed_rows,
        "semantic_tampering": semantic,
        "daemon_compromise": daemon_rows,
        "observability": observability_rows,
        "mechanism_ablation": ablation_rows,
    }
    (run_dir / "security_summary.json").write_text(json.dumps(result, indent=2, ensure_ascii=True), encoding="utf-8")
    write_csv(
        run_dir / "attack_rows.csv",
        all_attack_rows,
        [
            "scenario_group",
            "attack_case",
            "mode",
            "attack_profile",
            "status",
            "decision",
            "error",
            "latency_ms",
            "unauthorized_success",
            "expected_reject",
            "invariant_violated",
        ],
    )
    write_csv(
        run_dir / "attack_summary.csv",
        attack_summary,
        [
            "scenario_group",
            "attack_case",
            "mode",
            "attempts",
            "policy_violation_rate",
            "bypass_success_rate",
            "forgery_acceptance_rate",
            "detection_rate",
            "reject_rate",
            "invariant_violation_count",
            "reject_latency_avg_ms",
            "reject_latency_p95_ms",
        ],
    )
    write_csv(
        run_dir / "invariant_summary.csv",
        invariant_summary,
        [
            "mode",
            "I1_unauthorized_blocked",
            "I2_approval_required_enforced",
            "I3_session_binding_enforced",
            "I4_metadata_integrity_enforced",
            "I5_compromise_contained",
            "preserved_invariants_ratio",
        ],
    )
    write_csv(
        run_dir / "mixed_attack.csv",
        mixed_rows,
        [
            "mode",
            "attack_profile",
            "malicious_pct",
            "requests",
            "concurrency",
            "legit_throughput_rps",
            "legit_success_rate",
            "legit_p95_ms",
            "attack_acceptance_rate",
            "attack_count",
        ],
    )
    semantic_rows = semantic.get("rows", []) if isinstance(semantic, dict) else []
    write_csv(
        run_dir / "semantic_tampering.csv",
        semantic_rows,
        [
            "tool_id",
            "tool_name",
            "mutation_kind",
            "mutation_name",
            "detected",
            "expected_detect",
            "outcome",
        ],
    )
    semantic_summary_rows = [semantic.get("summary", {})] if isinstance(semantic, dict) and semantic.get("status") == "ok" else []
    write_csv(
        run_dir / "semantic_summary.csv",
        semantic_summary_rows,
        [
            "precision",
            "recall",
            "false_positive_rate",
            "false_negative_rate",
            "bypass_success_rate",
            "tp",
            "tn",
            "fp",
            "fn",
        ],
    )
    write_csv(
        run_dir / "daemon_compromise.csv",
        daemon_rows,
        [
            "mode",
            "scenario",
            "ticket_id",
            "approval_state_preserved",
            "session_state_preserved",
            "approval_error",
            "replay_error",
            "approval_latency_ms",
            "replay_latency_ms",
            "pre_crash_agent_visible",
            "post_crash_agent_visible",
        ],
    )
    write_csv(
        run_dir / "observability.csv",
        observability_rows,
        [
            "mode",
            "independent_audit",
            "state_introspection",
            "post_crash_visibility",
            "root_cause_success_rate",
        ],
    )
    write_csv(
        run_dir / "mechanism_ablation.csv",
        ablation_rows,
        [
            "mechanism",
            "baseline_mode",
            "ablated_mode",
            "baseline_attack_success_rate",
            "ablated_attack_success_rate",
            "delta",
        ],
    )
    (run_dir / "security_report.md").write_text(render_report(result), encoding="utf-8")
    print(f"[done] security_result_dir={run_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
