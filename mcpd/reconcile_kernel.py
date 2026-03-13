#!/usr/bin/env python3
"""Reconcile provider manifests with kernel capability-domain registry."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Dict

from architecture import build_capability_catalog, load_provider_manifest
from netlink_client import KernelMcpNetlinkClient

ROOT_DIR = Path(__file__).resolve().parent.parent
MANIFESTS_DIR = ROOT_DIR / "tool-app" / "manifests"
LIST_BIN = ROOT_DIR / "client" / "bin" / "genl_list_tools"

LIST_RE = re.compile(
    r"^id=(?P<id>\d+)\s+name=(?P<name>\S+)\s+perm=(?P<perm>\d+)\s+cost=(?P<cost>\d+)\s+status=(?P<status>\S+)(?:\s+hash=(?P<hash>\S+))?$"
)


def _run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=str(ROOT_DIR), text=True, capture_output=True)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def _check_prerequisites() -> None:
    if not LIST_BIN.exists():
        raise RuntimeError("client binary missing; run: make -C client clean && make -C client")

    lsmod = _run_cmd(["lsmod"])
    loaded = False
    for line in lsmod.stdout.splitlines()[1:]:
        cols = line.split()
        if cols and cols[0] == "kernel_mcp":
            loaded = True
            break
    if not loaded:
        raise RuntimeError("kernel module kernel_mcp not loaded")


def _load_capabilities() -> Dict[str, dict]:
    providers = []
    for manifest_path in sorted(MANIFESTS_DIR.glob("*.json")):
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        providers.append(load_provider_manifest(str(manifest_path), raw))
    if not providers:
        raise RuntimeError(f"no manifests found in {MANIFESTS_DIR}")

    capabilities = build_capability_catalog(providers)
    out: Dict[str, dict] = {}
    for capability_name, capability in capabilities.items():
        out[capability_name] = {
            "tool_id": capability.capability_id,
            "name": capability.name,
            "perm": capability.perm,
            "cost": capability.cost,
            "hash": capability.manifest_hash,
            "required_caps": capability.required_caps,
            "risk_level": capability.risk_level,
            "approval_mode": capability.approval_mode,
            "audit_mode": capability.audit_mode,
            "max_inflight_per_agent": capability.max_inflight_per_agent,
            "rate_limit": dict(capability.rate_limit),
        }
    return out


def _register_capabilities(capabilities: Dict[str, dict]) -> None:
    client = KernelMcpNetlinkClient()
    try:
        for capability_name in sorted(capabilities.keys()):
            capability = capabilities[capability_name]
            client.register_tool(
                tool_id=int(capability["tool_id"]),
                name=str(capability["name"]),
                perm=int(capability["perm"]),
                cost=int(capability["cost"]),
                tool_hash=str(capability["hash"]),
                required_caps=int(capability["required_caps"]),
                risk_level=int(capability["risk_level"]),
                approval_mode=int(capability["approval_mode"]),
                audit_mode=int(capability["audit_mode"]),
                max_inflight_per_agent=int(capability["max_inflight_per_agent"]),
                rl_enabled=bool(capability["rate_limit"].get("enabled", False)),
                rl_burst=int(capability["rate_limit"].get("burst", 0)),
                rl_refill_tokens=int(capability["rate_limit"].get("refill_tokens", 0)),
                rl_refill_jiffies=int(capability["rate_limit"].get("refill_jiffies", 0)),
                rl_default_cost=int(capability["rate_limit"].get("default_cost", 0)),
                rl_max_inflight_per_agent=int(
                    capability["rate_limit"].get("max_inflight_per_agent", 0)
                ),
                rl_defer_wait_ms=int(capability["rate_limit"].get("defer_wait_ms", 0)),
            )
            print(
                "[reconcile] registered capability id={} name={} perm={} cost={} hash={} required_caps={} risk_level={} approval_mode={} audit_mode={}".format(
                    capability["tool_id"],
                    capability["name"],
                    capability["perm"],
                    capability["cost"],
                    capability["hash"],
                    capability["required_caps"],
                    capability["risk_level"],
                    capability["approval_mode"],
                    capability["audit_mode"],
                ),
                flush=True,
            )
    finally:
        client.close()


def _list_kernel_tools() -> Dict[int, Dict[str, str]]:
    proc = _run_cmd([str(LIST_BIN)])
    tools: Dict[int, Dict[str, str]] = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        match = LIST_RE.match(line)
        if not match:
            continue
        tool_id = int(match.group("id"))
        tools[tool_id] = {
            "tool_id": tool_id,
            "name": match.group("name"),
            "perm": int(match.group("perm")),
            "cost": int(match.group("cost")),
            "hash": match.group("hash") or "",
        }
    return tools


def _verify(capabilities: Dict[str, dict], kernel_tools: Dict[int, Dict[str, str]]) -> None:
    expected_ids = {capability["tool_id"] for capability in capabilities.values()}
    actual_ids = set(kernel_tools.keys())
    ok = True

    missing = sorted(expected_ids - actual_ids)
    extra = sorted(actual_ids - expected_ids)
    if missing:
        print(f"[reconcile] missing capability ids in kernel registry: {missing}", flush=True)
        ok = False
    if extra:
        print(f"[reconcile] extra kernel entries not in capability registry: {extra}", flush=True)
        ok = False

    for capability in capabilities.values():
        actual = kernel_tools.get(capability["tool_id"])
        if actual is None:
            continue
        if (
            actual["name"] != capability["name"]
            or actual["perm"] != capability["perm"]
            or actual["cost"] != capability["cost"]
            or actual["hash"] != capability["hash"]
        ):
            print(
                "[reconcile] mismatch id={}: expected name={} perm={} cost={} hash={}, got name={} perm={} cost={} hash={}".format(
                    capability["tool_id"],
                    capability["name"],
                    capability["perm"],
                    capability["cost"],
                    capability["hash"],
                    actual["name"],
                    actual["perm"],
                    actual["cost"],
                    actual["hash"],
                ),
                flush=True,
            )
            ok = False

    if not ok:
        raise RuntimeError("capability registry reconciliation failed")


def main() -> int:
    try:
        _check_prerequisites()
        capabilities = _load_capabilities()
        print(
            "[reconcile] loaded capability domains: {}".format(
                sorted(capabilities.keys())
            ),
            flush=True,
        )
        _register_capabilities(capabilities)
        kernel_tools = _list_kernel_tools()
        _verify(capabilities, kernel_tools)
        print("[reconcile] OK: provider manifests and kernel capability registry are in sync", flush=True)
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[reconcile] ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
