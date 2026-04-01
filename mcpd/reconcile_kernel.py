#!/usr/bin/env python3
"""Reconcile user-space manifests with kernel tool registry."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict

from manifest_loader import DEFAULT_MANIFEST_DIR, ToolManifest, load_all_manifests

ROOT_DIR = Path(__file__).resolve().parent.parent
REGISTER_BIN = ROOT_DIR / "client" / "bin" / "genl_register_tool"
LIST_BIN = ROOT_DIR / "client" / "bin" / "genl_list_tools"

LIST_RE = re.compile(
    r"^id=(?P<id>\d+)\s+name=(?P<name>\S+)\s+risk_flags=(?P<risk_flags>0x[0-9a-fA-F]+)\s+status=(?P<status>\S+)(?:\s+hash=(?P<hash>\S+))?$"
)


def _run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=str(ROOT_DIR), text=True, capture_output=True)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def _load_tool_map() -> Dict[int, ToolManifest]:
    tools: Dict[int, ToolManifest] = {}
    for app in load_all_manifests(DEFAULT_MANIFEST_DIR):
        for tool in app.tools:
            tools[tool.tool_id] = tool
    return tools


def _check_prerequisites() -> None:
    if not REGISTER_BIN.exists() or not LIST_BIN.exists():
        raise RuntimeError("client binaries missing; run: make -C client clean && make -C client")

    lsmod = _run_cmd(["lsmod"])
    loaded = False
    for line in lsmod.stdout.splitlines()[1:]:
        cols = line.split()
        if cols and cols[0] == "kernel_mcp":
            loaded = True
            break
    if not loaded:
        raise RuntimeError("kernel module kernel_mcp not loaded")


def _register_manifest_tools(manifests: Dict[int, ToolManifest]) -> None:
    for tool_id in sorted(manifests.keys()):
        tool = manifests[tool_id]
        cmd = [
            str(REGISTER_BIN),
            "--id",
            str(tool.tool_id),
            "--name",
            str(tool.name),
            "--risk-flags",
            str(tool.risk_flags),
            "--hash",
            str(tool.manifest_hash),
        ]
        _run_cmd(cmd)
        print(
            f"[reconcile] registered tool id={tool.tool_id} name={tool.name} risk_flags=0x{tool.risk_flags:08x} hash={tool.manifest_hash}",
            flush=True,
        )


def _list_kernel_tools() -> Dict[int, Dict[str, object]]:
    proc = _run_cmd([str(LIST_BIN)])
    tools: Dict[int, Dict[str, object]] = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        match = LIST_RE.match(line)
        if not match:
            continue
        tool_id = int(match.group("id"))
        if tool_id in tools:
            raise RuntimeError(f"duplicate tool_id in kernel list output: {tool_id}")
        tools[tool_id] = {
            "tool_id": tool_id,
            "name": match.group("name"),
            "risk_flags": int(match.group("risk_flags"), 16),
            "status": match.group("status"),
            "hash": match.group("hash") or "",
        }
    return tools


def _verify_mapping(manifests: Dict[int, ToolManifest], kernel_tools: Dict[int, Dict[str, object]]) -> None:
    ok = True
    expected_ids = set(manifests.keys())
    actual_ids = set(kernel_tools.keys())

    missing = sorted(expected_ids - actual_ids)
    extra = sorted(actual_ids - expected_ids)
    if missing:
        print(f"[reconcile] missing in kernel registry: {missing}", flush=True)
        ok = False
    if extra:
        print(f"[reconcile] unexpected kernel tools (not in manifest): {extra}", flush=True)
        ok = False

    for tool_id in sorted(expected_ids & actual_ids):
        expected = manifests[tool_id]
        actual = kernel_tools[tool_id]
        mismatches = []
        if actual["name"] != expected.name:
            mismatches.append(f"name expected={expected.name} got={actual['name']}")
        if actual["risk_flags"] != expected.risk_flags:
            mismatches.append(
                f"risk_flags expected=0x{expected.risk_flags:08x} got=0x{actual['risk_flags']:08x}"
            )
        if actual["hash"] != expected.manifest_hash:
            mismatches.append(f"hash expected={expected.manifest_hash} got={actual['hash']}")
        if mismatches:
            ok = False
            print(f"[reconcile] mismatch tool_id={tool_id}: {'; '.join(mismatches)}", flush=True)

    if not ok:
        raise RuntimeError("manifest and kernel registry are out of sync")


def main() -> int:
    _check_prerequisites()
    manifests = _load_tool_map()
    _register_manifest_tools(manifests)
    kernel_tools = _list_kernel_tools()
    _verify_mapping(manifests, kernel_tools)
    print(f"[reconcile] ok: manifest_tools={len(manifests)} kernel_tools={len(kernel_tools)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
