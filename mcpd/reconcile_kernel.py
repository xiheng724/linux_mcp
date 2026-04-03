#!/usr/bin/env python3
"""Reconcile user-space manifests with kernel tool registry."""

from __future__ import annotations

from pathlib import Path
from typing import Dict

from manifest_loader import DEFAULT_MANIFEST_DIR, ToolManifest, load_all_tools
from netlink_client import KernelMcpNetlinkClient

ROOT_DIR = Path(__file__).resolve().parent.parent


def _load_tool_map() -> Dict[int, ToolManifest]:
    return {tool.tool_id: tool for tool in load_all_tools(DEFAULT_MANIFEST_DIR)}


def _check_prerequisites() -> None:
    if not (Path("/sys/kernel/mcp/tools").is_dir() and Path("/sys/kernel/mcp/agents").is_dir()):
        raise RuntimeError("kernel module kernel_mcp not loaded or sysfs ABI mismatch")


def _register_manifest_tools(manifests: Dict[int, ToolManifest]) -> None:
    client = KernelMcpNetlinkClient()
    try:
        client.reset_tools()
        for tool_id in sorted(manifests.keys()):
            tool = manifests[tool_id]
            client.register_tool(
                tool_id=tool.tool_id,
                name=tool.name,
                risk_flags=tool.risk_flags,
                tool_hash=tool.manifest_hash,
            )
            print(
                f"[reconcile] registered tool id={tool.tool_id} name={tool.name} risk_flags=0x{tool.risk_flags:08x} hash={tool.manifest_hash}",
                flush=True,
            )
    finally:
        client.close()


def _list_kernel_tools() -> Dict[int, Dict[str, object]]:
    client = KernelMcpNetlinkClient()
    try:
        items = client.list_tools()
    finally:
        client.close()

    tools: Dict[int, Dict[str, object]] = {}
    for item in items:
        tool_id = int(item["tool_id"])
        if tool_id in tools:
            raise RuntimeError(f"duplicate tool_id in kernel list output: {tool_id}")
        tools[tool_id] = item
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
