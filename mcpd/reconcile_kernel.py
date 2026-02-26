#!/usr/bin/env python3
"""Reconcile user-space tool manifests with kernel tool registry."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict

ROOT_DIR = Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT_DIR / "mcpd" / "tools.d"
REGISTER_BIN = ROOT_DIR / "client" / "bin" / "genl_register_tool"
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


def _ensure_int(name: str, value: Any, path: Path) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{path}: {name} must be int")
    return value


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _load_manifests() -> Dict[int, Dict[str, Any]]:
    if not TOOLS_DIR.is_dir():
        raise ValueError(f"manifest directory missing: {TOOLS_DIR}")

    registry: Dict[int, Dict[str, Any]] = {}
    for manifest in sorted(TOOLS_DIR.glob("*.json")):
        raw = json.loads(manifest.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"{manifest}: manifest must be object")
        for field in ("tool_id", "name", "perm", "cost"):
            if field not in raw:
                raise ValueError(f"{manifest}: missing field {field}")

        tool_id = _ensure_int("tool_id", raw["tool_id"], manifest)
        name = raw["name"]
        perm = _ensure_int("perm", raw["perm"], manifest)
        cost = _ensure_int("cost", raw["cost"], manifest)
        if not isinstance(name, str) or not name:
            raise ValueError(f"{manifest}: name must be non-empty string")
        if tool_id in registry:
            raise ValueError(f"duplicate tool_id {tool_id} in manifests")

        registry[tool_id] = {
            "tool_id": tool_id,
            "name": name,
            "perm": perm,
            "cost": cost,
            "hash": hashlib.sha256(_canonical_json_bytes(raw)).hexdigest()[:8],
        }

    if not registry:
        raise ValueError(f"no manifests found in {TOOLS_DIR}")
    return registry


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


def _register_manifest_tools(manifests: Dict[int, Dict[str, Any]]) -> None:
    for tool_id in sorted(manifests.keys()):
        tool = manifests[tool_id]
        cmd = [
            str(REGISTER_BIN),
            "--id",
            str(tool["tool_id"]),
            "--name",
            str(tool["name"]),
            "--perm",
            str(tool["perm"]),
            "--cost",
            str(tool["cost"]),
            "--hash",
            str(tool["hash"]),
        ]
        _run_cmd(cmd)
        print(
            f"[reconcile] registered tool id={tool['tool_id']} name={tool['name']} perm={tool['perm']} cost={tool['cost']} hash={tool['hash']}",
            flush=True,
        )


def _list_kernel_tools() -> Dict[int, Dict[str, Any]]:
    proc = _run_cmd([str(LIST_BIN)])
    tools: Dict[int, Dict[str, Any]] = {}
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
            "perm": int(match.group("perm")),
            "cost": int(match.group("cost")),
            "status": match.group("status"),
            "hash": match.group("hash") or "",
        }
    return tools


def _verify_mapping(manifests: Dict[int, Dict[str, Any]], kernel_tools: Dict[int, Dict[str, Any]]) -> None:
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
        if (
            expected["name"] != actual["name"]
            or expected["perm"] != actual["perm"]
            or expected["cost"] != actual["cost"]
            or expected["hash"] != actual["hash"]
        ):
            print(
                "[reconcile] mismatch for id={}: expected name={} perm={} cost={} hash={}, got name={} perm={} cost={} hash={}".format(
                    tool_id,
                    expected["name"],
                    expected["perm"],
                    expected["cost"],
                    expected["hash"],
                    actual["name"],
                    actual["perm"],
                    actual["cost"],
                    actual["hash"],
                ),
                flush=True,
            )
            ok = False

    if not ok:
        raise RuntimeError("manifest <-> kernel registry reconciliation failed")


def main() -> int:
    try:
        _check_prerequisites()
        manifests = _load_manifests()
        print(f"[reconcile] loaded manifests: {sorted(manifests.keys())}", flush=True)
        _register_manifest_tools(manifests)
        kernel_tools = _list_kernel_tools()
        _verify_mapping(manifests, kernel_tools)
        print("[reconcile] OK: manifest and kernel registry are in sync (1:1)", flush=True)
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[reconcile] ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
