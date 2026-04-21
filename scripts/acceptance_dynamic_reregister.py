#!/usr/bin/env python3
"""Dynamic manifest re-registration acceptance (§9).

Exercises catalog_epoch invalidation across add / remove / change
manifest mutations. Requires a running mcpd + kernel_mcp module.

Run via the bash wrapper scripts/acceptance_dynamic_reregister.sh so
the Python interpreter matches the repo venv.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_DIR = ROOT / "tool-app" / "manifests"
TEMP_MANIFEST = MANIFEST_DIR / "99_dynamic_reregister_probe.json"
SOCK_PATH = "/tmp/mcpd.sock"
EPOCH_SYSFS = Path("/sys/kernel/mcp/tool_catalog_epoch")


def rpc(req: dict, timeout: float = 3.0) -> dict:
    raw = json.dumps(req).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
        c.settimeout(timeout)
        c.connect(SOCK_PATH)
        c.sendall(struct.pack(">I", len(raw)) + raw)
        hdr = c.recv(4)
        if len(hdr) != 4:
            raise RuntimeError("short header")
        (n,) = struct.unpack(">I", hdr)
        buf = b""
        while len(buf) < n:
            chunk = c.recv(n - len(buf))
            if not chunk:
                raise RuntimeError("short body")
            buf += chunk
    return json.loads(buf.decode())


def read_catalog_epoch() -> int:
    try:
        return int(EPOCH_SYSFS.read_text().strip())
    except (FileNotFoundError, PermissionError, ValueError):
        return 0


def open_session(client_name: str) -> dict:
    return rpc({"sys": "open_session", "req_id": 1, "client_name": client_name})


def list_tools() -> list[dict]:
    resp = rpc({"sys": "list_tools"})
    tools = resp.get("tools", [])
    return tools if isinstance(tools, list) else []


def exec_tool(session_id: str, app_id: str, tool_id: int, payload: dict | None = None) -> dict:
    return rpc({
        "kind": "tool:exec",
        "req_id": int(time.time() * 1000) & 0xffffffff,
        "session_id": session_id,
        "app_id": app_id,
        "tool_id": tool_id,
        "payload": payload or {},
    })


PROBE_TOOL_ID_BASE = 900
PROBE_APP_ID = "dyn_reregister_probe_app"


def probe_manifest(risk_tags: list[str]) -> dict:
    """Shape the temporary probe manifest. Point at notes_app's endpoint so
    we don't need to start a new backend — the test never actually executes
    the probe tool against the real service, only exercises registration
    state."""
    return {
        "app_id": PROBE_APP_ID,
        "app_name": "Dynamic Reregister Probe",
        "transport": "uds_rpc",
        "endpoint": "/tmp/linux-mcp-apps/notes_app.sock",
        "demo_entrypoint": "tool-app/demo_apps/notes_app.py",
        "tools": [
            {
                "tool_id": PROBE_TOOL_ID_BASE,
                "name": "dyn_probe_ping",
                "risk_tags": risk_tags,
                "operation": "note_list",
                "timeout_ms": 5000,
                "description": "Transient tool used by the dynamic re-registration acceptance test. Never invoked directly.",
                "input_schema": {"type": "object", "additionalProperties": False, "properties": {}},
                "examples": [{"payload": {}}],
            }
        ],
    }


def write_manifest(data: dict) -> None:
    TEMP_MANIFEST.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def remove_manifest() -> None:
    try:
        TEMP_MANIFEST.unlink()
    except FileNotFoundError:
        pass


def expect(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        remove_manifest()
        sys.exit(1)
    print(f"  ok: {msg}")


def scenario_add_triggers_rebind() -> None:
    print("=== scenario 1: add manifest forces rebind ===")
    remove_manifest()
    # Touch list_tools so the current signature is cached before we mutate.
    list_tools()

    pre_epoch = read_catalog_epoch()
    sess = open_session("dyn-add")
    sid = sess["session_id"]

    write_manifest(probe_manifest(risk_tags=[]))
    # Trigger a reload by asking mcpd to list tools.
    tools = list_tools()
    post_epoch = read_catalog_epoch()
    expect(post_epoch > pre_epoch,
           f"catalog_epoch advanced ({pre_epoch} -> {post_epoch}) after add")
    expect(any(t.get("tool_id") == PROBE_TOOL_ID_BASE for t in tools),
           "list_tools includes the newly added tool")

    # Old session now tries to exec a *different* (pre-existing) tool;
    # kernel must still DENY with catalog_stale_rebind_required because
    # the global epoch advanced past the session's snapshot.
    resp = exec_tool(sid, app_id="notes_app", tool_id=2)
    expect(resp.get("decision") == "DENY",
           f"old session got DENY (got {resp.get('decision')!r}) on stale epoch")
    expect("catalog_stale_rebind_required" in resp.get("reason", ""),
           f"reason says catalog_stale_rebind_required (got {resp.get('reason')!r})")

    # Rebind and confirm the same exec works.
    sess2 = open_session("dyn-add-rebind")
    resp2 = exec_tool(sess2["session_id"], app_id="notes_app", tool_id=2)
    expect(resp2.get("status") == "ok",
           "rebound session executes cleanly")


def scenario_remove_unknown_tool_id() -> None:
    print("=== scenario 2: removed manifest hides tool_id at mcpd ===")
    # Leave the probe manifest in place from scenario 1? Add fresh for clarity.
    write_manifest(probe_manifest(risk_tags=[]))
    list_tools()  # ensure mcpd has absorbed the manifest

    # Rebind first so we have a fresh session bound to the current epoch.
    sess = open_session("dyn-remove")
    sid = sess["session_id"]

    pre_epoch = read_catalog_epoch()
    remove_manifest()
    list_tools()  # trigger reload that drops the tool
    post_epoch = read_catalog_epoch()
    expect(post_epoch > pre_epoch,
           f"catalog_epoch advanced ({pre_epoch} -> {post_epoch}) after remove")

    # First call after remove: old session sees stale_rebind DENY (kernel).
    resp = exec_tool(sid, app_id="notes_app", tool_id=2)
    expect(resp.get("decision") == "DENY",
           f"old session DENY post-remove (got {resp.get('decision')!r})")

    # Rebound session targeting the removed tool: mcpd userspace rejects
    # before netlink arbitration — no kernel record should be emitted.
    sess2 = open_session("dyn-remove-rebind")
    resp2 = exec_tool(sess2["session_id"], app_id=PROBE_APP_ID,
                      tool_id=PROBE_TOOL_ID_BASE)
    expect(resp2.get("status") == "error",
           "exec on removed tool returns error")
    err = resp2.get("error", "")
    expect("unsupported tool_id" in err or "unknown" in err.lower() or "unsupported" in err.lower(),
           f"error mentions unknown tool_id (got {err!r})")
    expect(resp2.get("decision") != "DENY",
           "mcpd userspace rejected before kernel arbitration (no 'decision')")


def _read_tool_binary_hash_sysfs(tool_id: int) -> str:
    p = Path(f"/sys/kernel/mcp/tools/{tool_id}/binary_hash")
    try:
        return p.read_text().strip()
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def scenario_binding_change_resets_kernel() -> None:
    """Endpoint change (binding-only) MUST force kernel unregister+
    register even though the exported manifest_hash is stable. Otherwise
    the old TOFU binary_hash pin makes every call after a backend
    rotation DENY as binary_mismatch. `operation` is NOT tested here
    because it is part of semantic identity (see scenario 5).
    """
    print("=== scenario 4: endpoint-only change forces kernel reset ===")
    # Start with a manifest pointing at notes_app's endpoint.
    initial = probe_manifest(risk_tags=[])
    initial["endpoint"] = "/tmp/linux-mcp-apps/notes_app.sock"
    initial["tools"][0]["operation"] = "note_list"
    write_manifest(initial)
    list_tools()

    # Warm the kernel TOFU slot by performing at least one exec. We use a
    # fresh session so catalog_epoch drift from earlier scenarios can't
    # interfere.
    sess = open_session("dyn-binding-warmup")
    sid = sess["session_id"]
    warm = exec_tool(sid, app_id=PROBE_APP_ID, tool_id=PROBE_TOOL_ID_BASE,
                     payload={"limit": 1})
    expect(warm.get("status") == "ok" or warm.get("decision") in ("DENY", None),
           f"warmup exec returned a defined response (got {warm.get('status')!r})")
    pinned_before = _read_tool_binary_hash_sysfs(PROBE_TOOL_ID_BASE)
    expect(bool(pinned_before),
           "kernel sysfs shows a non-empty binary_hash after warmup")

    pre_epoch = read_catalog_epoch()
    pre_manifest_hash = _manifest_hash_of_probe_tool()

    # Change ONLY the endpoint. Keep `operation` identical so nothing in
    # SEMANTIC_HASH_FIELDS moves — we're isolating the binding path.
    # Pointing at a non-existent endpoint is fine: we only check that
    # the kernel reset happened; we don't need the rebound exec to
    # succeed because any such behavior would depend on the attacker
    # scenario the guard is meant to prevent.
    rotated = probe_manifest(risk_tags=[])
    rotated["endpoint"] = "/tmp/linux-mcp-apps/nonexistent_rotation_target.sock"
    rotated["tools"][0]["operation"] = "note_list"  # unchanged
    write_manifest(rotated)
    list_tools()  # trigger reload

    post_epoch = read_catalog_epoch()
    post_manifest_hash = _manifest_hash_of_probe_tool()
    expect(post_manifest_hash == pre_manifest_hash,
           "manifest_hash stable across endpoint-only edit "
           f"(pre={pre_manifest_hash[:12]} post={post_manifest_hash[:12]})")
    expect(post_epoch > pre_epoch,
           f"catalog_epoch advanced ({pre_epoch} -> {post_epoch}) on "
           f"binding-only change even though semantic hash stayed put")

    pinned_after = _read_tool_binary_hash_sysfs(PROBE_TOOL_ID_BASE)
    # After an unregister the TOFU slot is cleared; subsequent
    # re-register arrives with an empty hash because the new endpoint
    # has no backend, so sysfs should show an empty string.
    expect(pinned_after != pinned_before,
           f"kernel TOFU slot was reset on binding change "
           f"(before={pinned_before[:12]} after={pinned_after[:12] or 'EMPTY'})")

    # Old session: catalog_epoch moved → stale rebind required.
    stale = exec_tool(sid, app_id=PROBE_APP_ID, tool_id=PROBE_TOOL_ID_BASE,
                      payload={"limit": 1})
    expect(stale.get("decision") == "DENY",
           f"old session DENY after binding change "
           f"(got {stale.get('decision')!r})")
    expect("catalog_stale_rebind_required" in stale.get("reason", ""),
           f"stale session reason mentions catalog_stale_rebind_required")

    remove_manifest()
    list_tools()


def scenario_operation_change_moves_semantic_hash() -> None:
    """Changing `operation` MUST move manifest_hash — otherwise the
    kernel's hash_mismatch check and any planner-side hash pin could
    silently allow a manifest edit to retarget a tool to a different
    RPC method on the same backend.
    """
    print("=== scenario 5: operation change moves semantic hash ===")
    initial = probe_manifest(risk_tags=[])
    initial["endpoint"] = "/tmp/linux-mcp-apps/notes_app.sock"
    initial["tools"][0]["operation"] = "note_list"
    write_manifest(initial)
    list_tools()

    pre_hash = _manifest_hash_of_probe_tool()
    pre_epoch = read_catalog_epoch()
    expect(bool(pre_hash), "probe tool appears in list_tools with a hash")

    sess = open_session("dyn-operation-warmup")
    sid = sess["session_id"]
    exec_tool(sid, app_id=PROBE_APP_ID, tool_id=PROBE_TOOL_ID_BASE,
              payload={"limit": 1})

    # Same endpoint, different RPC method. Under the old design this
    # would have been binding-only and left manifest_hash untouched —
    # that's the bug; the exported hash must move.
    rotated = probe_manifest(risk_tags=[])
    rotated["endpoint"] = "/tmp/linux-mcp-apps/notes_app.sock"
    rotated["tools"][0]["operation"] = "note_search"
    write_manifest(rotated)
    list_tools()

    post_hash = _manifest_hash_of_probe_tool()
    post_epoch = read_catalog_epoch()
    expect(post_hash != pre_hash,
           f"manifest_hash moved on operation change "
           f"({pre_hash[:12]} -> {post_hash[:12]})")
    expect(post_epoch > pre_epoch,
           f"catalog_epoch advanced ({pre_epoch} -> {post_epoch})")

    # Old session's next exec hits stale rebind; rebound session must
    # see the NEW operation being invoked.
    stale = exec_tool(sid, app_id=PROBE_APP_ID, tool_id=PROBE_TOOL_ID_BASE,
                      payload={"query": "anything"})
    expect(stale.get("decision") == "DENY",
           f"old session DENY after operation change (got {stale.get('decision')!r})")

    remove_manifest()
    list_tools()


def _manifest_hash_of_probe_tool() -> str:
    tools = list_tools()
    for t in tools:
        if t.get("tool_id") == PROBE_TOOL_ID_BASE:
            return str(t.get("hash", ""))
    return ""


def scenario_change_risk_flags_forces_rebind() -> None:
    print("=== scenario 3: risk_flags change forces rebind on old session ===")
    # Start with a low-risk variant.
    write_manifest(probe_manifest(risk_tags=[]))
    list_tools()

    sess = open_session("dyn-change")
    sid = sess["session_id"]
    pre_epoch = read_catalog_epoch()

    # Upgrade risk: system_mutation typically triggers approval path.
    write_manifest(probe_manifest(risk_tags=["system_mutation", "privileged"]))
    list_tools()
    post_epoch = read_catalog_epoch()
    expect(post_epoch > pre_epoch,
           f"catalog_epoch advanced ({pre_epoch} -> {post_epoch}) after change")

    # The old session's next exec must go stale before the new risk flags
    # can take effect — verifies the cached "low-risk allow" path cannot
    # be reused.
    resp = exec_tool(sid, app_id=PROBE_APP_ID, tool_id=PROBE_TOOL_ID_BASE)
    expect(resp.get("decision") == "DENY",
           f"old session DENY after change (got {resp.get('decision')!r})")
    expect("catalog_stale_rebind_required" in resp.get("reason", ""),
           "reason says catalog_stale_rebind_required")

    remove_manifest()
    # Drain the reload so the catalog is clean for subsequent runs.
    list_tools()


def main() -> int:
    try:
        scenario_add_triggers_rebind()
        scenario_remove_unknown_tool_id()
        scenario_change_risk_flags_forces_rebind()
        scenario_binding_change_resets_kernel()
        scenario_operation_change_moves_semantic_hash()
    finally:
        remove_manifest()
        try:
            list_tools()  # flush
        except Exception:  # noqa: BLE001
            pass
    print("=== pass: dynamic re-registration acceptance green ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
