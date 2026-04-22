#!/usr/bin/env python3
"""Kernel MCP data-plane daemon over Unix Domain Socket."""

from __future__ import annotations

import enum
import hashlib
import json
import logging
import os
import re
import signal
import socket
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Tuple

try:
    from config import ConfigError, SecurityConfig, load_security_config
    from manifest_loader import DEFAULT_MANIFEST_DIR, AppManifest, ToolManifest, load_all_manifests
    from netlink_client import KernelMcpNetlinkClient
    from public_catalog import list_apps_public, list_tools_public
    from rpc_framing import recv_frame, send_frame
    from schema_utils import ensure_int, ensure_non_empty_str, validate_payload
    from transport import TransportError, dial as transport_dial
    from session_store import (
        AgentBinding,
        PeerIdentity,
        approve_pending_approval,
        deny_pending_approval,
        normalize_session_ttl_ms,
        open_session,
        peek_pending_approval,
        put_pending_approval,
        remember_pending_approval,
        resolve_session,
        session_binding,
        take_pending_approval,
        validate_pending_approval_req,
    )
    from client.kernel_mcp import reasons as reason_taxonomy
except ModuleNotFoundError:  # pragma: no cover - package import fallback
    from .config import ConfigError, SecurityConfig, load_security_config
    from .manifest_loader import DEFAULT_MANIFEST_DIR, AppManifest, ToolManifest, load_all_manifests
    from .netlink_client import KernelMcpNetlinkClient
    from .public_catalog import list_apps_public, list_tools_public
    from .rpc_framing import recv_frame, send_frame
    from .schema_utils import ensure_int, ensure_non_empty_str, validate_payload
    from .transport import TransportError, dial as transport_dial
    from .session_store import (
        AgentBinding,
        PeerIdentity,
        approve_pending_approval,
        deny_pending_approval,
        normalize_session_ttl_ms,
        open_session,
        peek_pending_approval,
        put_pending_approval,
        remember_pending_approval,
        resolve_session,
        session_binding,
        take_pending_approval,
        validate_pending_approval_req,
    )
    from client.kernel_mcp import reasons as reason_taxonomy

SOCK_PATH = "/tmp/mcpd.sock"
MAX_MSG_SIZE = 16 * 1024 * 1024
DEFAULT_APPROVAL_TTL_MS = 5 * 60 * 1000
DEFAULT_SESSION_TTL_MS = 30 * 60 * 1000
APPROVAL_DECISION_MAP = {
    "approve": 1,
    "deny": 2,
    "revoke": 3,
}
LOGGER = logging.getLogger("mcpd")
HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _log_decision_event(
    *,
    source: str,
    req_id: int,
    agent_id: str,
    tool_id: int,
    decision: str,
    reason: str,
    ticket_id: int,
) -> None:
    """Single chokepoint for every tool:exec decision outcome.

    Grepping `event=decision` in mcpd stderr yields the complete stream
    of allow / deny / defer decisions regardless of source:
      source=arb           -> kernel arbitration reply
      source=probe         -> mcpd-side probe failure (never reached kernel)
      source=user_decline  -> sys:approval_reply deny from the session

    The category is looked up through the reason taxonomy; an unknown
    reason emits category=unknown and a one-shot warning so drift becomes
    visible at runtime rather than buried in an experiment-results join.
    """
    category_enum = reason_taxonomy.classify(reason)
    if category_enum is None:
        LOGGER.warning(
            "event=decision_unknown_reason source=%s reason=%s", source, reason,
        )
        category = "unknown"
    else:
        category = category_enum.value
    LOGGER.info(
        "event=decision source=%s req_id=%d agent=%s tool=%d "
        "decision=%s reason=%s category=%s ticket_id=%d",
        source, req_id, agent_id, tool_id,
        decision, reason, category, ticket_id,
    )

_stop_event = threading.Event()
_agents_lock = threading.Lock()
_registry_lock = threading.RLock()
_registered_agents: Dict[str, "AgentBinding"] = {}
_agent_bindings: Dict[str, "AgentBinding"] = {}
_app_registry: Dict[str, AppManifest] = {}
_tool_registry: Dict[int, ToolManifest] = {}
_kernel_client: KernelMcpNetlinkClient | None = None
_manifest_reload_lock = threading.Lock()
_manifest_signature = ""

# Backend binary hash cache.
# Key:  tool_id
# Value: (pid, exe_identity, sha256_hex)
#
# Linux execve(2) keeps the PID, so keying the cache by PID alone would
# let a backend self-reexec (systemd ExecReload, supervisord hot-reload,
# or an attacker-triggered execve) silently reuse the old hash. We bind
# cache validity to an `exe_identity` tuple drawn from /proc/<pid>/exe
# instead — readlink target plus stat's (dev, inode, size, mtime_ns).
# Any of those changing forces a re-hash.
_backend_hash_cache: Dict[int, Tuple[int, Tuple, str]] = {}
_backend_hash_lock = threading.Lock()


def _exe_identity(pid: int) -> Tuple | None:
    """Cheap fingerprint of the executable behind /proc/<pid>/exe.

    Caveats:
      - readlink catches execve to a different path.
      - st_dev + st_ino catch replacement via unlink+create (`cp`).
      - st_size + st_mtime_ns catch in-place rewrites (`open(O_TRUNC)`).

    Returns None when /proc is not readable — callers must treat that as
    "identity unknown" and recompute the digest rather than trust a cache.
    """
    try:
        exe_path = f"/proc/{pid}/exe"
        target = os.readlink(exe_path)
        st = os.stat(exe_path)
    except OSError:
        return None
    return (target, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def _is_interpreter_exe(exe_target: str) -> bool:
    """Heuristic: does /proc/<pid>/exe point at a language runtime rather
    than an application-specific binary? Used to decide whether hashing
    /proc/<pid>/exe alone fingerprints the loaded code or only the
    runtime (see the composite-hash logic below)."""
    base = os.path.basename(exe_target)
    # Strip minor-version suffixes like "python3.11" so python/python3/python3.11 all match.
    for name in _INTERPRETER_BASENAMES:
        if base.startswith(name):
            return True
    return False


def _composite_interpreter_hash(exe_digest: str, script_digest: str) -> str:
    """Combine the interpreter's /proc/<pid>/exe digest with the
    manifest-declared script digest into a single 64-hex string that
    moves when EITHER changes. Kernel only has one TOFU slot, so we
    present one value; operators see a stronger guarantee than "only
    the interpreter is pinned"."""
    return hashlib.sha256(
        (exe_digest + ":" + script_digest).encode("ascii")
    ).hexdigest()


def _fresh_script_digest(script_path: str) -> str:
    """Re-hash the on-disk entry script at probe time.

    The manifest's cached `script_digest` is only recomputed when the
    manifest JSON changes. For interpreter-hosted backends that means a
    script swap between mcpd startups would be trusted until the
    daemon is bounced — the attack the adversarial review flagged.
    Reading the file here at every probe means the composite hash
    tracks the script bytes actually on disk right now; if the kernel
    TOFU pin no longer matches, the next arbitration returns DENY
    binary_mismatch without needing a reload.
    """
    if not script_path:
        return ""
    try:
        h = hashlib.sha256()
        with open(script_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


# Serving identity — what is actually running right now.
#
# linux-mcp draws a hard line between two kinds of tool identity:
#
#   * Logical tool identity (ToolManifest.manifest_hash + kernel tool->hash):
#     "what this tool is semantically". Derived from manifest fields —
#     name, description, input_schema, risk_tags, operation, ... Stable
#     across host moves. See manifest_loader.SEMANTIC_HASH_FIELDS.
#
#   * Serving backend identity (ServingIdentity.composite_digest + kernel
#     tool->binary_hash): "who is running this tool right now". Derived
#     from a live probe of the backend process. Changes every time the
#     actual executable or script on disk changes.
#
# The two identities live on separate axes: a binding-only endpoint move
# resets serving identity without touching logical identity; a schema edit
# changes logical identity without touching the running backend. The
# kernel enforces each independently (hash_mismatch vs binary_mismatch).
@dataclass(frozen=True)
class ServingIdentity:
    """Composite of exe bytes + (optional) entry-script bytes.

    Fields:
      exe_digest       SHA-256 of /proc/<pid>/exe bytes.
      script_digest    SHA-256 of the manifest-declared entry script on
                       disk (empty for native-binary tools).
      composite_digest The value actually stored in the kernel TOFU slot:
                       HASH(exe_digest + ":" + script_digest) when a script
                       is declared, otherwise exe_digest verbatim.
      strategy         "native" | "scripted" | "scripted_degraded" — for
                       logs and the paper table; does not affect the digest
                       sent to the kernel.
    """
    exe_digest: str
    script_digest: str
    composite_digest: str
    strategy: str


def _compute_serving_identity(
    exe_digest: str, tool: ToolManifest
) -> ServingIdentity:
    """Single chokepoint for serving-identity composition.

    Rule (one rule, no special cases):
      * tool.script_path is empty -> strategy="native". Composite is the
        raw exe_digest. This is the case for any tool whose manifest did
        not declare `demo_entrypoint`.
      * tool.script_path is non-empty -> strategy="scripted". Try to
        re-hash the script from disk for freshness; if that fails, fall
        back to the manifest-time script_digest (strategy stays "scripted"
        because the declared script is still locking the composite). If
        BOTH live and manifest-cached digests are empty, degrade to
        "scripted_degraded" and return exe_digest alone — the caller
        should log that the application-code TOFU is not active for this
        tool.

    Interpreter-exe detection (_is_interpreter_exe) is deliberately NOT
    consulted here. The composite strategy is driven by whether the
    manifest declares an entry script, not by guessing from the kernel's
    /proc view. The heuristic remains available as a diagnostic warning
    emitted separately by the caller when a manifest without script_path
    happens to serve from an interpreter binary — see
    _probe_backend_binary_hash.
    """
    if not tool.script_path:
        return ServingIdentity(
            exe_digest=exe_digest,
            script_digest="",
            composite_digest=exe_digest,
            strategy="native",
        )

    script_digest = _fresh_script_digest(tool.script_path)
    if not script_digest:
        # Live re-read failed; fall back to manifest-cached digest so a
        # transient filesystem hiccup does not nuke an otherwise valid
        # pin. The next successful probe will DENY via binary_mismatch if
        # the script actually changed.
        script_digest = tool.script_digest

    if not script_digest:
        # Declared but unreadable both live and at manifest load time.
        # Operator needs to investigate — we return the exe-only digest so
        # the control plane stays usable but the TOFU guarantee is weaker.
        return ServingIdentity(
            exe_digest=exe_digest,
            script_digest="",
            composite_digest=exe_digest,
            strategy="scripted_degraded",
        )

    return ServingIdentity(
        exe_digest=exe_digest,
        script_digest=script_digest,
        composite_digest=_composite_interpreter_hash(exe_digest, script_digest),
        strategy="scripted",
    )

# Loaded on demand so tests and importing tools don't hit the filesystem.
_security_config: SecurityConfig | None = None

CATALOG_EPOCH_SYSFS = Path("/sys/kernel/mcp/tool_catalog_epoch")


def _get_security_config() -> SecurityConfig:
    global _security_config
    if _security_config is None:
        _security_config = load_security_config()
    return _security_config


def _get_kernel_client() -> KernelMcpNetlinkClient:
    if _kernel_client is None:
        raise RuntimeError("kernel netlink client is not initialized")
    return _kernel_client


def _read_catalog_epoch() -> int:
    """Snapshot the kernel's current tool catalog epoch.

    A session opened at epoch E can use any tool whose registered_at_epoch
    is <= E; the kernel denies with catalog_stale_rebind_required as soon
    as a tool is (re)registered or unregistered past that snapshot. We
    read on every open_session so the window is as tight as possible.
    """
    try:
        return int(CATALOG_EPOCH_SYSFS.read_text().strip())
    except (FileNotFoundError, PermissionError, ValueError):
        return 0


def _register_tool_with_kernel(tool: ToolManifest) -> None:
    """Register (or re-register) a tool in the kernel, pinning binary_hash
    as early as backend ready allows.

    Probes the backend with SO_PEERCRED + /proc/<pid>/exe so the kernel's
    TOFU slot is filled before first tool:exec, closing the window where
    an attacker could replace the backend binary between mcpd startup and
    the first call. If the probe returns empty we still register so the
    control plane remains intact, but we do not pin a new kernel hash
    until a later live probe succeeds.
    """
    client = _get_kernel_client()
    pr = _probe_backend_binary_hash(tool)
    # Pin a hash only when the probe is live AND returned a non-empty
    # digest. A cached fallback (live=False) must not be re-pinned — that
    # would re-confirm a stale digest against a backend we couldn't
    # actually observe this round.
    if pr.live and pr.digest:
        LOGGER.info(
            "event=tool_register tool=%d name=%s risk=0x%x binary_hash=%s",
            tool.tool_id, tool.name, tool.risk_flags, pr.digest[:16] + "...",
        )
    else:
        LOGGER.warning(
            "event=tool_register_degraded tool=%d name=%s probe_live=%s "
            "digest_empty=%s transport=%s endpoint=%s",
            tool.tool_id, tool.name, pr.live, not pr.digest,
            tool.transport, tool.endpoint,
        )
    # Only forward a non-empty hash when the probe was live. Forwarding
    # the cached fallback here would quietly refresh the kernel's view
    # of "known good" without any confirmation this round.
    outbound_hash = pr.digest if pr.live else ""
    client.register_tool(
        tool_id=tool.tool_id,
        name=tool.name,
        risk_flags=tool.risk_flags,
        tool_hash=tool.manifest_hash,
        binary_hash=outbound_hash,
    )


def _compute_manifest_signature() -> str:
    digest = hashlib.sha256()
    paths = sorted(DEFAULT_MANIFEST_DIR.glob("*.json"))
    if not paths:
        raise ValueError(f"no manifests found in {DEFAULT_MANIFEST_DIR}")
    for path in paths:
        digest.update(str(path.relative_to(DEFAULT_MANIFEST_DIR)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


class ReconcileAction(str, enum.Enum):
    """Explicit per-tool reconcile decision.

    The diff between the previous and the new manifest registry collapses
    into exactly one of these actions for each tool_id touched. See
    _plan_reconcile for the decision rules and _apply_reconcile_action for
    the kernel calls each rule emits.
    """

    # tool_id present in both and both fingerprints unchanged — no kernel call.
    KEEP = "keep"
    # tool_id new in this reload — register_tool() (bumps epoch, probes TOFU).
    ADD = "add"
    # tool_id disappeared — unregister_tool() (bumps epoch, frees TOFU slot).
    REMOVE = "remove"
    # manifest_hash changed, binding_fingerprint unchanged. In-place
    # register_tool() refreshes name/hash/risk_flags and bumps epoch;
    # kernel_mcp_register_tool preserves the TOFU binary_hash slot because
    # the serving backend is the same process.
    RE_REGISTER_SEMANTIC = "re_register_semantic"
    # binding_fingerprint changed (transport/endpoint); manifest_hash may or
    # may not have changed. The backend may now be a different process with
    # a different binary, so we must unregister_tool() first to clear the
    # TOFU slot, drop mcpd's hash cache, and then register_tool() so the
    # next live probe can pin a fresh binary_hash. Two epoch bumps (one per
    # kernel op) — harmless, surviving sessions just see the later one.
    RE_REGISTER_BINDING_MOVE = "re_register_binding_move"


def _plan_reconcile(
    prev: Dict[int, ToolManifest],
    new: Dict[int, ToolManifest],
) -> Dict[int, ReconcileAction]:
    """Pure function: compute a per-tool action table from two registries.

    Rules (applied in priority order per tool_id):
      - id in new only                 -> ADD
      - id in prev only                -> REMOVE
      - id in both:
          binding_fingerprint changed  -> RE_REGISTER_BINDING_MOVE
                                          (covers simultaneous semantic
                                          change — binding move is strictly
                                          more disruptive and handles both)
          manifest_hash changed        -> RE_REGISTER_SEMANTIC
          otherwise                    -> KEEP
    """
    plan: Dict[int, ReconcileAction] = {}
    prev_ids = set(prev.keys())
    new_ids = set(new.keys())

    for tid in new_ids - prev_ids:
        plan[tid] = ReconcileAction.ADD
    for tid in prev_ids - new_ids:
        plan[tid] = ReconcileAction.REMOVE
    for tid in prev_ids & new_ids:
        p, n = prev[tid], new[tid]
        if p.binding_fingerprint != n.binding_fingerprint:
            plan[tid] = ReconcileAction.RE_REGISTER_BINDING_MOVE
        elif p.manifest_hash != n.manifest_hash:
            plan[tid] = ReconcileAction.RE_REGISTER_SEMANTIC
        else:
            plan[tid] = ReconcileAction.KEEP
    return plan


def _apply_reconcile_action(
    client: KernelMcpNetlinkClient,
    tool_id: int,
    action: ReconcileAction,
    new_tool: ToolManifest | None,
) -> None:
    """Single dispatch point for reconcile actions. Every reconcile-driven
    mutation of the kernel registry must go through this function so logs
    and error handling stay uniform. `new_tool` is the post-reload manifest
    (None for REMOVE).
    """
    if action is ReconcileAction.KEEP:
        return

    if action is ReconcileAction.REMOVE:
        try:
            client.unregister_tool(tool_id)
        except RuntimeError as exc:
            LOGGER.error(
                "event=reconcile_step_failed tool=%d action=%s step=kernel_unregister err=%s",
                tool_id, action.value, exc,
            )
            raise RuntimeError(
                f"reconcile {action.value} failed for tool {tool_id}: "
                f"kernel unregister did not complete"
            ) from exc
        _backend_hash_cache.pop(tool_id, None)
        LOGGER.info("event=reconcile tool=%d action=%s", tool_id, action.value)
        return

    assert new_tool is not None, "ADD/RE_REGISTER_* require new_tool"

    if action is ReconcileAction.RE_REGISTER_BINDING_MOVE:
        # Clear the kernel's TOFU slot first. Without this, register_tool
        # would leave the old binary_hash in place and every tool:exec
        # would DENY with binary_mismatch once the new backend is probed.
        try:
            client.unregister_tool(tool_id)
        except RuntimeError as exc:
            LOGGER.error(
                "event=reconcile_step_failed tool=%d action=%s step=kernel_unregister err=%s",
                tool_id, action.value, exc,
            )
            raise RuntimeError(
                f"reconcile {action.value} failed for tool {tool_id}: "
                f"kernel unregister did not complete"
            ) from exc
        _backend_hash_cache.pop(tool_id, None)

    _register_tool_with_kernel(new_tool)
    LOGGER.info("event=reconcile tool=%d action=%s", tool_id, action.value)


def _load_runtime_registry(*, force_reset: bool = False) -> str:
    """Reconcile local manifest state with the kernel tool registry.

    Two fingerprints drive the diff, tracked separately on purpose:

      - manifest_hash  : semantic identity (name, description, schema,
                         risk_tags, operation, ...). Changing it means the
                         tool looks like a different tool to llm-app.
      - binding_fingerprint : runtime routing (transport, endpoint).
                         Changing this means the backend may be a different
                         process with a different executable.

    The two fingerprints drive distinct ReconcileAction values per tool
    (KEEP / ADD / REMOVE / RE_REGISTER_SEMANTIC / RE_REGISTER_BINDING_MOVE);
    see ReconcileAction and _plan_reconcile for the full decision table and
    kernel-side consequences.

    Control-plane invariants this function relies on:
      I1 TOFU `binary_hash` is NOT catalog state; filling the slot does not
         bump catalog_epoch. Only {name, hash, risk_flags} mutations do.
      I2 kernel reset_tools() (destroy_all) does NOT bump catalog_epoch;
         the subsequent per-tool register calls do. Cold-start relies on
         this: surviving agents still see a strictly-later tool epoch.
      I3 unregister_tool() DOES bump catalog_epoch; a single removal is
         sufficient to force any session holding that tool's old epoch to
         rebind before its next call.
      I4 catalog_stale detection is per-tool (request_catalog_epoch <
         tool_registered_epoch). An unrelated tool change does NOT force
         unrelated sessions to rebind.
      I5 mcpd userspace state (_sessions, _pending_approvals) is NOT
         persisted; it is lost on restart. Kernel state (tools, agents,
         approval tickets) survives as long as the module stays loaded —
         any stranded approval tickets expire via the kernel's cleanup
         timer.

    force_reset=True selects the cold-start path: reset_tools() wipes the
    kernel table, then every manifest tool is re-registered from scratch.
    Used exactly once at daemon boot, where trusting whatever survived in
    the kernel from a prior mcpd run is not worth the debugging risk.
    """
    apps = load_all_manifests()
    app_registry: Dict[str, AppManifest] = {}
    tool_registry: Dict[int, ToolManifest] = {}
    for app in apps:
        app_registry[app.app_id] = app
        for tool in app.tools:
            tool_registry[tool.tool_id] = tool

    client = _get_kernel_client()

    if force_reset:
        # Cold-start path. Treat every manifest tool as ADD after wipe.
        client.reset_tools()
        for tool in tool_registry.values():
            _register_tool_with_kernel(tool)
        LOGGER.info(
            "event=reconcile_summary mode=cold_start tools=%d",
            len(tool_registry),
        )
    else:
        # Live-reload path. Compute decision table against the in-memory
        # snapshot of what mcpd last pushed to the kernel.
        with _registry_lock:
            prev_snapshot: Dict[int, ToolManifest] = dict(_tool_registry)

        plan = _plan_reconcile(prev_snapshot, tool_registry)

        # Apply REMOVE before RE_REGISTER_BINDING_MOVE before RE_REGISTER_SEMANTIC
        # before ADD — the ordering is not semantically required today (each
        # tool_id is in the plan at most once and kernel ops are independent)
        # but keeps the log deterministic and matches how a reviewer would
        # read the decision table top-to-bottom.
        order = (
            ReconcileAction.REMOVE,
            ReconcileAction.RE_REGISTER_BINDING_MOVE,
            ReconcileAction.RE_REGISTER_SEMANTIC,
            ReconcileAction.ADD,
        )
        counts: Dict[ReconcileAction, int] = {a: 0 for a in ReconcileAction}
        for action in order:
            for tool_id, act in plan.items():
                if act is not action:
                    continue
                _apply_reconcile_action(
                    client, tool_id, action,
                    tool_registry.get(tool_id),
                )
                counts[action] += 1
        # KEEP is not in `order`; count it separately for the summary.
        counts[ReconcileAction.KEEP] = sum(
            1 for a in plan.values() if a is ReconcileAction.KEEP
        )

        mutated = any(counts[a] for a in ReconcileAction if a is not ReconcileAction.KEEP)
        if mutated:
            LOGGER.info(
                "event=reconcile_summary mode=live_reload add=%d remove=%d "
                "re_register_semantic=%d re_register_binding_move=%d keep=%d",
                counts[ReconcileAction.ADD],
                counts[ReconcileAction.REMOVE],
                counts[ReconcileAction.RE_REGISTER_SEMANTIC],
                counts[ReconcileAction.RE_REGISTER_BINDING_MOVE],
                counts[ReconcileAction.KEEP],
            )

    with _registry_lock:
        _app_registry.clear()
        _app_registry.update(app_registry)
        _tool_registry.clear()
        _tool_registry.update(tool_registry)

    LOGGER.info(
        "event=catalog_loaded apps=%d tools=%d app_ids=%s",
        len(app_registry),
        len(tool_registry),
        sorted(app_registry.keys()),
    )
    return _compute_manifest_signature()


def _ensure_runtime_registry_current(*, force: bool = False) -> None:
    """Drive the control-plane reconcile state machine.

    Two modes, explicit at the call site via `force`:

      force=True  -> COLD_START. Used exactly once at daemon boot. Discards
                     whatever survived in the kernel registry from a prior
                     mcpd run and re-registers every manifest tool from
                     scratch. Userspace-side state (_sessions,
                     _pending_approvals) is already empty at this point
                     because the process just started; there is nothing to
                     invalidate in userspace. Any kernel-side approval
                     tickets or agent records that outlived the old mcpd
                     are left to expire naturally — they will not match
                     freshly-issued ticket_ids or binding_hashes.

      force=False -> LIVE_RELOAD. The normal path, hit on session open and
                     catalog listing. Cheap in the common case: if the
                     on-disk manifest bundle's signature is unchanged we
                     return immediately. Otherwise _load_runtime_registry
                     computes the per-tool ReconcileAction table and
                     applies only the minimum kernel ops.
    """
    global _manifest_signature

    with _manifest_reload_lock:
        current_signature = _compute_manifest_signature()
        if not force and current_signature == _manifest_signature:
            return
        loaded_signature = _load_runtime_registry(force_reset=force)
        _manifest_signature = loaded_signature
        LOGGER.info("event=catalog_refreshed signature=%s", loaded_signature[:12])


def _read_peer_identity(conn: socket.socket) -> PeerIdentity:
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("SO_PEERCRED not available on this platform")
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return PeerIdentity(pid=pid, uid=uid, gid=gid)


def _bind_agent_identity(agent_id: str, binding: AgentBinding) -> None:
    with _agents_lock:
        bound = _agent_bindings.get(agent_id)
        if bound is not None and bound != binding:
            raise ValueError("agent_id is bound to a different peer identity")
        _agent_bindings[agent_id] = binding


def _ensure_agent_registered(agent_id: str, binding: AgentBinding) -> None:
    _bind_agent_identity(agent_id, binding)
    with _agents_lock:
        registered_peer = _registered_agents.get(agent_id)
        if registered_peer is not None:
            if registered_peer != binding:
                raise ValueError("agent_id is registered to a different peer identity")
            return

    client = _get_kernel_client()
    try:
        client.register_agent(
            agent_id,
            pid=binding.peer.pid,
            uid=binding.peer.uid,
            binding_hash=binding.binding_hash,
            binding_epoch=binding.binding_epoch,
            catalog_epoch=binding.catalog_epoch,
        )
    except RuntimeError as exc:
        if "Invalid argument" in str(exc):
            raise RuntimeError(
                "kernel agent ABI mismatch: rebuild and reload kernel_mcp from this repo"
            ) from exc
        raise
    LOGGER.info(
        "event=agent_register agent=%s pid=%d uid=%d binding_hash=%016x epoch=%d catalog_epoch=%d",
        agent_id,
        binding.peer.pid,
        binding.peer.uid,
        binding.binding_hash,
        binding.binding_epoch,
        binding.catalog_epoch,
    )

    with _agents_lock:
        _registered_agents[agent_id] = binding


def _kernel_arbitrate(
    req_id: int,
    agent_id: str,
    binding_hash: int,
    binding_epoch: int,
    tool_id: int,
    tool_hash: str,
    ticket_id: int = 0,
    payload_hash: bytes = b"",
    binary_hash: str = "",
    catalog_epoch: int = 0,
) -> Tuple[str, str, int]:
    client = _get_kernel_client()
    try:
        decision_reply = client.tool_request(
            req_id=req_id,
            agent_id=agent_id,
            binding_hash=binding_hash,
            binding_epoch=binding_epoch,
            tool_id=tool_id,
            tool_hash=tool_hash,
            ticket_id=ticket_id,
            payload_hash=payload_hash,
            binary_hash=binary_hash,
            catalog_epoch=catalog_epoch,
        )
    except RuntimeError as exc:
        if "Invalid argument" in str(exc):
            raise RuntimeError(
                "kernel request ABI mismatch: rebuild and reload kernel_mcp from this repo"
            ) from exc
        raise
    _log_decision_event(
        source="arb",
        req_id=req_id,
        agent_id=agent_id,
        tool_id=tool_id,
        decision=decision_reply.decision,
        reason=decision_reply.reason,
        ticket_id=decision_reply.ticket_id,
    )
    return (
        decision_reply.decision,
        decision_reply.reason,
        decision_reply.ticket_id,
    )


# Fine-grained outcome codes persisted to call_record.tool_status_code.
# Mirror of KERNEL_MCP_TSC_* in kernel_mcp_schema.h; keep in sync or
# `make schema-verify` will catch drift.
TSC_UNSPECIFIED = 0
TSC_OK = 1
TSC_TOOL_ERROR = 2
TSC_FORWARD_FAIL = 3
TSC_PROBE_FAILED = 4
TSC_KERNEL_DENY = 5
TSC_KERNEL_DEFER = 6


def _kernel_report_complete(
    agent_id: str,
    tool_id: int,
    req_id: int,
    status_code: int,
    exec_ms: int,
    payload_hash: bytes = b"",
    response_hash: bytes = b"",
    err_head: bytes = b"",
    tool_status_code: int = TSC_UNSPECIFIED,
) -> None:
    client = _get_kernel_client()
    client.tool_complete(
        req_id=req_id,
        agent_id=agent_id,
        tool_id=tool_id,
        status_code=status_code,
        exec_ms=exec_ms,
        payload_hash=payload_hash,
        response_hash=response_hash,
        err_head=err_head,
        tool_status_code=tool_status_code,
    )


def _canonical_payload_bytes(payload: Any) -> bytes:
    """Serialize payload the same way manifest hashing does so the audit
    prefix is stable across mcpd restarts and matches any offline replay."""
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError):
        return repr(payload).encode("utf-8", errors="replace")


def _summary_hash_prefix(blob: bytes) -> bytes:
    return hashlib.sha256(blob).digest()[:8] if blob else b""


_SO_PEERCRED_STRUCT = struct.Struct("iii")  # pid, uid, gid

# Basenames of executables we treat as interpreters rather than
# application binaries. When /proc/<pid>/exe points at one of these,
# hashing /proc/<pid>/exe alone would pin the *runtime* rather than
# the loaded application code, which is the bug the adversarial
# review flagged. We composite with the manifest-declared script
# digest instead. Matched by prefix so "python3.11" and "python3" are
# both caught.
_INTERPRETER_BASENAMES = ("python", "ruby", "node", "bash", "sh")


class ProbeResult:
    """Outcome of `_probe_backend_binary_hash`.

    `live` is the critical bit: True means this invocation actually
    confirmed the currently-serving binary's identity (either by
    hashing /proc/<pid>/exe fresh, or by validating that the cached
    digest's exe_identity still matches what /proc reports right now).
    False means we could not confirm and are falling back to the last
    known-good digest — the exec path must refuse to forward in that
    case because the backend may have been swapped during the blind
    window.

    When `hold=True` was passed to the probe and the result is live,
    `conn` is the open socket to the verified backend. Callers MUST
    close it (either by sending the real RPC through it or explicitly
    calling .close()); the exec path reuses this connection to prove
    the payload went to the same process we just probed, closing the
    TOCTOU window that a second dial would open.
    """
    __slots__ = ("digest", "live", "conn", "pid", "identity")

    def __init__(
        self,
        *,
        digest: str,
        live: bool,
        conn: socket.socket | None = None,
        pid: int = 0,
        identity: Tuple | None = None,
    ) -> None:
        self.digest = digest
        self.live = live
        self.conn = conn
        self.pid = pid
        self.identity = identity


def _check_peer_uid(peer_uid: int, tool_id: int, context: str) -> bool:
    """True iff SO_PEERCRED peer uid is in allowed_backend_uids.

    Applied to both the probe dial and the tool:exec dial so an
    attacker who races to bind the same abstract/path UDS under a
    different uid cannot impersonate a tool backend. For the default
    config (only mcpd's own euid is trusted) this closes the
    cross-user impersonation window the adversarial review flagged
    for abstract sockets; it also hardens the path-UDS case where
    /tmp/linux-mcp-apps/ is on a world-writable tmpfs.
    """
    sec = _get_security_config()
    allowed = sec.allowed_backend_uids or ()
    if peer_uid in allowed:
        return True
    LOGGER.warning(
        "peer uid check failed context=%s tool=%d peer_uid=%d allowed=%s",
        context, tool_id, peer_uid, sorted(allowed),
    )
    return False


def _read_peercred(conn: socket.socket) -> Tuple[int, int] | None:
    """Return (pid, uid) from SO_PEERCRED on an AF_UNIX connection, or
    None if the option cannot be read."""
    try:
        raw = conn.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            _SO_PEERCRED_STRUCT.size,
        )
        pid, uid, _gid = _SO_PEERCRED_STRUCT.unpack(raw)
        return (pid, uid)
    except (OSError, struct.error):
        return None


def _probe_backend_binary_hash(
    tool: ToolManifest, *, hold: bool = False
) -> ProbeResult:
    """Probe the backend behind `tool.endpoint` and return its binary hash
    plus a `live` bit indicating whether this call actually confirmed
    the currently-serving binary.

    When `hold=True`, a successful live probe returns a ProbeResult
    whose `.conn` is the still-open verified socket. The caller owns
    this socket and MUST close it (e.g. by handing it to
    `_call_tool_service`, which will consume it). Reusing the probed
    connection is the point: it eliminates the TOCTOU window between
    "probe saw process A" and "exec dial got process B that grabbed
    the same UDS name after A exited", which otherwise lets a
    same-uid substitute receive the payload that the kernel approved
    for A.

    On `hold=False`, the connection is always closed before return —
    used by the registration path that only wants to learn a hash.

    Contract for callers:
      - live=True, digest=<sha256>: current binary identity confirmed;
        safe to forward a tool:exec. With hold=True the caller must
        close result.conn.
      - live=True, digest="": confirmed, but hashing is not possible on
        this transport (non-AF_UNIX) — treated like "no new pin".
      - live=False, digest=<cached>: live probe failed; the exec path
        must refuse because the backend could have swapped during the
        blind window. conn is always None here even with hold=True.
      - live=False, digest="": no cached fallback available either.

    For interpreter-backed backends (python, ruby, node, ...), we
    substitute `composite_hash(interpreter_digest, script_digest)` for
    the raw /proc/<pid>/exe hash, so a swap of the application script
    on disk will invalidate the kernel's TOFU pin on the next restart.
    Without the script_digest (non-.py entry or missing file) we fall
    back to interpreter-only hashing and log a warning that TOFU is
    degraded for that tool.
    """
    with _backend_hash_lock:
        cached = _backend_hash_cache.get(tool.tool_id)
    fallback_digest = cached[2] if cached else ""

    # Helper to consistently return a failure while ensuring the
    # held socket is closed (callers must not have to worry about it).
    def _fail(conn: socket.socket | None) -> ProbeResult:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
        return ProbeResult(digest=fallback_digest, live=False)

    try:
        probe = transport_dial(tool.transport, tool.endpoint, 2.0)
    except (OSError, socket.timeout, TransportError, NotImplementedError) as exc:
        LOGGER.warning(
            "backend probe dial failed tool=%d transport=%s endpoint=%s err=%s",
            tool.tool_id, tool.transport, tool.endpoint, exc,
        )
        return _fail(None)

    if probe.family != socket.AF_UNIX:
        # SO_PEERCRED is AF_UNIX-only. vsock attestation is future
        # work; for now there's no way to confirm identity so we can't
        # claim live.
        return _fail(probe)

    peer = _read_peercred(probe)
    if peer is None:
        LOGGER.warning(
            "backend SO_PEERCRED failed tool=%d endpoint=%s",
            tool.tool_id, tool.endpoint,
        )
        return _fail(probe)
    backend_pid, backend_uid = peer
    if not _check_peer_uid(backend_uid, tool.tool_id, context="probe"):
        return _fail(probe)

    # Fast path: cache hit whose pinned identity still matches what
    # /proc reports *now*. This is the bulk of hot-path calls.
    current_identity = _exe_identity(backend_pid)
    if (
        cached is not None
        and cached[0] == backend_pid
        and current_identity is not None
        and cached[1] == current_identity
    ):
        if not hold:
            probe.close()
        return ProbeResult(
            digest=cached[2], live=True,
            conn=probe if hold else None,
            pid=backend_pid, identity=current_identity,
        )
    if (
        cached is not None
        and cached[0] == backend_pid
        and current_identity is not None
        and cached[1] != current_identity
    ):
        LOGGER.warning(
            "exe identity drift tool=%d pid=%d "
            "(execve or in-place binary replacement); re-hashing",
            tool.tool_id, backend_pid,
        )

    # Re-hash with race detection. Identity captured BEFORE the read is
    # the key we cache under (so the cached digest really is the hash
    # of the bytes identified by that tuple). If the post-read identity
    # disagrees, the backend execved or had its file replaced during
    # the read — retry once, otherwise give up and don't cache.
    for attempt in range(2):
        id_before = _exe_identity(backend_pid)
        if id_before is None:
            LOGGER.warning(
                "backend exe identity unreadable tool=%d pid=%d",
                tool.tool_id, backend_pid,
            )
            return _fail(probe)
        try:
            hasher = hashlib.sha256()
            with open(f"/proc/{backend_pid}/exe", "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    hasher.update(chunk)
            exe_digest = hasher.hexdigest()
        except OSError as exc:
            LOGGER.warning(
                "backend exe read failed tool=%d pid=%d err=%s",
                tool.tool_id, backend_pid, exc,
            )
            return _fail(probe)
        id_after = _exe_identity(backend_pid)
        if id_after is None:
            return _fail(probe)
        if id_before != id_after:
            LOGGER.warning(
                "exe identity raced during hash tool=%d pid=%d attempt=%d; retrying",
                tool.tool_id, backend_pid, attempt,
            )
            continue

        # Route through the single serving-identity chokepoint. The
        # composite strategy is driven by manifest declaration (is this a
        # scripted tool?), not by introspecting /proc. _is_interpreter_exe
        # is still consulted, but only as a diagnostic: if the backend
        # looks interpreter-hosted yet the manifest did not declare a
        # script, the operator has a supply-chain gap — the TOFU slot
        # pins the interpreter bytes but not the loaded application code.
        serving = _compute_serving_identity(exe_digest, tool)
        exe_target = id_before[0]
        if not tool.script_path and _is_interpreter_exe(exe_target):
            LOGGER.warning(
                "tool=%d name=%s backend exe=%s looks interpreter-hosted "
                "but manifest has no demo_entrypoint; serving_identity "
                "strategy=native covers interpreter bytes only, application "
                "code is NOT TOFU-protected",
                tool.tool_id, tool.name, exe_target,
            )
        elif serving.strategy == "scripted_degraded":
            LOGGER.warning(
                "tool=%d name=%s script_path=%s unreadable both live and "
                "at manifest load; serving_identity degraded to exe-only pin",
                tool.tool_id, tool.name, tool.script_path,
            )

        with _backend_hash_lock:
            _backend_hash_cache[tool.tool_id] = (
                backend_pid, id_before, serving.composite_digest,
            )
        if not hold:
            probe.close()
        return ProbeResult(
            digest=serving.composite_digest, live=True,
            conn=probe if hold else None,
            pid=backend_pid, identity=id_before,
        )

    LOGGER.warning(
        "unable to capture stable binary_hash tool=%d pid=%d; not caching",
        tool.tool_id, backend_pid,
    )
    return _fail(probe)


def _call_tool_service(
    tool: ToolManifest,
    req_id: int,
    agent_id: str,
    payload: Any,
    *,
    conn: socket.socket | None = None,
    probed_pid: int = 0,
    probed_identity: Tuple | None = None,
) -> Dict[str, Any]:
    """Send a tool:exec RPC and return the backend's response.

    If `conn` is provided it is the already-verified socket the probe
    used to compute the binary_hash. We reuse it for the real RPC so
    the kernel's approval and the actual payload destination are
    provably the same process — no TOCTOU between probe dial and exec
    dial. The caller passes `probed_pid` / `probed_identity` only for
    sanity checks in that path.

    When `conn` is None we fall back to a fresh dial (used by the
    synchronous test smoke and the legacy registration-sync path);
    that dial does its own peer UID check but cannot prove process
    identity continuity with an earlier probe.
    """
    req = {
        "req_id": req_id,
        "agent_id": agent_id,
        "tool_id": tool.tool_id,
        "operation": tool.operation,
        "payload": payload,
    }
    encoded = json.dumps(req, ensure_ascii=True).encode("utf-8")
    timeout_s = max(tool.timeout_ms / 1000.0, 1.0)

    if conn is None:
        try:
            conn = transport_dial(tool.transport, tool.endpoint, timeout_s)
        except (FileNotFoundError, ConnectionRefusedError, TimeoutError, OSError) as exc:
            raise ValueError(f"tool service offline: {tool.endpoint}") from exc
        except TransportError as exc:
            raise ValueError(f"tool transport error: {exc}") from exc
        except NotImplementedError as exc:
            raise ValueError(f"tool transport not implemented: {exc}") from exc
        reused = False
    else:
        reused = True
    try:
        with conn:
            conn.settimeout(timeout_s)
            if not reused and conn.family == socket.AF_UNIX:
                # Fresh dial: cannot prove continuity with any prior
                # probe. Fall back to the peer UID allowlist; the exec
                # path would have DENY'd upstream if the live probe
                # failed, so reaching here means we at least saw an OK
                # probe this round.
                peer = _read_peercred(conn)
                if peer is None:
                    raise ValueError(
                        f"tool service peer identity unreadable: {tool.endpoint}"
                    )
                _peer_pid, peer_uid = peer
                if not _check_peer_uid(peer_uid, tool.tool_id, context="exec"):
                    raise ValueError(
                        f"tool service peer uid={peer_uid} not in "
                        f"allowed_backend_uids (tool={tool.tool_id})"
                    )
            elif reused and conn.family == socket.AF_UNIX:
                # Reused probe socket: pid/identity were already
                # verified by the probe. Re-check both peer credentials
                # AND /proc/<pid>/exe identity before sending the
                # payload. execve() preserves PID and keeps already-
                # accepted connections open unless the backend marks
                # them CLOEXEC, so a same-PID check alone lets a
                # backend accept the probe, re-exec into different
                # code, and still receive the approved payload on the
                # already-held socket. Comparing the pre-exec identity
                # tuple against the one /proc reports now closes that
                # window.
                peer = _read_peercred(conn)
                if peer is None:
                    raise ValueError(
                        f"tool service peer identity unreadable on reused probe socket: {tool.endpoint}"
                    )
                now_pid, _now_uid = peer
                if probed_pid and now_pid and now_pid != probed_pid:
                    raise ValueError(
                        f"probed pid={probed_pid} but exec socket reports "
                        f"pid={now_pid} (tool={tool.tool_id}) — backend swapped"
                    )
                if probed_identity is not None:
                    now_identity = _exe_identity(now_pid or probed_pid)
                    if now_identity is None:
                        raise ValueError(
                            f"exe identity unreadable on reused probe socket: {tool.endpoint}"
                        )
                    if now_identity != probed_identity:
                        raise ValueError(
                            f"probe/exec identity drift on reused socket "
                            f"(tool={tool.tool_id} pid={now_pid}) — backend re-execed "
                            f"after probe approval"
                        )
            send_frame(conn, encoded, max_msg_size=MAX_MSG_SIZE)
            raw = recv_frame(conn, max_msg_size=MAX_MSG_SIZE)
    except (FileNotFoundError, ConnectionRefusedError, TimeoutError, OSError) as exc:
        raise ValueError(f"tool service offline: {tool.endpoint}") from exc

    try:
        resp = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"tool service returned invalid JSON ({tool.name})") from exc
    if not isinstance(resp, dict):
        raise ValueError(f"tool service returned non-object response ({tool.name})")
    status = resp.get("status", "")
    if status not in ("ok", "error"):
        raise ValueError(f"tool service returned invalid status ({tool.name})")
    return resp


def _list_apps_public() -> List[Dict[str, Any]]:
    with _registry_lock:
        return list_apps_public(list(_app_registry.values()))


def _list_tools_public(app_id: str = "") -> List[Dict[str, Any]]:
    with _registry_lock:
        if app_id:
            app = _app_registry.get(app_id)
            if app is None:
                raise ValueError(f"unknown app_id: {app_id}")
            tools = app.tools
        else:
            tools = _tool_registry.values()
    return list_tools_public(list(tools))


def _approval_decide(
    ticket_id: int,
    decision: str,
    agent_id: str,
    approver: str,
    reason: str,
    ttl_ms: int,
    *,
    binding_hash: int = 0,
    binding_epoch: int = 0,
) -> None:
    normalized = decision.strip().lower()
    decision_code = APPROVAL_DECISION_MAP.get(normalized)
    if decision_code is None:
        raise ValueError("decision must be one of: approve, deny, revoke")
    if ttl_ms <= 0:
        raise ValueError("ttl_ms must be positive")
    client = _get_kernel_client()
    client.approval_decide(
        ticket_id=ticket_id,
        agent_id=agent_id,
        decision=decision_code,
        binding_hash=binding_hash,
        binding_epoch=binding_epoch,
        approver=approver,
        reason=reason,
        ttl_ms=ttl_ms,
    )


def _build_rejection_response(
    *,
    req_id: int,
    decision: str,
    reason: str,
    error_message: str,
    ticket_id: int,
) -> Dict[str, Any]:
    """Single source for the DENY/DEFER response envelope.

    All rejection paths (probe-failed, kernel arbitration denied, kernel
    arbitration deferred) return the same field set; only `decision`,
    `reason`, `error_message`, and `ticket_id` vary. Keeping one builder
    makes it impossible for the three paths to drift apart.
    """
    return {
        "req_id": req_id,
        "status": "error",
        "result": {},
        "error": error_message,
        "t_ms": 0,
        "decision": decision,
        "reason": reason,
        "ticket_id": ticket_id,
    }


def _discard_probe_conn(probe_result: "ProbeResult") -> None:
    """Idempotent best-effort close of a held probe socket.

    The tool_exec path keeps the probe's verified socket open across
    kernel arbitration so it can reuse the same connection for the real
    RPC. On DENY or DEFER we never run that RPC, so the socket must be
    closed. The close may legitimately fail (already closed, peer gone);
    we swallow those — this function is audit/cleanup, not load-bearing.
    """
    if probe_result.conn is None:
        return
    try:
        probe_result.conn.close()
    except Exception:  # noqa: BLE001
        pass


def _record_probe_failed_audit(
    *,
    req_id: int,
    agent_id: str,
    tool_id: int,
    binding: AgentBinding,
    payload_hash: bytes,
) -> None:
    """Push a probe_failed entry into the kernel's per-agent call_log so
    the denial survives an mcpd crash and shows up in sysfs.

    Must register the agent first so cmd_tool_complete can resolve it.
    Failure to write the audit is logged but does not propagate — we
    still want to return the DENY to the caller.
    """
    try:
        _ensure_agent_registered(agent_id, binding)
        _kernel_report_complete(
            agent_id=agent_id,
            tool_id=tool_id,
            req_id=req_id,
            status_code=1,
            exec_ms=0,
            payload_hash=payload_hash,
            err_head=reason_taxonomy.PROBE_FAILED.name.encode("ascii"),
            tool_status_code=TSC_PROBE_FAILED,
        )
    except Exception as audit_exc:  # noqa: BLE001
        LOGGER.error(
            "event=audit_failed kind=probe_failed req_id=%d agent=%s tool=%d err=%s",
            req_id, agent_id, tool_id, audit_exc,
        )


def _resolve_tool_hash(req: Dict[str, Any], tool: ToolManifest) -> str:
    raw = req.get("tool_hash", "")
    if raw in (None, ""):
        return tool.manifest_hash
    if not isinstance(raw, str) or not HASH_RE.fullmatch(raw):
        raise ValueError("tool_hash must be 64 hex chars")
    return raw.lower()


def _dispatch_tool_call(
    *,
    tool: ToolManifest,
    req_id: int,
    agent_id: str,
    payload: Any,
    probe_result: "ProbeResult",
    decision: str,
    reason: str,
    ticket_id: int,
    payload_hash: bytes,
) -> Dict[str, Any]:
    """Forward the approved request to the backend and report completion.

    Stage 6 of _handle_tool_exec. Owns three things:
      1. Call _call_tool_service over the held probe socket (same-PID
         guarantee) and classify the outcome (ok / tool_error / mcpd
         forwarding failure).
      2. Build the success/tool-error response envelope.
      3. Always push a tool_complete record to the kernel call_log in
         finally{}, whether the call succeeded, the tool returned
         status=error, or mcpd itself failed to forward.

    Any exception that escapes _call_tool_service propagates to the
    caller; the finally{} block still records the failure so the kernel
    call_log reflects it.
    """
    exec_start = time.perf_counter()
    status_code = 1
    response_hash = b""
    err_head = b""
    tool_status_code = TSC_UNSPECIFIED
    try:
        try:
            # Reuse the probed socket for the real RPC. The kernel just
            # approved based on the identity we saw at probe time; by
            # sending the payload down the same socket we guarantee the
            # approval and the payload land in the same process.
            tool_resp = _call_tool_service(
                tool,
                req_id=req_id,
                agent_id=agent_id,
                payload=payload,
                conn=probe_result.conn,
                probed_pid=probe_result.pid,
                probed_identity=probe_result.identity,
            )
        except ValueError as exc:
            # _call_tool_service wraps connect refused / timeout / transport
            # errors into ValueError, so this branch is mcpd forwarding
            # failures (as opposed to the tool returning status=error).
            tool_status_code = TSC_FORWARD_FAIL
            err_head = str(exc).encode("utf-8", errors="replace")[:48]
            raise
        status = tool_resp.get("status")
        result = tool_resp.get("result", {})
        err = tool_resp.get("error", "")
        tool_t_ms = tool_resp.get("t_ms")
        if not isinstance(result, dict):
            result = {"value": result}
        if not isinstance(err, str):
            err = str(err)
        if not isinstance(tool_t_ms, int) or isinstance(tool_t_ms, bool) or tool_t_ms < 0:
            tool_t_ms = int((time.perf_counter() - exec_start) * 1000)
        if status == "ok":
            status_code = 0
            tool_status_code = TSC_OK
            response_hash = _summary_hash_prefix(_canonical_payload_bytes(result))
        else:
            tool_status_code = TSC_TOOL_ERROR
            err_head = err.encode("utf-8", errors="replace")[:48]
        return {
            "req_id": req_id,
            "status": status,
            "result": result if status == "ok" else {},
            "error": "" if status == "ok" else err,
            "t_ms": tool_t_ms,
            "tool_name": tool.name,
            "decision": decision,
            "reason": reason,
            "ticket_id": ticket_id,
        }
    except Exception as exc:  # noqa: BLE001
        if not err_head:
            err_head = str(exc).encode("utf-8", errors="replace")[:48]
        if tool_status_code == TSC_UNSPECIFIED:
            tool_status_code = TSC_FORWARD_FAIL
        raise
    finally:
        exec_ms = int((time.perf_counter() - exec_start) * 1000)
        try:
            _kernel_report_complete(
                agent_id=agent_id,
                tool_id=tool.tool_id,
                req_id=req_id,
                status_code=status_code,
                exec_ms=exec_ms,
                payload_hash=payload_hash,
                response_hash=response_hash,
                err_head=err_head,
                tool_status_code=tool_status_code,
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.error(
                "event=tool_complete_failed req_id=%d agent=%s tool=%d err=%s",
                req_id,
                agent_id,
                tool.tool_id,
                exc,
            )


def _handle_tool_exec(req: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a tool:exec request. The stages below mirror the paper's
    control-plane description; keep them in lock-step with the section
    headers so a reviewer grepping ``# === stage:`` sees the same split.
    """

    # === stage: reconcile trigger ===
    _ensure_runtime_registry_current()

    # === stage: semantic validation ===
    req_id = ensure_int("req_id", req.get("req_id", 0))
    session_id = ensure_non_empty_str("session_id", req.get("session_id", ""))
    peer = req.get("_peer")
    if not isinstance(peer, PeerIdentity):
        raise ValueError("missing peer identity")
    app_id = ensure_non_empty_str("app_id", req.get("app_id", ""))
    tool_id = ensure_int("tool_id", req.get("tool_id", 0))
    with _registry_lock:
        tool = _tool_registry.get(tool_id)
    if tool is None:
        raise ValueError(f"unsupported tool_id: {tool_id}")
    if tool.app_id != app_id:
        raise ValueError(
            f"tool_id={tool_id} does not belong to app_id={app_id} (expected {tool.app_id})"
        )
    payload = req.get("payload", {})
    validate_payload(tool.input_schema, payload)
    payload_hash = _summary_hash_prefix(_canonical_payload_bytes(payload))

    # === stage: binding / session lookup ===
    session = resolve_session(session_id, peer)
    binding = session_binding(session)
    agent_id = ensure_non_empty_str("agent_id", session.get("agent_id", ""))

    # === stage: serving-identity probe ===
    # hold=True: keep the probe's verified socket open so the real RPC
    # reuses the same connection after kernel arbitration. That closes
    # the TOCTOU window between probe and exec dial.
    probe_result = _probe_backend_binary_hash(tool, hold=True)
    backend_binary_hash = probe_result.digest
    if not probe_result.live:
        # Refuse any request whose live backend identity we could not
        # confirm this round. Serving the cached digest on a failed live
        # probe would let a swapped backend pass the kernel TOFU check.
        LOGGER.warning(
            "event=probe_failed tool=%d name=%s cached_digest_present=%s",
            tool_id, tool.name, bool(backend_binary_hash),
        )
        _log_decision_event(
            source="probe",
            req_id=req_id,
            agent_id=agent_id,
            tool_id=tool_id,
            decision="DENY",
            reason=reason_taxonomy.PROBE_FAILED.name,
            ticket_id=0,
        )
        _record_probe_failed_audit(
            req_id=req_id, agent_id=agent_id, tool_id=tool_id,
            binding=binding, payload_hash=payload_hash,
        )
        return _build_rejection_response(
            req_id=req_id,
            decision="DENY",
            reason=reason_taxonomy.PROBE_FAILED.name,
            error_message="binary_hash probe failed",
            ticket_id=0,
        )

    # === stage: kernel arbitration ===
    tool_hash = _resolve_tool_hash(req, tool)
    _ensure_agent_registered(agent_id, binding)
    approval_ticket_id = ensure_int("approval_ticket_id", req.get("approval_ticket_id", 0))
    decision, reason, ticket_id = _kernel_arbitrate(
        req_id=req_id,
        agent_id=agent_id,
        binding_hash=binding.binding_hash,
        binding_epoch=binding.binding_epoch,
        tool_id=tool_id,
        tool_hash=tool_hash,
        ticket_id=approval_ticket_id,
        payload_hash=payload_hash,
        binary_hash=backend_binary_hash,
        catalog_epoch=binding.catalog_epoch,
    )

    # === stage: approval continuation / rejection shortcut ===
    if decision == "DENY":
        _discard_probe_conn(probe_result)
        return _build_rejection_response(
            req_id=req_id, decision=decision, reason=reason,
            error_message=f"kernel arbitration denied: {reason}",
            ticket_id=ticket_id,
        )
    if decision == "DEFER":
        # Deferred awaiting approval: close probe socket, the retry
        # after approval opens a fresh probe.
        _discard_probe_conn(probe_result)
        if ticket_id > 0:
            remember_pending_approval(
                ticket_id=ticket_id,
                session_id=session_id,
                req_id=req_id,
                agent_id=agent_id,
                binding_hash=binding.binding_hash,
                binding_epoch=binding.binding_epoch,
                app_id=app_id,
                tool_id=tool_id,
                payload=payload,
                tool_hash=tool_hash,
            )
        return _build_rejection_response(
            req_id=req_id, decision=decision, reason=reason,
            error_message=f"kernel arbitration deferred: {reason}",
            ticket_id=ticket_id,
        )

    # === stage: tool dispatch + completion reporting ===
    return _dispatch_tool_call(
        tool=tool,
        req_id=req_id,
        agent_id=agent_id,
        payload=payload,
        probe_result=probe_result,
        decision=decision,
        reason=reason,
        ticket_id=ticket_id,
        payload_hash=payload_hash,
    )


def _handle_sys_approval_decide(
    conn: socket.socket, req: Dict[str, Any], t0: float
) -> None:
    """Operator-driven approval decision path.

    No session binding is required — the operator tool issues the decide
    out-of-band. The pending_approval entry is inspected read-only for
    binding_hash/agent_id recovery; after the kernel accepts the decide,
    the userspace record's state is mirrored (approve / deny / revoke)
    but the entry itself stays so the client's eventual tool:exec retry
    can find it. Idempotent re-decide is tolerated on both sides.
    """
    ticket_id_raw = req.get("ticket_id", 0)
    decision_raw = req.get("decision", "")
    operator_raw = req.get("operator", "")
    agent_id_raw = req.get("agent_id", "")
    reason_raw = req.get("reason", "")
    ttl_ms_raw = req.get("ttl_ms", DEFAULT_APPROVAL_TTL_MS)
    ticket_id = ensure_int("ticket_id", ticket_id_raw)
    decision_text = ensure_non_empty_str("decision", decision_raw)
    operator_text = ensure_non_empty_str("operator", operator_raw)
    reason_text = ensure_non_empty_str("reason", reason_raw)
    ttl_ms = ensure_int("ttl_ms", ttl_ms_raw)
    binding_hash = 0
    binding_epoch = 0
    agent_id_text = agent_id_raw if isinstance(agent_id_raw, str) else ""
    pending_known = False
    try:
        pending = peek_pending_approval(ticket_id)
        replay_req = validate_pending_approval_req(pending)
        if not agent_id_text:
            agent_id_text = replay_req["agent_id"]
        binding_hash = replay_req["binding_hash"]
        binding_epoch = replay_req["binding_epoch"]
        pending_known = True
    except ValueError:
        if not agent_id_text:
            agent_id_text = operator_text
    agent_id_text = ensure_non_empty_str("agent_id", agent_id_text)
    _approval_decide(
        ticket_id,
        decision_text,
        agent_id_text,
        operator_text,
        reason_text,
        ttl_ms,
        binding_hash=binding_hash,
        binding_epoch=binding_epoch,
    )
    # Mirror the kernel decide into the userspace pending record so its
    # state and the kernel ticket state stay observably coherent. Skip if
    # we never had a pending entry (operator-only flow or already-
    # consumed ticket).
    if pending_known:
        normalized_decision = decision_text.strip().lower()
        try:
            if normalized_decision == "approve":
                approve_pending_approval(
                    ticket_id, trigger="operator_approve"
                )
            elif normalized_decision in ("deny", "revoke"):
                deny_pending_approval(
                    ticket_id,
                    trigger=(
                        "operator_revoke"
                        if normalized_decision == "revoke"
                        else "operator_deny"
                    ),
                )
        except ValueError:
            # Race: entry was taken/invalidated between peek and state
            # update. Kernel side is already authoritative; nothing to
            # mirror.
            pass
    resp = {
        "status": "ok",
        "ticket_id": ticket_id,
        "decision": decision_text.lower(),
        "operator": operator_text,
        "agent_id": agent_id_text,
        "ttl_ms": ttl_ms,
    }
    send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
    t_ms = int((time.perf_counter() - t0) * 1000)
    LOGGER.info(
        "kind=%s status=ok ticket_id=%d decision=%s t_ms=%d",
        "sys:approval_decide",
        ticket_id,
        decision_text.lower(),
        t_ms,
    )


def _handle_sys_approval_reply(
    conn: socket.socket,
    req: Dict[str, Any],
    peer: PeerIdentity,
    t0: float,
) -> None:
    """Session-bound client approval reply path.

    Unlike approval_decide (operator-only), this path runs inside the
    client's own session. Order is strict: kernel decide -> mirror
    userspace state -> take. Keeping the record in place across the
    kernel call means an exception from _approval_decide leaves PENDING
    intact without needing a put_back rollback. On approve we replay the
    deferred tool:exec via _handle_tool_exec; if that replay raises
    before the kernel has consumed the ticket, we put the pending entry
    back so a subsequent tool:exec carrying ticket_id can still land.
    """
    session_id = ensure_non_empty_str("session_id", req.get("session_id", ""))
    ticket_id = ensure_int("ticket_id", req.get("ticket_id", 0))
    decision_text = ensure_non_empty_str("decision", req.get("decision", ""))
    reason_text = ensure_non_empty_str("reason", req.get("reason", ""))
    ttl_ms = ensure_int("ttl_ms", req.get("ttl_ms", DEFAULT_APPROVAL_TTL_MS))
    normalized = decision_text.strip().lower()
    if normalized not in ("approve", "deny"):
        raise ValueError("decision must be approve or deny")
    session = resolve_session(session_id, peer)
    pending = peek_pending_approval(ticket_id)
    if pending.get("session_id") != session_id:
        raise ValueError("approval ticket is bound to a different session")
    operator_text = ensure_non_empty_str("agent_id", session.get("agent_id", ""))
    binding = session_binding(session)
    _approval_decide(
        ticket_id=ticket_id,
        decision=normalized,
        agent_id=operator_text,
        approver=operator_text,
        reason=reason_text,
        ttl_ms=ttl_ms,
        binding_hash=binding.binding_hash,
        binding_epoch=binding.binding_epoch,
    )
    if normalized == "approve":
        approve_pending_approval(ticket_id, trigger="user_approve")
        pending = take_pending_approval(ticket_id, trigger="consume")
        try:
            replay_req = validate_pending_approval_req(pending)
            replay_req["approval_ticket_id"] = ticket_id
            replay_req["_peer"] = peer
            replay_req["session_id"] = session_id
            resp = _handle_tool_exec(replay_req)
            # Only discard the userspace mirror when the replay actually
            # consumed the approved kernel ticket. A normal error response
            # (e.g. probe_failed, catalog_stale, binding/hash mismatch,
            # or a deferred retry) leaves the kernel ticket unconsumed, so
            # dropping the pending record here would strand mcpd's view.
            if resp.get("decision") != "ALLOW":
                put_pending_approval(ticket_id, pending)
        except Exception:
            # Retry failed before kernel consumed the ticket; restore the
            # pending entry so a subsequent tool:exec carrying ticket_id
            # can still land.
            put_pending_approval(ticket_id, pending)
            raise
    else:  # deny
        deny_pending_approval(ticket_id, trigger="user_deny")
        take_pending_approval(ticket_id, trigger="user_deny_terminal")
        # The replay req_id is the original deferred request's id; recover
        # it from pending before we log so the event line lines up with
        # the earlier arb-side DEFER event for the same req_id.
        replay_req = validate_pending_approval_req(pending)
        _log_decision_event(
            source="user_decline",
            req_id=replay_req["req_id"],
            agent_id=replay_req["agent_id"],
            tool_id=replay_req["tool_id"],
            decision="DENY",
            reason=reason_taxonomy.USER_DECLINED.name,
            ticket_id=ticket_id,
        )
        resp = {
            "status": "error",
            "error": "approval declined by user",
            "ticket_id": ticket_id,
            "decision": "DENY",
            "reason": reason_taxonomy.USER_DECLINED.name,
            "t_ms": 0,
        }
    send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
    t_ms = int((time.perf_counter() - t0) * 1000)
    LOGGER.info(
        "kind=%s status=%s ticket_id=%d decision=%s t_ms=%d",
        "sys:approval_reply",
        resp.get("status"),
        ticket_id,
        normalized,
        t_ms,
    )


def _handle_connection(conn: socket.socket) -> None:
    with conn:
        peer = _read_peer_identity(conn)
        while True:
            req_id = 0
            agent_id = "unknown"
            app_id = ""
            tool_id = 0
            req_kind = "tool:exec"
            t0 = time.perf_counter()
            try:
                raw = recv_frame(conn, max_msg_size=MAX_MSG_SIZE)
                req = json.loads(raw.decode("utf-8"))
                if not isinstance(req, dict):
                    raise ValueError("request must be JSON object")

                if req.get("sys") == "list_apps":
                    req_kind = "sys:list_apps"
                    _ensure_runtime_registry_current()
                    apps_public = _list_apps_public()
                    resp = {"status": "ok", "apps": apps_public}
                    send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
                    t_ms = int((time.perf_counter() - t0) * 1000)
                    LOGGER.info("kind=%s status=ok apps=%d t_ms=%d", req_kind, len(apps_public), t_ms)
                    continue

                if req.get("sys") == "list_tools":
                    req_kind = "sys:list_tools"
                    _ensure_runtime_registry_current()
                    app_id_req = req.get("app_id", "")
                    if app_id_req not in ("", None) and not isinstance(app_id_req, str):
                        raise ValueError("app_id must be string when provided")
                    app_id_str = "" if app_id_req in ("", None) else app_id_req
                    resp = {"status": "ok", "app_id": app_id_str, "tools": _list_tools_public(app_id=app_id_str)}
                    send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
                    t_ms = int((time.perf_counter() - t0) * 1000)
                    LOGGER.info(
                        "kind=%s status=ok app_id=%s tools=%d t_ms=%d",
                        req_kind,
                        app_id_str or "all",
                        len(resp["tools"]),
                        t_ms,
                    )
                    continue

                if req.get("sys") == "open_session":
                    req_kind = "sys:open_session"
                    client_name = ensure_non_empty_str("client_name", req.get("client_name", "llm-app"))
                    ttl_ms = normalize_session_ttl_ms(req.get("ttl_ms", DEFAULT_SESSION_TTL_MS))
                    # Make sure the manifest catalog is fresh before we
                    # snapshot the epoch; otherwise an lll-app concurrent
                    # with a manifest change could bind to a stale epoch.
                    _ensure_runtime_registry_current()
                    catalog_epoch = _read_catalog_epoch()
                    resp = open_session(peer, client_name, ttl_ms, catalog_epoch=catalog_epoch)
                    _bind_agent_identity(resp["agent_id"], session_binding(resolve_session(resp["session_id"], peer)))
                    send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
                    t_ms = int((time.perf_counter() - t0) * 1000)
                    LOGGER.info(
                        "kind=%s status=ok client=%s session=%s agent=%s uid=%d pid=%d t_ms=%d",
                        req_kind,
                        client_name,
                        resp["session_id"][:12],
                        resp["agent_id"],
                        peer.uid,
                        peer.pid,
                        t_ms,
                    )
                    continue

                if req.get("sys") == "approval_decide":
                    req_kind = "sys:approval_decide"
                    _handle_sys_approval_decide(conn, req, t0)
                    continue

                if req.get("sys") == "approval_reply":
                    req_kind = "sys:approval_reply"
                    _handle_sys_approval_reply(conn, req, peer, t0)
                    continue

                if "kind" in req and req.get("kind") != "tool:exec":
                    raise ValueError(f"unsupported request kind: {req.get('kind')}")

                req_id = ensure_int("req_id", req.get("req_id", 0))
                session_id = ensure_non_empty_str("session_id", req.get("session_id", ""))
                session = resolve_session(session_id, peer)
                agent_id = ensure_non_empty_str("agent_id", session.get("agent_id", ""))
                app_id = ensure_non_empty_str("app_id", req.get("app_id", ""))
                tool_id = ensure_int("tool_id", req.get("tool_id", 0))
                req["_peer"] = peer
                resp = _handle_tool_exec(req)
                send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
                t_ms = int((time.perf_counter() - t0) * 1000)
                LOGGER.info(
                    "req_id=%d session=%s agent=%s app=%s tool=%d kind=%s status=%s t_ms=%d",
                    req_id,
                    session_id[:12],
                    agent_id,
                    app_id,
                    tool_id,
                    req_kind,
                    resp.get("status"),
                    t_ms,
                )
            except ConnectionError:
                return
            except Exception as exc:  # noqa: BLE001
                t_ms = int((time.perf_counter() - t0) * 1000)
                if req_kind.startswith("sys:"):
                    resp = {"status": "error", "error": str(exc)}
                else:
                    resp = {
                        "req_id": req_id,
                        "status": "error",
                        "result": {},
                        "error": str(exc),
                        "t_ms": t_ms,
                    }
                try:
                    send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
                except Exception:  # noqa: BLE001
                    return
                LOGGER.error(
                    "req_id=%d agent=%s app=%s tool=%d kind=%s status=error err=%s",
                    req_id,
                    agent_id,
                    app_id,
                    tool_id,
                    req_kind,
                    exc,
                )


def _accept_loop(server: socket.socket) -> None:
    while not _stop_event.is_set():
        try:
            conn, _addr = server.accept()
        except OSError:
            if _stop_event.is_set():
                return
            continue
        th = threading.Thread(target=_handle_connection, args=(conn,), daemon=True)
        th.start()


def _cleanup_socket(path: str) -> None:
    p = Path(path)
    if p.exists():
        p.unlink()


def _signal_handler(_sig: int, _frame: Any) -> None:
    _stop_event.set()


def main() -> int:
    global _kernel_client

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # Resolve security config up front so an ambiguous uid-trust policy
    # (e.g. root mcpd with no explicit allowed_backend_uids) causes a
    # clean startup failure before we touch netlink or the socket.
    try:
        sec = _get_security_config()
    except ConfigError as exc:
        LOGGER.error("event=startup_refused reason=%s", exc)
        return 2
    LOGGER.info(
        "security: allowed_backend_uids=%s (euid=%d)",
        list(sec.allowed_backend_uids or ()), os.geteuid(),
    )

    try:
        _kernel_client = KernelMcpNetlinkClient()
        _ensure_runtime_registry_current(force=True)
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("event=startup_failed reason=%s", exc)
        if _kernel_client is not None:
            _kernel_client.close()
            _kernel_client = None
        return 1

    _cleanup_socket(SOCK_PATH)

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(SOCK_PATH)
            os.chmod(SOCK_PATH, 0o666)
            server.listen(128)
            server.settimeout(0.5)
            LOGGER.info("event=startup sock=%s", SOCK_PATH)

            accept_thread = threading.Thread(target=_accept_loop, args=(server,), daemon=True)
            accept_thread.start()

            while not _stop_event.is_set():
                time.sleep(0.2)
        return 0
    finally:
        _cleanup_socket(SOCK_PATH)
        if _kernel_client is not None:
            _kernel_client.close()
            _kernel_client = None
        LOGGER.info("event=shutdown")


if __name__ == "__main__":
    raise SystemExit(main())
