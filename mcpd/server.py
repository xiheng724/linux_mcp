#!/usr/bin/env python3
"""Kernel MCP data-plane daemon over Unix Domain Socket."""

from __future__ import annotations

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
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Tuple

try:
    from config import SecurityConfig, load_security_config
    from manifest_loader import DEFAULT_MANIFEST_DIR, AppManifest, ToolManifest, load_all_manifests
    from netlink_client import KernelMcpNetlinkClient
    from public_catalog import list_apps_public, list_tools_public
    from rpc_framing import recv_frame, send_frame
    from schema_utils import ensure_int, ensure_non_empty_str, validate_payload
    from transport import TransportError, dial as transport_dial
    from session_store import (
        AgentBinding,
        PeerIdentity,
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
except ModuleNotFoundError:  # pragma: no cover - package import fallback
    from .config import SecurityConfig, load_security_config
    from .manifest_loader import DEFAULT_MANIFEST_DIR, AppManifest, ToolManifest, load_all_manifests
    from .netlink_client import KernelMcpNetlinkClient
    from .public_catalog import list_apps_public, list_tools_public
    from .rpc_framing import recv_frame, send_frame
    from .schema_utils import ensure_int, ensure_non_empty_str, validate_payload
    from .transport import TransportError, dial as transport_dial
    from .session_store import (
        AgentBinding,
        PeerIdentity,
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
            "register tool=%d name=%s risk=0x%x binary_hash=%s",
            tool.tool_id, tool.name, tool.risk_flags, pr.digest[:16] + "...",
        )
    else:
        LOGGER.warning(
            "register tool=%d name=%s probe live=%s digest_empty=%s "
            "transport=%s endpoint=%s (will retry at exec)",
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


def _load_runtime_registry(*, force_reset: bool = False) -> str:
    """Reconcile local manifest state with the kernel tool registry.

    Two fingerprints drive the diff, tracked separately on purpose:

      - manifest_hash  : semantic identity (name, description, schema,
                         risk_tags, ...). Changing it means the tool looks
                         like a different tool to llm-app. Semantic-only
                         changes trigger a plain register_tool() — the
                         kernel refreshes name/hash/risk_flags and bumps
                         catalog_epoch. The TOFU binary_hash slot is
                         intentionally preserved; same backend runs it.
      - binding_fingerprint : runtime routing (transport, endpoint,
                         operation). Changing this means the tool may now
                         be served by a *different process with a different
                         binary*. The old TOFU binary_hash pin would make
                         every subsequent call DENY as binary_mismatch, so
                         we must unregister_tool() first to clear the slot,
                         then register_tool() so the next probe can learn
                         the new backend's hash cleanly. Each mutation also
                         advances catalog_epoch, which is what forces any
                         pre-change session to hit catalog_stale_rebind_required
                         instead of silently routing to the new endpoint.

    Both fingerprints are compared explicitly; we do NOT fold binding into
    manifest_hash because that would make a host-move look like a tool
    identity change to external consumers, which is the opposite of what
    the semantic-hash design guarantees.

    force_reset=True keeps the old startup behavior — useful once after
    kernel module reload when the module's tool registry is known to be
    inconsistent with whatever mcpd has cached.
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
        client.reset_tools()
        for tool in tool_registry.values():
            _register_tool_with_kernel(tool)
    else:
        with _registry_lock:
            previous_tool_ids = set(_tool_registry.keys())
            previous_manifest_hashes = {
                tid: t.manifest_hash for tid, t in _tool_registry.items()
            }
            previous_binding_fingerprints = {
                tid: t.binding_fingerprint for tid, t in _tool_registry.items()
            }
        new_tool_ids = set(tool_registry.keys())

        removed = previous_tool_ids - new_tool_ids
        added = new_tool_ids - previous_tool_ids

        intersect = previous_tool_ids & new_tool_ids
        semantic_changed = {
            tid for tid in intersect
            if previous_manifest_hashes.get(tid)
            != tool_registry[tid].manifest_hash
        }
        binding_changed = {
            tid for tid in intersect
            if previous_binding_fingerprints.get(tid)
            != tool_registry[tid].binding_fingerprint
        }

        for tool_id in removed:
            try:
                client.unregister_tool(tool_id)
            except RuntimeError as exc:
                LOGGER.warning("kernel unregister failed tool=%d err=%s",
                               tool_id, exc)
            _backend_hash_cache.pop(tool_id, None)

        # Binding changes must clear the kernel TOFU slot before re-registering;
        # if we only call register_tool(), kernel_mcp_register_tool preserves
        # the old binary_hash and every subsequent tool:exec will DENY as
        # binary_mismatch after a genuine backend move. Also drop mcpd's
        # per-tool hash cache so the next probe starts clean.
        for tool_id in binding_changed:
            try:
                client.unregister_tool(tool_id)
            except RuntimeError as exc:
                LOGGER.warning(
                    "kernel unregister during binding-change failed tool=%d err=%s",
                    tool_id, exc,
                )
            _backend_hash_cache.pop(tool_id, None)
            LOGGER.warning(
                "tool=%d runtime binding changed (transport/endpoint/operation); "
                "cleared kernel TOFU slot and local hash cache before re-register",
                tool_id,
            )

        # A binding_changed tool also needs to be re-registered. A
        # semantic_changed tool whose binding is unchanged only needs the
        # in-place register (kernel updates metadata and bumps epoch, TOFU
        # slot intentionally preserved).
        to_register = added | binding_changed | semantic_changed
        for tool_id in to_register:
            _register_tool_with_kernel(tool_registry[tool_id])

        if removed or added or semantic_changed or binding_changed:
            LOGGER.info(
                "reconciled kernel catalog added=%d removed=%d "
                "semantic_changed=%d binding_changed=%d",
                len(added), len(removed),
                len(semantic_changed), len(binding_changed),
            )

    with _registry_lock:
        _app_registry.clear()
        _app_registry.update(app_registry)
        _tool_registry.clear()
        _tool_registry.update(tool_registry)

    LOGGER.info(
        "loaded manifests apps=%d tools=%d app_ids=%s",
        len(app_registry),
        len(tool_registry),
        sorted(app_registry.keys()),
    )
    return _compute_manifest_signature()


def _ensure_runtime_registry_current(*, force: bool = False) -> None:
    global _manifest_signature

    with _manifest_reload_lock:
        current_signature = _compute_manifest_signature()
        if not force and current_signature == _manifest_signature:
            return
        # force=True is only used at startup; do a hard reset so we don't
        # trust whatever state survived in the kernel from a prior run.
        # Subsequent on-demand reloads run incrementally so only mutated
        # tools bump the catalog epoch.
        loaded_signature = _load_runtime_registry(force_reset=force)
        _manifest_signature = loaded_signature
        LOGGER.info("manifest catalog refreshed signature=%s", loaded_signature[:12])


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
        "agent registered via netlink: %s pid=%d uid=%d binding_hash=%016x epoch=%d catalog_epoch=%d",
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
    LOGGER.info(
        "arb req_id=%d agent=%s tool=%d decision=%s reason=%s ticket_id=%d",
        req_id,
        agent_id,
        tool_id,
        decision_reply.decision,
        decision_reply.reason,
        decision_reply.ticket_id,
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

        # Interpreter-aware composite hash. When the backend is hosted
        # by an interpreter, hashing /proc/<pid>/exe alone pins the
        # interpreter, NOT the application code. We combine with a
        # live-read digest of the entry script so a change to the
        # script on disk invalidates the kernel TOFU pin immediately —
        # the manifest-cached digest is only refreshed when the
        # manifest JSON itself changes, so relying on it would leave a
        # swapped .py trusted until mcpd bounces.
        exe_target = id_before[0]
        if _is_interpreter_exe(exe_target):
            live_script_digest = _fresh_script_digest(tool.script_path)
            if not live_script_digest:
                # Fall back to whatever we captured at manifest load so
                # a transient read failure doesn't nuke an otherwise
                # valid pin; the next successful read will DENY via
                # binary_mismatch if the script actually changed.
                live_script_digest = tool.script_digest
                if live_script_digest:
                    LOGGER.warning(
                        "tool=%d name=%s script re-read failed "
                        "(path=%s); using manifest-cached digest",
                        tool.tool_id, tool.name, tool.script_path,
                    )
            if live_script_digest:
                digest = _composite_interpreter_hash(exe_digest, live_script_digest)
            else:
                LOGGER.warning(
                    "tool=%d name=%s backend is interpreter-hosted (exe=%s) but "
                    "no script_digest available — binary_hash pins interpreter "
                    "only; application code is NOT TOFU-protected",
                    tool.tool_id, tool.name, exe_target,
                )
                digest = exe_digest
        else:
            digest = exe_digest

        with _backend_hash_lock:
            _backend_hash_cache[tool.tool_id] = (backend_pid, id_before, digest)
        if not hold:
            probe.close()
        return ProbeResult(
            digest=digest, live=True,
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


def _resolve_tool_hash(req: Dict[str, Any], tool: ToolManifest) -> str:
    raw = req.get("tool_hash", "")
    if raw in (None, ""):
        return tool.manifest_hash
    if not isinstance(raw, str) or not HASH_RE.fullmatch(raw):
        raise ValueError("tool_hash must be 64 hex chars")
    return raw.lower()


def _handle_tool_exec(req: Dict[str, Any]) -> Dict[str, Any]:
    _ensure_runtime_registry_current()
    req_id = ensure_int("req_id", req.get("req_id", 0))
    session_id = ensure_non_empty_str("session_id", req.get("session_id", ""))
    peer = req.get("_peer")
    if not isinstance(peer, PeerIdentity):
        raise ValueError("missing peer identity")
    session = resolve_session(session_id, peer)
    binding = session_binding(session)
    agent_id = ensure_non_empty_str("agent_id", session.get("agent_id", ""))
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
    # hold=True: keep the probe's verified socket open so we can send the
    # actual payload on the same connection after kernel arbitration.
    # That closes the TOCTOU window between probe and exec dial.
    probe_result = _probe_backend_binary_hash(tool, hold=True)
    backend_binary_hash = probe_result.digest

    # Refuse any request whose live backend identity we could not confirm
    # this round. Serving the cached digest on a failed live probe would
    # let a swapped backend pass the kernel TOFU check.
    if not probe_result.live:
        LOGGER.warning(
            "refusing tool=%d name=%s: live probe failed "
            "(cached_digest_present=%s)",
            tool_id, tool.name, bool(backend_binary_hash),
        )
        # Record the denial in the kernel's per-agent call_log so it
        # survives an mcpd crash and shows up in sysfs. Register the
        # agent first so tool_complete has an agent to look up.
        try:
            _ensure_agent_registered(agent_id, binding)
            _kernel_report_complete(
                agent_id=agent_id,
                tool_id=tool_id,
                req_id=req_id,
                status_code=1,
                exec_ms=0,
                payload_hash=payload_hash,
                err_head=b"probe_failed",
                tool_status_code=TSC_PROBE_FAILED,
            )
        except Exception as audit_exc:  # noqa: BLE001
            LOGGER.error(
                "failed to record probe_failed audit req_id=%d agent=%s tool=%d err=%s",
                req_id, agent_id, tool_id, audit_exc,
            )
        return {
            "req_id": req_id,
            "status": "error",
            "result": {},
            "error": "binary_hash probe failed",
            "t_ms": 0,
            "decision": "DENY",
            "reason": "probe_failed",
            "ticket_id": 0,
        }
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
    if decision == "DENY":
        # Kernel rejected: close the probed socket, do NOT forward.
        if probe_result.conn is not None:
            try:
                probe_result.conn.close()
            except Exception:  # noqa: BLE001
                pass
        return {
            "req_id": req_id,
            "status": "error",
            "result": {},
            "error": f"kernel arbitration denied: {reason}",
            "t_ms": 0,
            "decision": decision,
            "reason": reason,
            "ticket_id": ticket_id,
        }
    if decision == "DEFER":
        # Deferred awaiting approval: close probe socket, the retry
        # after approval opens a fresh probe.
        if probe_result.conn is not None:
            try:
                probe_result.conn.close()
            except Exception:  # noqa: BLE001
                pass
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
        return {
            "req_id": req_id,
            "status": "error",
            "result": {},
            "error": f"kernel arbitration deferred: {reason}",
            "t_ms": 0,
            "decision": decision,
            "reason": reason,
            "ticket_id": ticket_id,
        }

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
                tool_id=tool_id,
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
                "tool_complete report failed req_id=%d agent=%s tool=%d err=%s",
                req_id,
                agent_id,
                tool_id,
                exc,
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
                    try:
                        pending = peek_pending_approval(ticket_id)
                        replay_req = validate_pending_approval_req(pending)
                        if not agent_id_text:
                            agent_id_text = replay_req["agent_id"]
                        binding_hash = replay_req["binding_hash"]
                        binding_epoch = replay_req["binding_epoch"]
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
                        req_kind,
                        ticket_id,
                        decision_text.lower(),
                        t_ms,
                    )
                    continue

                if req.get("sys") == "approval_reply":
                    req_kind = "sys:approval_reply"
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
                    pending = take_pending_approval(ticket_id)
                    try:
                        replay_req = validate_pending_approval_req(pending)
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
                        if normalized == "deny":
                            resp = {
                                "status": "error",
                                "error": "approval declined by user",
                                "ticket_id": ticket_id,
                                "decision": "DENY",
                                "reason": "user_declined",
                                "t_ms": 0,
                            }
                        else:
                            replay_req["approval_ticket_id"] = ticket_id
                            replay_req["_peer"] = peer
                            replay_req["session_id"] = session_id
                            resp = _handle_tool_exec(replay_req)
                    except Exception:
                        if normalized == "approve":
                            put_pending_approval(ticket_id, pending)
                        raise
                    send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"), max_msg_size=MAX_MSG_SIZE)
                    t_ms = int((time.perf_counter() - t0) * 1000)
                    LOGGER.info(
                        "kind=%s status=%s ticket_id=%d decision=%s t_ms=%d",
                        req_kind,
                        resp.get("status"),
                        ticket_id,
                        normalized,
                        t_ms,
                    )
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

    try:
        _kernel_client = KernelMcpNetlinkClient()
        _ensure_runtime_registry_current(force=True)
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("failed to initialize mcpd runtime: %s", exc)
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
            LOGGER.info("mcpd listening on %s", SOCK_PATH)

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
        LOGGER.info("mcpd stopped")


if __name__ == "__main__":
    raise SystemExit(main())
