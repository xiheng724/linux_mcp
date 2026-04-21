#!/usr/bin/env python3
"""Unit tests for the backend binary-hash probe (mcpd/server.py).

Drives the probe in isolation by monkey-patching the few syscalls it
depends on (transport_dial, _read_peercred, _exe_identity, and the
actual /proc/<pid>/exe file read). That gives us deterministic
control over the scenarios the adversarial review flagged, which
would otherwise need a multi-user VM or a race-sensitive timing
test to reproduce reliably.

Run with:  python3 scripts/test_probe_unit.py
"""
from __future__ import annotations

import io
import os
import sys
import socket
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "mcpd"))

# Import mcpd modules. server.py pulls session_store at import time
# which imports an optional package; that's fine in this environment.
import config  # noqa: E402
import server  # noqa: E402
from manifest_loader import ToolManifest  # noqa: E402


FAILED = 0


def check(cond: bool, msg: str) -> None:
    global FAILED
    if cond:
        print(f"  ok: {msg}")
    else:
        print(f"  FAIL: {msg}")
        FAILED += 1


def _tool(
    tool_id: int = 9001,
    *,
    script_digest: str = "",
    script_path: str = "",
) -> ToolManifest:
    return ToolManifest(
        tool_id=tool_id,
        name="probe_unit_tool",
        app_id="probe_unit_app",
        app_name="Probe Unit",
        risk_tags=[],
        risk_flags=0,
        description="unit test",
        input_schema={"type": "object"},
        examples=[],
        path_semantics={},
        approval_policy={},
        transport="uds_rpc",
        endpoint="/tmp/linux-mcp-apps/probe_unit.sock",
        operation="noop",
        timeout_ms=1000,
        manifest_hash="0" * 64,
        binding_fingerprint="0" * 64,
        script_digest=script_digest,
        script_path=script_path,
    )


def _reset_state(uid: int = None) -> None:
    """Wipe probe cache + install a security config scoped to the given
    uid (defaults to current euid)."""
    with server._backend_hash_lock:
        server._backend_hash_cache.clear()
    cfg = config.SecurityConfig(
        allowed_backend_uids=(uid if uid is not None else os.geteuid(),),
    )
    server._security_config = cfg


class _FakeSocket:
    """Minimal stand-in for transport_dial's return socket."""
    family = socket.AF_UNIX

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self):
        pass


def test_denies_after_probe_dial_failure_with_warm_cache() -> None:
    """Once a digest is cached, a later probe failure must NOT be
    masked by serving the cached hash — the exec path keys on `live`,
    not on digest emptiness."""
    print("== cache warm, probe dial now fails ==")
    _reset_state()
    tool = _tool()

    # Warm the cache as if a prior probe succeeded.
    with server._backend_hash_lock:
        server._backend_hash_cache[tool.tool_id] = (
            424242, ("/bin/native_echo", 1, 2, 100, 99), "deadbeef" * 8,
        )

    # Now make the dial itself raise — live probe fails.
    orig_dial = server.transport_dial
    server.transport_dial = lambda *a, **kw: (_ for _ in ()).throw(OSError("refused"))
    try:
        pr = server._probe_backend_binary_hash(tool)
        check(pr.digest == "deadbeef" * 8,
              "probe returned the cached digest as fallback")
        check(pr.live is False,
              "probe flagged live=False so exec path can refuse")
    finally:
        server.transport_dial = orig_dial

    # Simulate the exec-path condition directly: not-live must trigger DENY.
    check(not pr.live,
          "live=False triggers DENY path even though digest is cached")


def test_identity_race_does_not_cache_mismatched_digest() -> None:
    """Fix #2: if _exe_identity changes between pre-read and post-read,
    the probe must NOT cache (new_id, old_digest)."""
    print("== identity race: execve between pre-id and post-id ==")
    _reset_state()
    tool = _tool(tool_id=9002)

    # Arrange fake dial + peercred so the probe gets a stable pid/uid.
    fake_pid = 777777
    orig_dial = server.transport_dial
    orig_peercred = server._read_peercred
    orig_identity = server._exe_identity

    server.transport_dial = lambda *a, **kw: _FakeSocket()
    server._read_peercred = lambda conn: (fake_pid, os.geteuid())

    # Identity is polled 5 times in the race path:
    #   current_identity (cache-hit check, discarded on miss),
    #   attempt 0: pre_id, post_id,
    #   attempt 1: pre_id, post_id.
    # Simulate an execve that happens during attempt 0's file read:
    # pre_0 = A, post_0 = B (race), pre_1 = B, post_1 = B (stable).
    id_A = ("/bin/a", 1, 10, 100, 1000)
    id_B = ("/bin/b", 1, 20, 200, 2000)
    identity_queue = [id_A, id_A, id_B, id_B, id_B]

    def fake_identity(pid: int):
        check(pid == fake_pid, "identity queried for the right pid")
        return identity_queue.pop(0) if identity_queue else id_B

    server._exe_identity = fake_identity

    # Reads in order: attempt 0 opens while exe=A and reads A's bytes;
    # attempt 1 opens while exe=B and reads B's bytes.
    read_queue = [b"payload-A", b"payload-B"]

    import hashlib
    expected_hash_B = hashlib.sha256(b"payload-B").hexdigest()

    class _FakeFH:
        def __init__(self, data): self._data = data
        def __enter__(self): return self
        def __exit__(self, *exc): return False
        def read(self, n):
            if not self._data: return b""
            chunk = self._data[:n]
            self._data = self._data[n:]
            return chunk

    orig_open = server.__builtins__["open"] if isinstance(server.__builtins__, dict) else __builtins__.open

    def fake_open(path, mode="r", *a, **kw):
        if path == f"/proc/{fake_pid}/exe" and "b" in mode:
            data = read_queue.pop(0) if read_queue else b""
            return _FakeFH(data)
        return orig_open(path, mode, *a, **kw)

    # Monkey-patch open in server's module namespace.
    orig_server_open = getattr(server, "open", None)
    server.open = fake_open  # type: ignore[attr-defined]

    try:
        pr = server._probe_backend_binary_hash(tool)
    finally:
        server.transport_dial = orig_dial
        server._read_peercred = orig_peercred
        server._exe_identity = orig_identity
        if orig_server_open is None:
            try:
                del server.open  # type: ignore[attr-defined]
            except AttributeError:
                pass
        else:
            server.open = orig_server_open

    check(pr.live is True, "retry converged to a stable identity")
    check(pr.digest == expected_hash_B,
          f"cached digest matches the bytes actually read under id_B "
          f"(got {pr.digest[:12]}..., want {expected_hash_B[:12]}...)")
    with server._backend_hash_lock:
        cached = server._backend_hash_cache.get(tool.tool_id)
    check(cached is not None and cached[1] == id_B,
          "cache is keyed on id_B (the identity we actually hashed), not id_A")


def test_identity_race_exhausts_retries_and_does_not_cache() -> None:
    """If the race persists across all retries, probe must return
    live=False and leave the cache unchanged."""
    print("== identity race: persistent, retries exhausted ==")
    _reset_state()
    tool = _tool(tool_id=9003)
    fake_pid = 888888
    id_A = ("/bin/a", 1, 10, 100, 1000)
    id_B = ("/bin/b", 1, 20, 200, 2000)
    # Always flip between A and B so no attempt sees a stable identity.
    flipping = [id_A, id_B, id_A, id_B, id_A, id_B]

    orig_dial = server.transport_dial
    orig_peercred = server._read_peercred
    orig_identity = server._exe_identity
    server.transport_dial = lambda *a, **kw: _FakeSocket()
    server._read_peercred = lambda conn: (fake_pid, os.geteuid())
    server._exe_identity = lambda pid: flipping.pop(0) if flipping else id_A

    orig_server_open = getattr(server, "open", None)
    class _FH:
        def __enter__(self): return self
        def __exit__(self, *e): return False
        def read(self, n): return b""
    server.open = lambda p, m="r", *a, **kw: _FH()  # type: ignore[attr-defined]

    try:
        pr = server._probe_backend_binary_hash(tool)
    finally:
        server.transport_dial = orig_dial
        server._read_peercred = orig_peercred
        server._exe_identity = orig_identity
        if orig_server_open is None:
            try: del server.open  # type: ignore[attr-defined]
            except AttributeError: pass
        else:
            server.open = orig_server_open

    check(pr.live is False,
          "persistent race yields live=False (exec path will refuse)")
    with server._backend_hash_lock:
        cached = server._backend_hash_cache.get(tool.tool_id)
    check(cached is None, "cache is NOT populated from an unstable hash")


def test_interpreter_backend_composite_hash_reflects_script_change() -> None:
    """Fix (interpreter-aware TOFU): when /proc/<pid>/exe is a Python
    interpreter, the probe must composite the interpreter hash with
    the manifest-declared script_digest. Changing EITHER the
    interpreter bytes OR the script_digest must change the final
    binary_hash — otherwise a swapped .py backend would keep the same
    TOFU pin and defeat the guarantee."""
    print("== interpreter-hosted backend: composite hash ==")
    _reset_state()

    # Identical interpreter bytes + identity, two different scripts.
    fake_pid = 555555
    id_interp = ("/usr/bin/python3", 1, 42, 8000, 123)

    orig_dial = server.transport_dial
    orig_peercred = server._read_peercred
    orig_identity = server._exe_identity
    orig_server_open = getattr(server, "open", None)

    class _FH:
        def __init__(self, data): self._data = data
        def __enter__(self): return self
        def __exit__(self, *e): return False
        def read(self, n):
            if not self._data: return b""
            chunk = self._data[:n]; self._data = self._data[n:]
            return chunk

    def run_probe(script_digest: str) -> str:
        _reset_state()
        identities = [id_interp, id_interp, id_interp]  # current, pre, post
        server.transport_dial = lambda *a, **kw: _FakeSocket()
        server._read_peercred = lambda conn: (fake_pid, os.geteuid())
        server._exe_identity = lambda pid: identities.pop(0) if identities else id_interp
        server.open = lambda p, m="r", *a, **kw: _FH(b"python-interp-bytes")  # type: ignore[attr-defined]
        tool = _tool(tool_id=9100, script_digest=script_digest)
        pr = server._probe_backend_binary_hash(tool)
        return pr.digest

    try:
        digest_script_A = run_probe("a" * 64)
        digest_script_B = run_probe("b" * 64)
        digest_no_script = run_probe("")  # interpreter-only fallback
    finally:
        server.transport_dial = orig_dial
        server._read_peercred = orig_peercred
        server._exe_identity = orig_identity
        if orig_server_open is None:
            try: del server.open  # type: ignore[attr-defined]
            except AttributeError: pass
        else:
            server.open = orig_server_open

    check(digest_script_A != digest_no_script,
          "adding a script_digest changes the composite hash vs. interpreter-only")
    check(digest_script_A != digest_script_B,
          "changing script_digest changes the exported binary_hash")
    check(len(digest_script_A) == 64 and len(digest_script_B) == 64,
          "composite hashes are well-formed 64-hex SHA-256 strings")


def test_uid_mismatch_rejects_probe() -> None:
    """Fix #3: SO_PEERCRED uid not in allowed_backend_uids must block
    the probe before any /proc/<pid>/exe read."""
    print("== uid allowlist: disallowed peer uid ==")
    _reset_state(uid=424242)  # demand uid=424242
    tool = _tool(tool_id=9004)

    orig_dial = server.transport_dial
    orig_peercred = server._read_peercred
    orig_identity = server._exe_identity

    server.transport_dial = lambda *a, **kw: _FakeSocket()
    # Peer uid does NOT match allowlist.
    server._read_peercred = lambda conn: (12345, os.geteuid())

    read_called = {"count": 0}
    def should_never_be_called(pid):
        read_called["count"] += 1
        return ("/bin/x", 1, 1, 1, 1)
    server._exe_identity = should_never_be_called

    try:
        pr = server._probe_backend_binary_hash(tool)
    finally:
        server.transport_dial = orig_dial
        server._read_peercred = orig_peercred
        server._exe_identity = orig_identity

    check(pr.live is False, "disallowed uid returns live=False")
    check(read_called["count"] == 0,
          "probe short-circuited before reading /proc (no identity query)")


def test_probe_refreshes_script_digest_from_disk() -> None:
    """Fix (interpreter script swap): the probe must re-read the entry
    script from disk on every call, not trust the manifest-cached
    digest. Otherwise a .py swap after backend restart stays trusted
    until mcpd reloads."""
    print("== interpreter backend: probe re-reads script from disk ==")
    import tempfile, hashlib

    _reset_state()
    fake_pid = 666666
    id_interp = ("/usr/bin/python3", 1, 42, 8000, 123)

    orig_dial = server.transport_dial
    orig_peercred = server._read_peercred
    orig_identity = server._exe_identity
    orig_server_open = getattr(server, "open", None)

    class _FH:
        def __init__(self, data): self._data = data
        def __enter__(self): return self
        def __exit__(self, *e): return False
        def read(self, n):
            if not self._data: return b""
            chunk = self._data[:n]; self._data = self._data[n:]
            return chunk

    server.transport_dial = lambda *a, **kw: _FakeSocket()
    server._read_peercred = lambda conn: (fake_pid, os.geteuid())
    server._exe_identity = lambda pid: id_interp

    # Route /proc/<pid>/exe reads to an interpreter blob, but let the
    # real script path read through to the host filesystem so the
    # probe picks up whatever's actually on disk.
    def routed_open(path, mode="r", *a, **kw):
        if path == f"/proc/{fake_pid}/exe" and "b" in mode:
            return _FH(b"python-interp-bytes")
        return open(path, mode, *a, **kw)
    server.open = routed_open  # type: ignore[attr-defined]

    with tempfile.NamedTemporaryFile("wb", suffix=".py", delete=False) as tf:
        tf.write(b"# v1\nprint('v1')\n")
        script_path = tf.name

    try:
        stale_digest = "f" * 64  # deliberately NOT the v1 content hash
        tool = _tool(tool_id=9300, script_digest=stale_digest, script_path=script_path)

        pr1 = server._probe_backend_binary_hash(tool)
        check(pr1.live is True, "first probe succeeds with live=True")

        # Compute what the composite SHOULD be based on the on-disk v1.
        v1_script_hash = hashlib.sha256(Path(script_path).read_bytes()).hexdigest()
        interp_hash = hashlib.sha256(b"python-interp-bytes").hexdigest()
        expected_v1 = hashlib.sha256(
            (interp_hash + ":" + v1_script_hash).encode("ascii")
        ).hexdigest()
        check(pr1.digest == expected_v1,
              "probe used the LIVE file hash, not the stale manifest digest")

        # Swap the script on disk. No manifest reload, no mcpd bounce.
        Path(script_path).write_bytes(b"# v2 SWAPPED\nprint('attack')\n")
        # Clear cache so the probe goes through the re-hash path.
        with server._backend_hash_lock:
            server._backend_hash_cache.pop(tool.tool_id, None)

        pr2 = server._probe_backend_binary_hash(tool)
        v2_script_hash = hashlib.sha256(Path(script_path).read_bytes()).hexdigest()
        expected_v2 = hashlib.sha256(
            (interp_hash + ":" + v2_script_hash).encode("ascii")
        ).hexdigest()
        check(pr2.digest == expected_v2,
              "probe picked up the swap immediately without manifest reload")
        check(pr1.digest != pr2.digest,
              "composite hash moved after the swap (kernel will DENY binary_mismatch)")
    finally:
        os.unlink(script_path)
        server.transport_dial = orig_dial
        server._read_peercred = orig_peercred
        server._exe_identity = orig_identity
        if orig_server_open is None:
            try: del server.open  # type: ignore[attr-defined]
            except AttributeError: pass
        else:
            server.open = orig_server_open


def test_reused_probe_socket_detects_identity_drift() -> None:
    """Fix (reused-probe TOCTOU): when the probe's socket is reused,
    _call_tool_service must re-validate /proc/<pid>/exe identity,
    not just the PID. execve() preserves PID and keeps accepted
    sockets open, so a same-PID check alone lets the backend re-exec
    after the probe and still receive the approved payload."""
    print("== reused probe socket: rejects exe identity drift ==")

    orig_dial = server.transport_dial
    orig_peercred = server._read_peercred
    orig_identity = server._exe_identity
    orig_send = server.send_frame
    orig_recv = server.recv_frame

    server.transport_dial = lambda *a, **kw: (_ for _ in ()).throw(
        AssertionError("must not dial")
    )
    server._read_peercred = lambda conn: (4242, os.geteuid())
    # Identity at probe time differs from identity reported now — that's
    # the execve-under-the-same-pid scenario.
    server._exe_identity = lambda pid: ("/usr/bin/attack_exe", 1, 99, 900, 9999)
    server.send_frame = lambda *a, **kw: (_ for _ in ()).throw(
        AssertionError("must not send on swapped socket")
    )
    server.recv_frame = lambda *a, **kw: (_ for _ in ()).throw(
        AssertionError("must not recv on swapped socket")
    )

    class _HeldSocket:
        family = socket.AF_UNIX
        def __enter__(self): return self
        def __exit__(self, *e): self.close(); return False
        def settimeout(self, t): pass
        def close(self): pass

    tool = _tool(tool_id=9400)
    held = _HeldSocket()
    probed_identity = ("/usr/bin/original_backend", 1, 11, 500, 1000)
    raised = False
    try:
        try:
            server._call_tool_service(
                tool, req_id=1, agent_id="a1", payload={},
                conn=held, probed_pid=4242,
                probed_identity=probed_identity,
            )
        except ValueError as exc:
            raised = True
            check("identity drift" in str(exc),
                  f"raised ValueError mentions identity drift (got {exc!r})")
    finally:
        server.transport_dial = orig_dial
        server._read_peercred = orig_peercred
        server._exe_identity = orig_identity
        server.send_frame = orig_send
        server.recv_frame = orig_recv

    check(raised,
          "reused socket with a drifted /proc/<pid>/exe identity was rejected")


def test_exec_reuses_probed_connection() -> None:
    """Fix (probe/exec TOCTOU): _call_tool_service must not dial a new
    socket when the caller hands in the probe's already-verified
    connection. Proves the exec-path uses the identity the kernel
    approved, not whoever grabs the UDS name between probe and exec."""
    print("== exec reuses probed connection (no second dial) ==")

    dial_calls = {"n": 0}
    orig_dial = server.transport_dial

    def counting_dial(*a, **kw):
        dial_calls["n"] += 1
        return _FakeSocket()

    server.transport_dial = counting_dial

    # Build a fake held connection that records send/recv.
    sent_frames: list[bytes] = []

    class _HeldSocket:
        family = socket.AF_UNIX
        def __enter__(self): return self
        def __exit__(self, *e):
            self.close(); return False
        def settimeout(self, t): pass
        def close(self): pass
        def sendall(self, b): sent_frames.append(b)
        def recv(self, n): return b""

    # Stub send_frame/recv_frame to shortcut the protocol.
    orig_send = server.send_frame
    orig_recv = server.recv_frame
    orig_peercred = server._read_peercred
    server.send_frame = lambda conn, data, **kw: sent_frames.append(data)
    server.recv_frame = lambda conn, **kw: (
        b'{"req_id":1,"status":"ok","result":{},"error":"","t_ms":0}'
    )
    server._read_peercred = lambda conn: (4242, os.geteuid())

    tool = _tool(tool_id=9200)
    held = _HeldSocket()
    try:
        resp = server._call_tool_service(
            tool, req_id=1, agent_id="a1", payload={},
            conn=held, probed_pid=4242, probed_identity=None,
        )
    finally:
        server.transport_dial = orig_dial
        server.send_frame = orig_send
        server.recv_frame = orig_recv
        server._read_peercred = orig_peercred

    check(dial_calls["n"] == 0,
          "transport_dial was NOT called when conn was provided "
          f"(actual calls={dial_calls['n']})")
    check(resp.get("status") == "ok",
          f"reused-connection exec returned ok (got {resp!r})")


def main() -> int:
    test_denies_after_probe_dial_failure_with_warm_cache()
    test_identity_race_does_not_cache_mismatched_digest()
    test_identity_race_exhausts_retries_and_does_not_cache()
    test_interpreter_backend_composite_hash_reflects_script_change()
    test_probe_refreshes_script_digest_from_disk()
    test_reused_probe_socket_detects_identity_drift()
    test_uid_mismatch_rejects_probe()
    test_exec_reuses_probed_connection()
    print()
    if FAILED:
        print(f"FAILED: {FAILED} assertion(s)")
        return 1
    print("all probe unit checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
