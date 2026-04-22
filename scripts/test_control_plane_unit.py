#!/usr/bin/env python3
"""Minimal in-process verification hooks for the control-plane boundaries.

Covers the four boundary cases called out by the Phase 6 spec:

  1. illegal ticket transition        (session_store)
  2. stale rebind / catalog_stale     (reason taxonomy + response shape)
  3. identity mismatch                (reason taxonomy + response shape)
  4. restart / reconcile boundary     (ReconcileAction plan over manifests)

No pytest / unittest: follows the same custom-`check()` style as
scripts/test_probe_unit.py so the repo stays framework-free.

Run with:  python3 scripts/test_control_plane_unit.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "mcpd"))

import server  # noqa: E402
import session_store  # noqa: E402
from client.kernel_mcp import reasons as reason_taxonomy  # noqa: E402
from manifest_loader import ToolManifest  # noqa: E402


FAILED = 0


def check(cond: bool, msg: str) -> None:
    global FAILED
    if cond:
        print(f"  ok: {msg}")
    else:
        print(f"  FAIL: {msg}")
        FAILED += 1


def _stub_tool(tid: int, *, mh: str = "mh", bf: str = "bf") -> ToolManifest:
    return ToolManifest(
        tool_id=tid, name=f"t{tid}", app_id="a", app_name="A",
        risk_tags=[], risk_flags=0, description="",
        input_schema={}, examples=[], path_semantics={},
        approval_policy={}, transport="uds_rpc",
        endpoint=f"/tmp/t{tid}", operation="op", timeout_ms=1000,
        manifest_hash=mh, binding_fingerprint=bf,
        script_digest="", script_path="",
    )


def _reset_pending() -> None:
    """Drop any leftover _pending_approvals records so each test starts clean."""
    with session_store._approval_lock:
        session_store._pending_approvals.clear()


# ---------------------------------------------------------------------------
# 1. Illegal ticket transition
# ---------------------------------------------------------------------------
def test_illegal_ticket_transition() -> None:
    print("[1] illegal ticket transition")
    _reset_pending()
    session_store.remember_pending_approval(
        ticket_id=101, session_id="s", req_id=1, agent_id="a",
        binding_hash=1, binding_epoch=1, app_id="x", tool_id=1,
        payload={}, tool_hash="",
    )
    # PENDING -> DENIED is legal; DENIED -> APPROVED is not.
    session_store.deny_pending_approval(101, trigger="test_deny")
    raised = False
    try:
        session_store.approve_pending_approval(101, trigger="should_fail")
    except ValueError as exc:
        raised = True
        check(
            "illegal ticket transition" in str(exc),
            f"ValueError names the illegal transition (msg={exc!r})",
        )
    check(raised, "DENIED -> APPROVED is rejected by _transition_ticket")

    # State of the surviving record should still be DENIED — the illegal
    # call must not have corrupted it.
    with session_store._approval_lock:
        rec = session_store._pending_approvals.get(101)
    check(rec is not None, "pending entry still present after rejected transition")
    check(
        rec and rec.get("state") is session_store.TicketState.DENIED,
        f"state remains DENIED (got {rec and rec.get('state')})",
    )
    _reset_pending()


# ---------------------------------------------------------------------------
# 2. Stale rebind / catalog_stale
# ---------------------------------------------------------------------------
def test_stale_rebind_taxonomy_and_shape() -> None:
    print("[2] stale rebind case")
    # The wire string catalog_stale_rebind_required must classify as BINDING
    # so that both kernel- and mcpd-side greps see the same category.
    cat = reason_taxonomy.classify(reason_taxonomy.CATALOG_STALE.name)
    check(
        cat is reason_taxonomy.ReasonCategory.BINDING,
        f"catalog_stale -> category=BINDING (got {cat})",
    )
    # The rejection envelope built by mcpd for a kernel-issued stale DENY
    # must carry the exact reason the llm-app rebind path keys off of.
    resp = server._build_rejection_response(
        req_id=77, decision="DENY",
        reason=reason_taxonomy.CATALOG_STALE.name,
        error_message=f"kernel arbitration denied: {reason_taxonomy.CATALOG_STALE.name}",
        ticket_id=0,
    )
    check(resp["decision"] == "DENY", "decision field is DENY")
    check(resp["reason"] == "catalog_stale_rebind_required",
          f"reason is byte-equal (got {resp['reason']})")
    check(resp["status"] == "error", "status=error")
    check(resp["result"] == {}, "empty result")
    check(
        set(resp) == {
            "req_id", "status", "result", "error", "t_ms",
            "decision", "reason", "ticket_id",
        },
        "response envelope field set",
    )


# ---------------------------------------------------------------------------
# 3. Identity mismatch
# ---------------------------------------------------------------------------
def test_identity_mismatch_categories() -> None:
    print("[3] identity mismatch cases")
    # All three serving-/logical-identity denials must land in IDENTITY.
    for name in (
        reason_taxonomy.HASH_MISMATCH.name,
        reason_taxonomy.BINARY_MISMATCH.name,
        reason_taxonomy.PROBE_FAILED.name,
    ):
        cat = reason_taxonomy.classify(name)
        check(
            cat is reason_taxonomy.ReasonCategory.IDENTITY,
            f"{name} -> category=IDENTITY (got {cat})",
        )
    # Every kernel-emitted reason name must round-trip through BY_NAME —
    # otherwise we would silently log category=unknown at runtime.
    for r in (
        reason_taxonomy.ALLOW, reason_taxonomy.ALLOW_APPROVED,
        reason_taxonomy.AGENT_UNKNOWN, reason_taxonomy.APPROVAL_MISSING,
        reason_taxonomy.APPROVAL_REQUIRED, reason_taxonomy.APPROVAL_UNAVAILABLE,
        reason_taxonomy.HASH_MISMATCH, reason_taxonomy.BINARY_MISMATCH,
        reason_taxonomy.BINDING_MISMATCH, reason_taxonomy.CATALOG_STALE,
        reason_taxonomy.TICKET_PENDING, reason_taxonomy.TICKET_DENIED,
        reason_taxonomy.TICKET_UNKNOWN, reason_taxonomy.TICKET_CONSUMED,
        reason_taxonomy.TICKET_SCOPE_MISMATCH,
        reason_taxonomy.TICKET_BINDING_MISMATCH,
        reason_taxonomy.TICKET_HASH_MISMATCH,
        reason_taxonomy.USER_DECLINED, reason_taxonomy.PROBE_FAILED,
    ):
        check(
            reason_taxonomy.BY_NAME.get(r.name) is r,
            f"BY_NAME[{r.name}] round-trips",
        )


# ---------------------------------------------------------------------------
# 4. Restart / reconcile boundary
# ---------------------------------------------------------------------------
def test_reconcile_plan() -> None:
    print("[4] restart / reconcile boundary")
    A = server.ReconcileAction
    prev = {
        1: _stub_tool(1, mh="mh1", bf="bf1"),  # unchanged
        2: _stub_tool(2, mh="mh2", bf="bf2"),  # semantic only
        3: _stub_tool(3, mh="mh3", bf="bf3"),  # binding only
        4: _stub_tool(4, mh="mh4", bf="bf4"),  # both change -> binding-move wins
        5: _stub_tool(5, mh="mh5", bf="bf5"),  # disappears
    }
    new = {
        1: _stub_tool(1, mh="mh1", bf="bf1"),
        2: _stub_tool(2, mh="mh2_NEW", bf="bf2"),
        3: _stub_tool(3, mh="mh3", bf="bf3_NEW"),
        4: _stub_tool(4, mh="mh4_NEW", bf="bf4_NEW"),
        6: _stub_tool(6, mh="mh6", bf="bf6"),  # appears
    }
    plan = server._plan_reconcile(prev, new)
    expected = {
        1: A.KEEP,
        2: A.RE_REGISTER_SEMANTIC,
        3: A.RE_REGISTER_BINDING_MOVE,
        4: A.RE_REGISTER_BINDING_MOVE,  # binding move must dominate
        5: A.REMOVE,
        6: A.ADD,
    }
    for tid, exp in expected.items():
        got = plan.get(tid)
        check(got is exp, f"tool={tid} action={got and got.value} (expected {exp.value})")
    # Empty reload over empty previous must produce no actions — and
    # specifically no spurious KEEP entries for tools that don't exist.
    check(server._plan_reconcile({}, {}) == {}, "empty->empty yields no actions")


def test_approval_reply_preserves_pending_on_non_allow_replay() -> None:
    print("[5] approval replay preserves pending on non-ALLOW")
    _reset_pending()
    session_store.remember_pending_approval(
        ticket_id=202, session_id="sess", req_id=9, agent_id="ag",
        binding_hash=11, binding_epoch=22, app_id="app", tool_id=7,
        payload={"x": 1}, tool_hash="",
    )

    originals = {
        "resolve_session": server.resolve_session,
        "session_binding": server.session_binding,
        "_approval_decide": server._approval_decide,
        "_handle_tool_exec": server._handle_tool_exec,
        "send_frame": server.send_frame,
    }
    frames = []

    try:
        peer = session_store.PeerIdentity(pid=1, uid=2, gid=3)
        server.resolve_session = lambda session_id, _peer: {  # type: ignore[assignment]
            "session_id": session_id,
            "agent_id": "ag",
            "peer": peer,
            "binding_hash": 11,
            "binding_epoch": 22,
            "catalog_epoch": 1,
        }
        server.session_binding = lambda session: session_store.AgentBinding(  # type: ignore[assignment]
            peer=session["peer"], binding_hash=11, binding_epoch=22, catalog_epoch=1
        )
        server._approval_decide = lambda **_kw: None  # type: ignore[assignment]
        server._handle_tool_exec = lambda req: {  # type: ignore[assignment]
            "req_id": req["req_id"],
            "status": "error",
            "result": {},
            "error": "kernel arbitration denied: catalog_stale_rebind_required",
            "t_ms": 0,
            "decision": "DENY",
            "reason": reason_taxonomy.CATALOG_STALE.name,
            "ticket_id": 202,
        }
        server.send_frame = lambda _conn, data, **_kw: frames.append(data)  # type: ignore[assignment]

        server._handle_sys_approval_reply(
            object(),
            {
                "session_id": "sess",
                "ticket_id": 202,
                "decision": "approve",
                "reason": "approved in test",
                "ttl_ms": 1000,
            },
            peer,
            0.0,
        )
    finally:
        server.resolve_session = originals["resolve_session"]  # type: ignore[assignment]
        server.session_binding = originals["session_binding"]  # type: ignore[assignment]
        server._approval_decide = originals["_approval_decide"]  # type: ignore[assignment]
        server._handle_tool_exec = originals["_handle_tool_exec"]  # type: ignore[assignment]
        server.send_frame = originals["send_frame"]  # type: ignore[assignment]

    pending = session_store.peek_pending_approval(202)
    resp = __import__("json").loads(frames[-1].decode("utf-8"))
    check(resp.get("reason") == reason_taxonomy.CATALOG_STALE.name,
          f"replay returned the expected non-ALLOW reason (got {resp.get('reason')})")
    check(
        pending.get("state") is session_store.TicketState.APPROVED,
        f"pending ticket restored as APPROVED (got {pending.get('state')})",
    )
    _reset_pending()


def test_reconcile_unregister_failure_is_fail_closed() -> None:
    print("[6] reconcile unregister failure is fail-closed")
    tool = _stub_tool(303, mh="mh303_new", bf="bf303_new")
    A = server.ReconcileAction
    called = {"register": False}

    class _FailingClient:
        def unregister_tool(self, tool_id: int) -> None:
            raise RuntimeError(f"boom tool={tool_id}")

    original_register = server._register_tool_with_kernel
    original_cache = dict(server._backend_hash_cache)
    try:
        server._backend_hash_cache.clear()
        server._backend_hash_cache[303] = (55, ("exe", 1, 2, 3, 4), "cached")
        server._register_tool_with_kernel = lambda _tool: called.__setitem__("register", True)  # type: ignore[assignment]
        raised = False
        try:
            server._apply_reconcile_action(
                _FailingClient(),
                303,
                A.RE_REGISTER_BINDING_MOVE,
                tool,
            )
        except RuntimeError as exc:
            raised = True
            check(
                "kernel unregister did not complete" in str(exc),
                f"error names fail-closed unregister boundary (msg={exc!r})",
            )
        check(raised, "binding-move unregister failure aborts reconcile")
        check(not called["register"], "register_tool was not called after unregister failure")
        check(303 in server._backend_hash_cache, "cache entry was preserved on failed unregister")
    finally:
        server._register_tool_with_kernel = original_register  # type: ignore[assignment]
        server._backend_hash_cache.clear()
        server._backend_hash_cache.update(original_cache)


def main() -> int:
    test_illegal_ticket_transition()
    test_stale_rebind_taxonomy_and_shape()
    test_identity_mismatch_categories()
    test_reconcile_plan()
    test_approval_reply_preserves_pending_on_non_allow_replay()
    test_reconcile_unregister_failure_is_fail_closed()
    print()
    if FAILED:
        print(f"FAILED: {FAILED} check(s)")
        return 1
    print("all control-plane unit checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
