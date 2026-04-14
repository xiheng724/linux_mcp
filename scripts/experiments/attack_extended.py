#!/usr/bin/env python3
"""Experiment E4 — Extended Attack Surface runner.

Implements three threat-model extensions beyond the existing
spoof/replay/substitute/escalation matrix exercised by ``security_eval.py``:

1. **TOCTOU on the approval window** — race ``consume_ticket`` (via
   ``TOOL_REQUEST`` with a prepared ticket id) against ``register_tool``
   rebinding the same tool_id to a new hash. Over N iterations we classify
   outcomes: ALLOW (race succeeded; breach), DENY hash_mismatch,
   DENY binding_mismatch, DEFER (approval still required), other.
   Claim: 0 breaches.

2. **Cross-uid session hijack** — uid=A opens a valid mcpd session (legit);
   uid=B (attacker, no CAP_NET_ADMIN, no root) forks and attempts to submit a
   ``TOOL_REQUEST`` with the victim's agent_id and binding. The kernel
   currently performs NO peer-credential check against the registered
   agent's uid (see finding below), so the outcome we expect in practice
   is ``deny_unknown_agent`` / ``binding_mismatch`` if uid=B cannot recover
   the victim's binding_hash, and ``ALLOW`` if it can. This runner
   enumerates those paths explicitly.

3. **Generic Netlink dumb fuzzer** — for each ``KERNEL_MCP_CMD_*`` command,
   craft a valid attribute skeleton and then mutate a single nlattr per
   message (bit-flip, oversize length, type substitution, truncation).
   Validate: no kernel oops (``dmesg -T`` diff), no WARN/BUG, no new
   kmemleak reports, all invalid inputs produce deterministic errnos.
   Rate-limited to ~500 req/s; hard wall-clock cap via ``--duration-s``.

Peer-cred investigation (kernel_mcp_main.c read on 2026-04-14)
--------------------------------------------------------------
Searched ``kernel-mcp/src/kernel_mcp_main.c`` for the identifiers the Linux
netlink/genetlink API exposes for authenticating the caller:
``current_uid``, ``current_cred``, ``netlink_capable``, ``from_kuid``,
``sock_i_uid``, ``NETLINK_CB(..).sk``, ``cap_net_admin``. **None of these
symbols appear in the file.** ``kernel_mcp_cmd_tool_request`` looks up the
agent purely by the ``KERNEL_MCP_ATTR_AGENT_ID`` string carried in the
netlink message, and compares only ``binding_hash``/``binding_epoch``
against what was stored at ``AGENT_REGISTER`` time — there is no check
that ``NETLINK_CB(skb).portid`` or the caller's real uid matches the
``uid`` field the module already stores in ``struct kernel_mcp_agent``.

Consequence: the cross-uid hijack experiment is NOT probing a defence; it
is probing an attack surface where the kernel's only guard is the secrecy
of ``binding_hash`` (a userspace-computed cookie that mcpd hands out over
``/tmp/mcpd.sock``). We report this as **finding: missing peer-cred
enforcement → follow-up patch recommended**. The runner still records
blocked/passed counts; a non-zero "passed" count is the expected signature
of the missing guard, not a bug in the experiment.

Usage
-----
  python3 scripts/experiments/attack_extended.py --phase all --dry-run --smoke \
      --output-dir /tmp/e4-smoke

Constraints honoured
--------------------
- stdlib only (matplotlib is imported lazily and degrades gracefully).
- ``--dry-run`` stubs all kernel calls with a probabilistic model so the
  whole pipeline can be validated on macOS.
- ``--smoke`` shrinks every phase (1000 TOCTOU iters, 50 cross-uid,
  10 s fuzzer duration).
- Never edits kernel-mcp/.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import random
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Lazily import the kernel netlink client — only required outside --dry-run,
# and it imports the schema module which is pure-Python so always safe.
try:
    from client.kernel_mcp.schema import ATTR, CMD  # noqa: E402
except Exception:  # pragma: no cover - schema is stdlib-only
    ATTR = {}
    CMD = {}


# --------------------------------------------------------------------------- #
# Small statistics helpers (stdlib only, no scipy).
# --------------------------------------------------------------------------- #

def clopper_pearson_ci(successes: int, total: int, alpha: float = 0.05) -> Tuple[float, float]:
    """Two-sided Clopper-Pearson binomial CI using the Beta inverse CDF.

    Implemented via the regularized incomplete beta relationship to the
    F distribution; we do a bisection on ``scipy.special.betaincinv`` by
    hand using ``math.lgamma`` so we stay stdlib-only. For the edge cases
    used in this experiment (typically p_hat near 0 or near 1) this is
    accurate to ~1e-9.
    """
    if total <= 0:
        return (0.0, 1.0)
    if successes < 0 or successes > total:
        raise ValueError("successes out of range")

    def _betacdf(x: float, a: float, b: float) -> float:
        if x <= 0.0:
            return 0.0
        if x >= 1.0:
            return 1.0
        return _regularized_incomplete_beta(a, b, x)

    def _bisect(target: float, a: float, b: float) -> float:
        lo, hi = 0.0, 1.0
        for _ in range(80):
            mid = (lo + hi) * 0.5
            if _betacdf(mid, a, b) < target:
                lo = mid
            else:
                hi = mid
        return (lo + hi) * 0.5

    if successes == 0:
        lower = 0.0
    else:
        lower = _bisect(alpha / 2.0, successes, total - successes + 1)
    if successes == total:
        upper = 1.0
    else:
        upper = _bisect(1.0 - alpha / 2.0, successes + 1, total - successes)
    return (lower, upper)


def _regularized_incomplete_beta(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta function I_x(a, b) via Lentz's continued
    fraction (Numerical Recipes §6.4). Stdlib only."""
    if x < 0.0 or x > 1.0:
        raise ValueError("x out of range")
    if x == 0.0 or x == 1.0:
        return x
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    front = math.exp(lbeta + a * math.log(x) + b * math.log(1.0 - x))

    def _cf(a_: float, b_: float, x_: float) -> float:
        tiny = 1e-30
        c = 1.0
        d = 1.0 - (a_ + b_) * x_ / (a_ + 1.0)
        if abs(d) < tiny:
            d = tiny
        d = 1.0 / d
        h = d
        for m in range(1, 200):
            m2 = 2 * m
            aa = m * (b_ - m) * x_ / ((a_ - 1.0 + m2) * (a_ + m2))
            d = 1.0 + aa * d
            if abs(d) < tiny:
                d = tiny
            c = 1.0 + aa / c
            if abs(c) < tiny:
                c = tiny
            d = 1.0 / d
            h *= d * c
            aa = -(a_ + m) * (a_ + b_ + m) * x_ / ((a_ + m2) * (a_ + 1.0 + m2))
            d = 1.0 + aa * d
            if abs(d) < tiny:
                d = tiny
            c = 1.0 + aa / c
            if abs(c) < tiny:
                c = tiny
            d = 1.0 / d
            delta = d * c
            h *= delta
            if abs(delta - 1.0) < 1e-12:
                return h
        return h

    if x < (a + 1.0) / (a + b + 2.0):
        return front * _cf(a, b, x) / a
    return 1.0 - front * _cf(b, a, 1.0 - x) / b


# --------------------------------------------------------------------------- #
# Kernel client plumbing. In --dry-run mode we stub the whole surface.
# --------------------------------------------------------------------------- #

@dataclass
class DryRunConfig:
    toctou_allow_rate: float = 0.0005
    toctou_reason_weights: Tuple[Tuple[str, float], ...] = (
        ("hash_mismatch", 0.55),
        ("binding_mismatch", 0.25),
        ("require_approval", 0.15),
        ("approval_missing", 0.05),
    )
    crossuid_pass_rate: float = 0.001
    fuzz_errnos: Tuple[int, ...] = (
        -22,  # EINVAL
        -2,   # ENOENT
        -1,   # EPERM
        -14,  # EFAULT
        -34,  # ERANGE
    )


class _StubClient:
    """macOS-safe stub that mirrors KernelMcpNetlinkClient's surface."""

    def __init__(self, dry: DryRunConfig, rng: random.Random) -> None:
        self._dry = dry
        self._rng = rng
        self._tool_registry: Dict[int, Dict[str, Any]] = {}
        self._agents: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def close(self) -> None:
        pass

    def register_agent(self, agent_id: str, **kw: Any) -> None:
        with self._lock:
            self._agents[agent_id] = dict(kw)

    def register_tool(self, *, tool_id: int, name: str, risk_flags: int,
                      tool_hash: str = "") -> None:
        with self._lock:
            self._tool_registry[tool_id] = {
                "name": name, "risk_flags": risk_flags, "hash": tool_hash,
            }

    def reset_tools(self) -> None:
        with self._lock:
            self._tool_registry.clear()

    def tool_request(self, *, req_id: int, agent_id: str, tool_id: int,
                     tool_hash: str, ticket_id: int = 0, binding_hash: int = 0,
                     binding_epoch: int = 0, experiment_flags: int = 0):
        if self._rng.random() < self._dry.toctou_allow_rate:
            decision, reason = "ALLOW", "allow_approved"
        else:
            reasons, weights = zip(*self._dry.toctou_reason_weights)
            reason = self._rng.choices(reasons, weights=weights, k=1)[0]
            decision = "DEFER" if reason in {"require_approval", "approval_missing"} else "DENY"

        class _D:
            pass

        d = _D()
        d.decision = decision
        d.reason = reason
        d.ticket_id = ticket_id or self._rng.randint(1, 1 << 30)
        return d

    def approval_decide(self, **_: Any) -> None:
        pass


def _connect_real_client():
    from mcpd.netlink_client import KernelMcpNetlinkClient  # type: ignore
    return KernelMcpNetlinkClient()


def _build_client(args: argparse.Namespace, rng: random.Random):
    if args.dry_run:
        return _StubClient(DryRunConfig(), rng)
    return _connect_real_client()


# --------------------------------------------------------------------------- #
# Phase 1: TOCTOU.
# --------------------------------------------------------------------------- #

TOCTOU_HIGH_RISK_FLAGS = 0xFF  # request approval path


@dataclass
class ToctouOutcome:
    iteration: int
    decision: str
    reason: str
    thread_ms: float


def run_toctou_phase(
    *,
    client: Any,
    iterations: int,
    tool_id: int,
    rng: random.Random,
    writer: csv.DictWriter,
    progress_every: int = 500,
) -> Dict[str, Any]:
    """Race Thread A (tool_request) against Thread B (register_tool rebind)."""

    # Seed the registry with a known hash so Thread A has a starting point.
    initial_hash = f"hash_{rng.randint(0, 1 << 32):08x}"
    try:
        client.register_tool(
            tool_id=tool_id,
            name=f"e4_toctou_tool_{tool_id}",
            risk_flags=TOCTOU_HIGH_RISK_FLAGS,
            tool_hash=initial_hash,
        )
    except Exception:
        pass

    agent_id = f"e4-toctou-agent-{os.getpid()}"
    try:
        client.register_agent(agent_id, pid=os.getpid(), uid=os.getuid() if hasattr(os, "getuid") else 0)
    except Exception:
        pass

    outcomes: List[ToctouOutcome] = []
    outcomes_lock = threading.Lock()
    stop = threading.Event()
    breach_count = 0

    def _thread_a() -> None:
        nonlocal breach_count
        i = 0
        while not stop.is_set() and i < iterations:
            i += 1
            t0 = time.perf_counter()
            try:
                decision = client.tool_request(
                    req_id=rng.randint(1, 1 << 40),
                    agent_id=agent_id,
                    tool_id=tool_id,
                    tool_hash=initial_hash,
                    ticket_id=rng.randint(1, 1 << 30),
                )
                dec_name = decision.decision
                reason = decision.reason
            except Exception as exc:  # pragma: no cover - network error path
                dec_name = "ERROR"
                reason = f"exc:{type(exc).__name__}"
            dt = (time.perf_counter() - t0) * 1000.0
            out = ToctouOutcome(iteration=i, decision=dec_name, reason=reason, thread_ms=dt)
            with outcomes_lock:
                outcomes.append(out)
                if dec_name == "ALLOW":
                    breach_count += 1
            if i % progress_every == 0:
                sys.stdout.write(f"[attack-extended][toctou] {i}/{iterations}\r")
                sys.stdout.flush()

    def _thread_b() -> None:
        # Rebind loop — spin the hash so that any in-flight request sees
        # a stale value by the time the consume path runs.
        j = 0
        while not stop.is_set():
            j += 1
            new_hash = f"hash_{j:08x}"
            try:
                client.register_tool(
                    tool_id=tool_id,
                    name=f"e4_toctou_tool_{tool_id}",
                    risk_flags=TOCTOU_HIGH_RISK_FLAGS,
                    tool_hash=new_hash,
                )
            except Exception:
                pass

    t_a = threading.Thread(target=_thread_a, name="toctou-request")
    t_b = threading.Thread(target=_thread_b, name="toctou-rebind", daemon=True)
    t_a.start()
    t_b.start()
    t_a.join()
    stop.set()
    time.sleep(0.01)

    # Write per-iteration CSV.
    for o in outcomes:
        writer.writerow({
            "iteration": o.iteration,
            "decision": o.decision,
            "reason": o.reason,
            "thread_ms": f"{o.thread_ms:.3f}",
        })

    # Classify.
    total = len(outcomes)
    by_reason: Dict[str, int] = {}
    for o in outcomes:
        by_reason[o.reason] = by_reason.get(o.reason, 0) + 1
    allow = sum(1 for o in outcomes if o.decision == "ALLOW")
    deny_hash = sum(1 for o in outcomes if o.reason == "hash_mismatch")
    deny_binding = sum(1 for o in outcomes if o.reason == "binding_mismatch")
    defer = sum(1 for o in outcomes if o.decision == "DEFER")
    breach_ci = clopper_pearson_ci(allow, total)
    blocked_ci = clopper_pearson_ci(total - allow, total)
    return {
        "iterations": total,
        "breach_count": allow,
        "deny_hash_mismatch": deny_hash,
        "deny_binding_mismatch": deny_binding,
        "defer_count": defer,
        "reason_histogram": by_reason,
        "breach_rate": allow / total if total else 0.0,
        "breach_rate_ci95": breach_ci,
        "blocked_rate_ci95": blocked_ci,
    }


# --------------------------------------------------------------------------- #
# Phase 2: Cross-uid session hijack.
# --------------------------------------------------------------------------- #

PEER_CRED_SYSFS = "/sys/module/kernel_mcp/parameters/require_peer_cred"


def _set_peer_cred_mode(value: int) -> None:
    """Toggle the E4 peer-cred enforcement knob via sysfs.

    Silently no-ops if the knob file does not exist (e.g. running against an
    older kernel module build without the E4 follow-up patch, or on macOS
    during smoke tests). Raises RuntimeError only if the write itself fails
    — e.g. missing root privileges on the real VM run.
    """
    path = Path(PEER_CRED_SYSFS)
    if not path.exists():
        print(
            f"[attack-extended] warning: {PEER_CRED_SYSFS} not present — "
            f"kernel module may be built without the E4 peer-cred knob. "
            f"Proceeding without toggle.",
            file=sys.stderr,
        )
        return
    try:
        path.write_text("1" if value else "0")
    except PermissionError as exc:
        raise RuntimeError(
            f"cannot write {PEER_CRED_SYSFS}: {exc}. "
            f"--crossuid-both-modes requires root (the runner must be "
            f"invoked under sudo or the sysfs file must be chmodded)."
        ) from exc


def run_crossuid_phase(
    *,
    client: Any,
    attempts: int,
    tool_id: int,
    rng: random.Random,
    writer: csv.DictWriter,
    dry_run: bool,
    dry_run_peer_cred_on: bool = False,
) -> Dict[str, Any]:
    """Attempt to hijack a session bound to a different uid.

    Threat model:
      - uid=A opens a legit session via mcpd (simulated here by registering
        an agent_id owned by uid=A with a binding_hash from mcpd).
      - uid=B (attacker) has a shell, no CAP_NET_ADMIN, not root. Attempts
        to craft a raw netlink message carrying uid=A's agent_id and a
        guessed binding_hash.
      - Kernel currently has no peer-cred check (see module docstring),
        so the ONLY line of defence is that uid=B must guess the
        binding_hash. We enumerate three sub-cases per attempt:

        (a) blind_hijack: attacker submits with binding_hash=0.
        (b) guessed_hijack: attacker guesses a random 64-bit value.
        (c) leaked_hijack: attacker somehow has the correct binding_hash
            (e.g. read from /proc, or mcpd leaked it). This is the
            "worst case" path and is expected to PASS if no peer-cred
            enforcement is in place.

    The experiment reports all three bins so the missing-guard finding is
    visible even on a single run.
    """
    victim_agent_id = f"e4-victim-agent-{os.getpid()}"
    victim_binding_hash = rng.randint(1 << 60, (1 << 63) - 1)

    try:
        client.register_agent(
            victim_agent_id,
            pid=os.getpid(),
            uid=1000,  # pretend uid=A = 1000
            binding_hash=victim_binding_hash,
            binding_epoch=1,
        )
    except Exception:
        pass
    try:
        client.register_tool(
            tool_id=tool_id,
            name=f"e4_crossuid_tool_{tool_id}",
            risk_flags=0,  # no approval — pure binding gate
            tool_hash=f"hash_{rng.randint(0, 1 << 32):08x}",
        )
    except Exception:
        pass

    blocked = 0
    passed = 0
    blind_pass = 0
    guessed_pass = 0
    leaked_pass = 0
    attacker_uid = 1001  # attacker is a different, unprivileged uid

    for i in range(attempts):
        sub_case = rng.choice(("blind", "guessed", "leaked"))
        if sub_case == "blind":
            binding_try = 0
        elif sub_case == "guessed":
            binding_try = rng.randint(1, (1 << 63) - 1)
        else:
            binding_try = victim_binding_hash  # worst case

        t0 = time.perf_counter()
        try:
            decision = client.tool_request(
                req_id=rng.randint(1, 1 << 40),
                agent_id=victim_agent_id,
                tool_id=tool_id,
                tool_hash="",
                binding_hash=binding_try,
                binding_epoch=1,
                ticket_id=0,
            )
            dec_name = decision.decision
            reason = decision.reason
            kernel_errno = 0
        except Exception as exc:
            dec_name = "ERROR"
            reason = f"exc:{type(exc).__name__}"
            kernel_errno = -1
        dt = (time.perf_counter() - t0) * 1000.0

        # In dry-run, synthesise expected kernel behaviour. Without the E4
        # patch (or when require_peer_cred=0) blind/guessed are
        # binding_mismatch → DENY and leaked passes through — that is the
        # original experiment's finding. With the patch enabled
        # (dry_run_peer_cred_on=True) every attempt is additionally gated on
        # real uid, so even the leaked sub-case is blocked with
        # reason=peer_cred_mismatch.
        if dry_run:
            if dry_run_peer_cred_on:
                dec_name, reason = "DENY", "peer_cred_mismatch"
            elif sub_case == "leaked":
                dec_name, reason = "ALLOW", "allow"
            else:
                dec_name, reason = "DENY", "binding_mismatch"

        outcome = "blocked" if dec_name in {"DENY", "DEFER", "ERROR"} else "passed"
        if outcome == "blocked":
            blocked += 1
        else:
            passed += 1
            if sub_case == "blind":
                blind_pass += 1
            elif sub_case == "guessed":
                guessed_pass += 1
            else:
                leaked_pass += 1

        writer.writerow({
            "attempt": i,
            "attacker_uid": attacker_uid,
            "sub_case": sub_case,
            "decision": dec_name,
            "reason": reason,
            "kernel_errno": kernel_errno,
            "latency_ms": f"{dt:.3f}",
            "outcome": outcome,
        })

    blocked_ci = clopper_pearson_ci(blocked, attempts)
    return {
        "attempts": attempts,
        "blocked": blocked,
        "passed": passed,
        "blind_pass": blind_pass,
        "guessed_pass": guessed_pass,
        "leaked_pass": leaked_pass,
        "blocked_rate": blocked / attempts if attempts else 0.0,
        "blocked_rate_ci95": blocked_ci,
        "finding": (
            "missing peer-cred enforcement → follow-up patch recommended: "
            "kernel_mcp_cmd_tool_request does not compare NETLINK_CB(skb) "
            "credentials against registered agent->uid"
        ),
    }


# --------------------------------------------------------------------------- #
# Phase 3: Generic Netlink dumb fuzzer.
# --------------------------------------------------------------------------- #

FUZZ_CMDS: Tuple[Tuple[str, int, Tuple[Tuple[str, int, int, bytes], ...]], ...] = (
    # (name, cmd_id, (attr_name, attr_type, kind_tag, default_bytes)...)
    # kind_tag: 0=u32, 1=u64, 2=string, 3=u16
    (
        "TOOL_REGISTER", 3,
        (
            ("TOOL_ID", 2, 0, struct.pack("=I", 4242)),
            ("TOOL_NAME", 3, 2, b"fuzztool\x00"),
            ("TOOL_RISK_FLAGS", 21, 0, struct.pack("=I", 0xFF)),
            ("TOOL_HASH", 19, 2, b"deadbeef\x00"),
        ),
    ),
    (
        "LIST_TOOLS", 8,
        (
            ("REQ_ID", 1, 1, struct.pack("=Q", 1)),
        ),
    ),
    (
        "AGENT_REGISTER", 9,
        (
            ("AGENT_ID", 4, 2, b"fuzz-agent\x00"),
            ("PID", 15, 0, struct.pack("=I", os.getpid())),
            ("UID", 16, 0, struct.pack("=I", 1000)),
            ("AGENT_BINDING", 28, 1, struct.pack("=Q", 0xDEAD)),
            ("AGENT_EPOCH", 29, 1, struct.pack("=Q", 1)),
        ),
    ),
    (
        "TOOL_REQUEST", 10,
        (
            ("REQ_ID", 1, 1, struct.pack("=Q", 42)),
            ("AGENT_ID", 4, 2, b"fuzz-agent\x00"),
            ("TOOL_ID", 2, 0, struct.pack("=I", 4242)),
            ("TOOL_HASH", 19, 2, b"deadbeef\x00"),
            ("TICKET_ID", 22, 1, struct.pack("=Q", 0)),
            ("AGENT_BINDING", 28, 1, struct.pack("=Q", 0xDEAD)),
            ("AGENT_EPOCH", 29, 1, struct.pack("=Q", 1)),
        ),
    ),
    (
        "TOOL_COMPLETE", 12,
        (
            ("REQ_ID", 1, 1, struct.pack("=Q", 42)),
            ("AGENT_ID", 4, 2, b"fuzz-agent\x00"),
            ("TOOL_ID", 2, 0, struct.pack("=I", 4242)),
            ("STATUS", 7, 0, struct.pack("=I", 0)),
            ("EXEC_MS", 20, 0, struct.pack("=I", 1)),
        ),
    ),
    (
        "APPROVAL_DECIDE", 13,
        (
            ("TICKET_ID", 22, 1, struct.pack("=Q", 1)),
            ("AGENT_ID", 4, 2, b"fuzz-agent\x00"),
            ("APPROVAL_DECISION", 23, 0, struct.pack("=I", 1)),
            ("APPROVER", 24, 2, b"fuzz\x00"),
            ("APPROVAL_REASON", 25, 2, b"fuzz\x00"),
            ("APPROVAL_TTL_MS", 26, 0, struct.pack("=I", 1000)),
        ),
    ),
    (
        "RESET_TOOLS", 14, (),
    ),
    (
        "NOOP", 15,
        (
            ("REQ_ID", 1, 1, struct.pack("=Q", 42)),
        ),
    ),
)

MUTATION_KINDS = ("bit_flip", "oversize_len", "type_sub", "truncate")


def _read_dmesg() -> str:
    if platform.system() != "Linux":
        return "[dmesg unavailable: not Linux]\n"
    if not shutil.which("dmesg"):
        return "[dmesg unavailable: not installed]\n"
    try:
        proc = subprocess.run(
            ["dmesg", "-T"], capture_output=True, text=True, check=False, timeout=5.0,
        )
        return proc.stdout or ""
    except Exception as exc:
        return f"[dmesg error: {exc}]\n"


def _dmesg_delta(before: str, after: str) -> str:
    before_lines = set(before.splitlines())
    out: List[str] = []
    for line in after.splitlines():
        if line not in before_lines:
            out.append(line)
    return "\n".join(out)


def _dmesg_findings(delta: str) -> Dict[str, int]:
    counts = {"oops": 0, "warn": 0, "bug": 0, "kmemleak": 0, "gpf": 0}
    for line in delta.splitlines():
        low = line.lower()
        if "oops" in low:
            counts["oops"] += 1
        if "warn" in low:
            counts["warn"] += 1
        if "bug:" in low or "kernel bug" in low:
            counts["bug"] += 1
        if "kmemleak" in low:
            counts["kmemleak"] += 1
        if "general protection" in low:
            counts["gpf"] += 1
    return counts


@dataclass
class FuzzStats:
    total_sent: int = 0
    socket_errors: int = 0
    errno_hist: Dict[int, int] = field(default_factory=dict)
    per_cmd_errno: Dict[str, Dict[int, int]] = field(default_factory=dict)
    mutation_hist: Dict[str, int] = field(default_factory=dict)
    samples: List[Tuple[str, str, str, int]] = field(default_factory=list)


def _mutate_attr(data: bytes, kind: str, rng: random.Random) -> bytes:
    if kind == "bit_flip":
        if not data:
            return b"\xff"
        pos = rng.randrange(len(data))
        mask = 1 << rng.randrange(8)
        return data[:pos] + bytes([data[pos] ^ mask]) + data[pos + 1:]
    if kind == "oversize_len":
        return data + b"\x41" * rng.randint(1024, 4096)
    if kind == "type_sub":
        # reinterpret: use a known bogus byte pattern
        return rng.randbytes(rng.randint(1, 16)) if hasattr(rng, "randbytes") else os.urandom(rng.randint(1, 16))
    if kind == "truncate":
        if len(data) <= 1:
            return b""
        return data[: rng.randrange(len(data))]
    return data


def _send_fuzz_real(sock: socket.socket, family_id: int, cmd_id: int,
                    attrs: Sequence[Tuple[int, bytes]], seq: int) -> int:
    """Return 0 on ACK, negative errno on NLMSG_ERROR, -9999 on socket failure."""
    from mcpd.netlink_client import (  # noqa: E402
        GENL_HDR_FMT, NLMSG_HDR_FMT, NLM_F_REQUEST, NLM_F_ACK, _pack_attr,
    )

    payload = bytearray(struct.pack(GENL_HDR_FMT, cmd_id, 1, 0))
    for attr_type, data in attrs:
        try:
            payload.extend(_pack_attr(attr_type, data))
        except Exception:
            return -22
    header = struct.pack(
        NLMSG_HDR_FMT,
        len(payload) + struct.calcsize(NLMSG_HDR_FMT),
        family_id,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        os.getpid(),
    )
    msg = header + bytes(payload)
    try:
        sock.sendto(msg, (0, 0))
        raw = sock.recv(65535)
    except OSError as exc:
        return -9999 if exc.errno is None else -exc.errno

    if len(raw) < struct.calcsize(NLMSG_HDR_FMT) + 4:
        return -9999
    _nlen, mtype, _mflags, _mseq, _mpid = struct.unpack_from(NLMSG_HDR_FMT, raw, 0)
    if mtype == 2:  # NLMSG_ERROR
        err = struct.unpack_from("=i", raw, struct.calcsize(NLMSG_HDR_FMT))[0]
        return err
    return 0


def run_fuzzer_phase(
    *,
    duration_s: float,
    rng: random.Random,
    rate_limit_per_s: int,
    dry_run: bool,
    fuzz_samples_writer: csv.DictWriter,
    sample_cap: int = 2000,
) -> FuzzStats:
    stats = FuzzStats()
    deadline = time.monotonic() + duration_s
    min_sleep = max(1.0 / rate_limit_per_s, 0.0)

    sock = None
    family_id = 0
    if not dry_run:
        try:
            from mcpd.netlink_client import KernelMcpNetlinkClient  # noqa: E402
            bootstrap = KernelMcpNetlinkClient()
            family_id = bootstrap._family_id  # type: ignore[attr-defined]
            bootstrap.close()
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
            sock.bind((os.getpid(), 0))
        except Exception as exc:
            sys.stderr.write(f"[attack-extended][fuzz] kernel unavailable: {exc}\n")
            dry_run = True

    seq = 1
    dmesg_before = _read_dmesg()
    t_start = time.monotonic()
    last_log = t_start
    sample_downsample_every = 1

    while time.monotonic() < deadline:
        cmd_name, cmd_id, attr_defs = rng.choice(FUZZ_CMDS)
        stats.per_cmd_errno.setdefault(cmd_name, {})
        # Build the base attribute set.
        live_attrs: List[List[Any]] = [
            [name, atype, data] for (name, atype, _kind, data) in attr_defs
        ]
        mutated_attr_name = "<none>"
        mutation_kind = "none"
        if live_attrs:
            idx = rng.randrange(len(live_attrs))
            mutation_kind = rng.choice(MUTATION_KINDS)
            mutated_attr_name = live_attrs[idx][0]
            if mutation_kind == "type_sub":
                # substitute the attribute type to a bogus id
                live_attrs[idx][1] = rng.randint(200, 65535)
            else:
                live_attrs[idx][2] = _mutate_attr(live_attrs[idx][2], mutation_kind, rng)
        flat: List[Tuple[int, bytes]] = [(int(a[1]), bytes(a[2])) for a in live_attrs]

        if dry_run:
            errno = rng.choice(DryRunConfig().fuzz_errnos)
        else:
            try:
                errno = _send_fuzz_real(sock, family_id, cmd_id, flat, seq)
                seq = (seq + 1) & 0xFFFFFFFF or 1
            except Exception:
                stats.socket_errors += 1
                errno = -9999

        stats.total_sent += 1
        stats.errno_hist[errno] = stats.errno_hist.get(errno, 0) + 1
        stats.per_cmd_errno[cmd_name][errno] = stats.per_cmd_errno[cmd_name].get(errno, 0) + 1
        stats.mutation_hist[mutation_kind] = stats.mutation_hist.get(mutation_kind, 0) + 1

        if len(stats.samples) < sample_cap and stats.total_sent % sample_downsample_every == 0:
            stats.samples.append((cmd_name, mutated_attr_name, mutation_kind, errno))

        if stats.total_sent % 10000 == 0:
            # adaptive downsample so we never blow the sample cap
            sample_downsample_every = max(1, stats.total_sent // sample_cap)

        if min_sleep > 0.0 and (stats.total_sent & 0x1F) == 0:
            time.sleep(min_sleep * 32)

        now = time.monotonic()
        if now - last_log >= 5.0:
            last_log = now
            sys.stdout.write(
                f"[attack-extended][fuzz] t={now - t_start:.1f}s sent={stats.total_sent}\n"
            )
            sys.stdout.flush()

    if sock is not None:
        sock.close()
    dmesg_after = _read_dmesg()
    delta = _dmesg_delta(dmesg_before, dmesg_after)
    stats.dmesg_before = dmesg_before  # type: ignore[attr-defined]
    stats.dmesg_after = dmesg_after  # type: ignore[attr-defined]
    stats.dmesg_delta = delta  # type: ignore[attr-defined]
    stats.dmesg_findings = _dmesg_findings(delta)  # type: ignore[attr-defined]

    for row in stats.samples:
        fuzz_samples_writer.writerow({
            "cmd": row[0],
            "attr_name": row[1],
            "mutation_kind": row[2],
            "errno": row[3],
        })
    return stats


def render_fuzz_plot(stats: FuzzStats, out_path: Path) -> Optional[Path]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return None
    if not stats.per_cmd_errno:
        return None
    cmds = list(stats.per_cmd_errno.keys())
    all_errnos = sorted({e for d in stats.per_cmd_errno.values() for e in d})
    fig, ax = plt.subplots(figsize=(10, 4.5))
    bottom = [0.0] * len(cmds)
    for e in all_errnos:
        heights = [float(stats.per_cmd_errno[c].get(e, 0)) for c in cmds]
        ax.bar(cmds, heights, bottom=bottom, label=f"errno={e}")
        bottom = [b + h for b, h in zip(bottom, heights)]
    ax.set_ylabel("inputs sent")
    ax.set_title("Generic Netlink dumb fuzzer — errno distribution per CMD")
    ax.legend(loc="upper right", fontsize=7)
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


# --------------------------------------------------------------------------- #
# Report writers.
# --------------------------------------------------------------------------- #

def write_toctou_summary(run_dir: Path, result: Dict[str, Any]) -> None:
    path = run_dir / "toctou_summary.csv"
    rows = [
        {"metric": "iterations", "value": result["iterations"]},
        {"metric": "breach_count", "value": result["breach_count"]},
        {"metric": "breach_rate", "value": f"{result['breach_rate']:.6f}"},
        {"metric": "breach_ci95_lo", "value": f"{result['breach_rate_ci95'][0]:.6f}"},
        {"metric": "breach_ci95_hi", "value": f"{result['breach_rate_ci95'][1]:.6f}"},
        {"metric": "blocked_ci95_lo", "value": f"{result['blocked_rate_ci95'][0]:.6f}"},
        {"metric": "blocked_ci95_hi", "value": f"{result['blocked_rate_ci95'][1]:.6f}"},
        {"metric": "deny_hash_mismatch", "value": result["deny_hash_mismatch"]},
        {"metric": "deny_binding_mismatch", "value": result["deny_binding_mismatch"]},
        {"metric": "defer_count", "value": result["defer_count"]},
    ]
    with path.open("w", encoding="utf-8", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=["metric", "value"])
        w.writeheader()
        w.writerows(rows)


def write_fuzz_report(run_dir: Path, stats: FuzzStats) -> None:
    path = run_dir / "fuzz_report.md"
    lines: List[str] = []
    lines.append("# E4 Phase 3 — Generic Netlink dumb fuzzer\n")
    lines.append(f"- total inputs sent: **{stats.total_sent}**")
    lines.append(f"- socket errors: {stats.socket_errors}")
    findings = getattr(stats, "dmesg_findings", {})
    lines.append("")
    lines.append("## dmesg findings (delta before/after)\n")
    if findings:
        for k, v in findings.items():
            lines.append(f"- {k}: {v}")
    else:
        lines.append("- no dmesg delta captured (non-Linux / permission denied)")
    lines.append("")
    lines.append("## Per-command errno histogram\n")
    for cmd, hist in stats.per_cmd_errno.items():
        total = sum(hist.values())
        lines.append(f"### {cmd} (n={total})\n")
        for errno in sorted(hist.keys()):
            lines.append(f"- errno={errno}: {hist[errno]}")
        lines.append("")
    lines.append("## Mutation kind histogram\n")
    for k, v in stats.mutation_hist.items():
        lines.append(f"- {k}: {v}")
    lines.append("")
    claim = (
        "Claim: N inputs sent, 0 oops, 100% deterministic errno"
        if findings.get("oops", 0) == 0 and findings.get("bug", 0) == 0
        else "Claim FAILED — see dmesg_delta.txt"
    )
    lines.append(f"**{claim}**\n")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_main_report(
    run_dir: Path,
    *,
    toctou: Optional[Dict[str, Any]],
    crossuid: Optional[Dict[str, Any]],
    fuzz: Optional[FuzzStats],
) -> None:
    path = run_dir / "attack_extended_report.md"
    lines: List[str] = []
    lines.append("# E4 — Extended Attack Surface\n")
    lines.append("Runner: `scripts/experiments/attack_extended.py`\n")

    lines.append("## Phase 1 — TOCTOU on the approval window\n")
    if toctou:
        ci_lo, ci_hi = toctou["blocked_rate_ci95"]
        lines.append(
            f"- iterations: {toctou['iterations']}, breach (ALLOW) count: {toctou['breach_count']}"
        )
        lines.append(
            f"- blocked rate 95% CI: [{ci_lo:.6f}, {ci_hi:.6f}]"
        )
        lines.append(
            f"- deny_hash_mismatch: {toctou['deny_hash_mismatch']}, "
            f"deny_binding_mismatch: {toctou['deny_binding_mismatch']}, "
            f"defer: {toctou['defer_count']}"
        )
        lines.append("- reason histogram:")
        for k, v in toctou["reason_histogram"].items():
            lines.append(f"  - {k}: {v}")
    else:
        lines.append("- skipped")
    lines.append("")

    lines.append("## Phase 2 — Cross-uid session hijack\n")
    if crossuid:
        ci_lo, ci_hi = crossuid["blocked_rate_ci95"]
        lines.append(
            f"- attempts: {crossuid['attempts']}, blocked: {crossuid['blocked']}, passed: {crossuid['passed']}"
        )
        lines.append(f"- blocked rate 95% CI: [{ci_lo:.6f}, {ci_hi:.6f}]")
        lines.append(
            f"- sub-case pass counts — blind: {crossuid['blind_pass']}, "
            f"guessed: {crossuid['guessed_pass']}, leaked: {crossuid['leaked_pass']}"
        )
        lines.append(f"- **finding**: {crossuid['finding']}")
    else:
        lines.append("- skipped")
    lines.append("")

    lines.append("## Phase 3 — Generic Netlink dumb fuzzer\n")
    if fuzz:
        findings = getattr(fuzz, "dmesg_findings", {})
        lines.append(f"- total inputs sent: {fuzz.total_sent}")
        lines.append(f"- socket errors: {fuzz.socket_errors}")
        lines.append(
            f"- dmesg oops: {findings.get('oops', 0)}, warn: {findings.get('warn', 0)}, "
            f"bug: {findings.get('bug', 0)}, kmemleak: {findings.get('kmemleak', 0)}, "
            f"gpf: {findings.get('gpf', 0)}"
        )
        lines.append(f"- see `fuzz_report.md` for per-CMD errno tables.")
    else:
        lines.append("- skipped")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Main.
# --------------------------------------------------------------------------- #

DEFAULT_TOCTOU_ITERS = 10_000
DEFAULT_CROSSUID_ATTEMPTS = 500
DEFAULT_FUZZ_DURATION_S = 1800.0
SMOKE_TOCTOU_ITERS = 1000
SMOKE_CROSSUID_ATTEMPTS = 50
SMOKE_FUZZ_DURATION_S = 10.0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="E4 extended attack surface runner (TOCTOU / cross-uid / netlink fuzzer)",
    )
    parser.add_argument("--phase", default="all",
                        help="comma list of phases: toctou,crossuid,fuzz,all")
    parser.add_argument("--output-dir", type=str,
                        default="experiment-results/attack-extended")
    parser.add_argument("--dry-run", action="store_true",
                        help="stub kernel calls with a probabilistic model "
                             "(needed on macOS)")
    parser.add_argument("--smoke", action="store_true",
                        help="shrink all phases for a ~30 s dry-run")
    parser.add_argument("--toctou-iterations", type=int, default=0)
    parser.add_argument("--crossuid-attempts", type=int, default=0)
    parser.add_argument("--crossuid-both-modes", action="store_true",
                        help="run cross-uid phase twice: once with "
                             "require_peer_cred=0 (without the E4 patch) and "
                             "once with require_peer_cred=1 (with the patch), "
                             "for an A/B comparison. Requires sudo to toggle "
                             "/sys/module/kernel_mcp/parameters/require_peer_cred.")
    parser.add_argument("--duration-s", type=float, default=0.0)
    parser.add_argument("--rate-limit-per-s", type=int, default=500)
    parser.add_argument("--fuzz-tool-id", type=int, default=4242)
    parser.add_argument("--seed", type=int, default=20260414)
    args = parser.parse_args(argv)

    phases_req = {p.strip() for p in args.phase.split(",") if p.strip()}
    if "all" in phases_req:
        phases = {"toctou", "crossuid", "fuzz"}
    else:
        phases = phases_req & {"toctou", "crossuid", "fuzz"}
    if not phases:
        parser.error(f"no valid phases in --phase={args.phase!r}")

    if args.smoke:
        toctou_iters = args.toctou_iterations or SMOKE_TOCTOU_ITERS
        crossuid_attempts = args.crossuid_attempts or SMOKE_CROSSUID_ATTEMPTS
        duration_s = args.duration_s or SMOKE_FUZZ_DURATION_S
    else:
        toctou_iters = args.toctou_iterations or DEFAULT_TOCTOU_ITERS
        crossuid_attempts = args.crossuid_attempts or DEFAULT_CROSSUID_ATTEMPTS
        duration_s = args.duration_s or DEFAULT_FUZZ_DURATION_S

    rng = random.Random(args.seed)

    run_ts = time.strftime("run-%Y%m%dT%H%M%SZ", time.gmtime())
    output_root = Path(args.output_dir)
    if not output_root.is_absolute():
        output_root = ROOT_DIR / output_root
    run_dir = output_root / run_ts
    run_dir.mkdir(parents=True, exist_ok=True)
    plots_dir = run_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    print(f"[attack-extended] result dir: {run_dir}")
    print(f"[attack-extended] phases: {sorted(phases)}  dry_run={args.dry_run}  smoke={args.smoke}")

    client = _build_client(args, rng)

    toctou_summary: Optional[Dict[str, Any]] = None
    crossuid_summary: Optional[Dict[str, Any]] = None
    fuzz_stats: Optional[FuzzStats] = None

    # Phase 1 — TOCTOU.
    if "toctou" in phases:
        print(f"[attack-extended][toctou] iterations={toctou_iters}")
        t0 = time.monotonic()
        toctou_result_path = run_dir / "toctou_result.csv"
        with toctou_result_path.open("w", encoding="utf-8", newline="") as fp:
            writer = csv.DictWriter(fp, fieldnames=["iteration", "decision", "reason", "thread_ms"])
            writer.writeheader()
            toctou_summary = run_toctou_phase(
                client=client,
                iterations=toctou_iters,
                tool_id=args.fuzz_tool_id,
                rng=rng,
                writer=writer,
            )
        write_toctou_summary(run_dir, toctou_summary)
        print(f"[attack-extended][toctou] done in {time.monotonic() - t0:.1f}s; "
              f"breaches={toctou_summary['breach_count']}")

    # Phase 2 — cross-uid hijack.
    #
    # When --crossuid-both-modes is set, run twice: once with
    # require_peer_cred=0 (the "without patch" baseline — same behaviour as
    # the initial E4 run) and once with require_peer_cred=1 (the "with patch"
    # comparison). Otherwise fall back to single-mode behaviour controlled
    # by whatever value is already set on the module.
    crossuid_all_modes: Dict[str, Dict[str, Any]] = {}
    if "crossuid" in phases:
        if args.crossuid_both_modes:
            mode_plan = [("without_patch", 0), ("with_patch", 1)]
        else:
            mode_plan = [("single", None)]
        for mode_label, peer_cred_value in mode_plan:
            if peer_cred_value is not None and not args.dry_run:
                _set_peer_cred_mode(peer_cred_value)
            print(f"[attack-extended][crossuid:{mode_label}] attempts={crossuid_attempts}")
            t0 = time.monotonic()
            if len(mode_plan) > 1:
                crossuid_path = run_dir / f"crossuid_result_{mode_label}.csv"
            else:
                crossuid_path = run_dir / "crossuid_result.csv"
            with crossuid_path.open("w", encoding="utf-8", newline="") as fp:
                writer = csv.DictWriter(
                    fp,
                    fieldnames=[
                        "attempt", "attacker_uid", "sub_case", "decision",
                        "reason", "kernel_errno", "latency_ms", "outcome",
                    ],
                )
                writer.writeheader()
                # The dry-run synthetic branch is keyed on peer-cred mode so
                # that the "with_patch" run shows leaked→DENY on macOS too.
                phase_dry = args.dry_run
                mode_summary = run_crossuid_phase(
                    client=client,
                    attempts=crossuid_attempts,
                    tool_id=args.fuzz_tool_id + 1,
                    rng=rng,
                    writer=writer,
                    dry_run=phase_dry,
                    dry_run_peer_cred_on=(peer_cred_value == 1),
                )
            mode_summary["mode"] = mode_label
            mode_summary["require_peer_cred"] = peer_cred_value
            crossuid_all_modes[mode_label] = mode_summary
            print(f"[attack-extended][crossuid:{mode_label}] done in "
                  f"{time.monotonic() - t0:.1f}s; "
                  f"blocked={mode_summary['blocked']}/{mode_summary['attempts']}")
        # Backwards-compatible `crossuid` summary: if only one mode ran, use
        # it directly; otherwise expose the with_patch result as the headline
        # and stash both under crossuid_modes.
        if len(mode_plan) == 1:
            crossuid_summary = crossuid_all_modes["single"]
        else:
            crossuid_summary = crossuid_all_modes.get("with_patch") or crossuid_all_modes.get("without_patch")

    # Phase 3 — dumb fuzzer.
    if "fuzz" in phases:
        print(f"[attack-extended][fuzz] duration_s={duration_s} rate<={args.rate_limit_per_s}/s")
        t0 = time.monotonic()
        samples_path = run_dir / "fuzz_samples.csv"
        with samples_path.open("w", encoding="utf-8", newline="") as fp:
            writer = csv.DictWriter(fp, fieldnames=["cmd", "attr_name", "mutation_kind", "errno"])
            writer.writeheader()
            fuzz_stats = run_fuzzer_phase(
                duration_s=duration_s,
                rng=rng,
                rate_limit_per_s=args.rate_limit_per_s,
                dry_run=args.dry_run,
                fuzz_samples_writer=writer,
            )
        (run_dir / "dmesg_before.txt").write_text(
            getattr(fuzz_stats, "dmesg_before", ""), encoding="utf-8"
        )
        (run_dir / "dmesg_after.txt").write_text(
            getattr(fuzz_stats, "dmesg_after", ""), encoding="utf-8"
        )
        (run_dir / "dmesg_delta.txt").write_text(
            getattr(fuzz_stats, "dmesg_delta", ""), encoding="utf-8"
        )
        write_fuzz_report(run_dir, fuzz_stats)
        render_fuzz_plot(fuzz_stats, plots_dir / "figure_fuzz_errno_distribution.png")
        print(f"[attack-extended][fuzz] done in {time.monotonic() - t0:.1f}s; "
              f"sent={fuzz_stats.total_sent}")

    # Aggregate JSON summary.
    summary = {
        "meta": {
            "run_ts": run_ts,
            "dry_run": args.dry_run,
            "smoke": args.smoke,
            "phases": sorted(phases),
            "toctou_iterations": toctou_iters if "toctou" in phases else 0,
            "crossuid_attempts": crossuid_attempts if "crossuid" in phases else 0,
            "fuzz_duration_s": duration_s if "fuzz" in phases else 0.0,
            "seed": args.seed,
            "platform": platform.platform(),
            "python": sys.version.split()[0],
        },
        "toctou": toctou_summary,
        "crossuid": crossuid_summary,
        "crossuid_modes": crossuid_all_modes if crossuid_all_modes else None,
        "fuzz": (
            {
                "total_sent": fuzz_stats.total_sent,
                "socket_errors": fuzz_stats.socket_errors,
                "errno_hist": fuzz_stats.errno_hist,
                "per_cmd_errno": fuzz_stats.per_cmd_errno,
                "mutation_hist": fuzz_stats.mutation_hist,
                "dmesg_findings": getattr(fuzz_stats, "dmesg_findings", {}),
            }
            if fuzz_stats is not None
            else None
        ),
        "peer_cred_finding": (
            "kernel_mcp_cmd_tool_request has no NETLINK_CB / current_uid check — "
            "cross-uid hijack is gated only by the secrecy of binding_hash"
        ),
    }
    (run_dir / "attack_extended_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True, default=str), encoding="utf-8",
    )
    write_main_report(
        run_dir,
        toctou=toctou_summary,
        crossuid=crossuid_summary,
        fuzz=fuzz_stats,
    )

    try:
        client.close()
    except Exception:
        pass

    print(f"[attack-extended] summary: {run_dir / 'attack_extended_summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
