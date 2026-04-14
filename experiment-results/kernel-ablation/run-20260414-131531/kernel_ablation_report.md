# Kernel Path Ablation (E1)

## Setup

- reps: 10
- requests per (mode, rep) — benign: 10000
- requests per (mode, rep) — ticket_trigger: 1000
- benign registry scale: 1024 tools, 64 agents
- order randomization: per-rep shuffle of mode list
- dry-run: False

## Environment

VMware guest / Apple aarch64 host / 4 vCPU / 8 GB. Absolute numbers
must be read together with the measured noise floor (noop).

## Scenarios

- **full** (benign_large_registry, flags=0x0): Full arbitration path at realistic registry scale (N tools, M agents)
- **skip_lookups** (benign_large_registry, flags=0x1): Early return before any tool/agent lookup (bypasses 2 mutex pairs + xa_load + hashtable walk)
- **ticket_trigger_full** (ticket_trigger, flags=0x0): High-risk tool, request without ticket -> runs kernel_mcp_consume_approval_ticket + issue_approval_ticket
- **ticket_trigger_skip** (ticket_trigger, flags=0x8): Same workload as ticket_trigger_full but SKIP_TICKET bypasses the approval branch
- **skip_hash** (benign_large_registry, flags=0x2): Methodology note: guard body is dead under valid hash, reported to document the path-identity caveat
- **skip_binding** (benign_large_registry, flags=0x4): Methodology note: guard body is dead under valid binding, reported to document the path-identity caveat

## Per-mode RTT summary

| mode | n | avg_ms | p50 | p95 | p99 | std |
|---|---:|---:|---:|---:|---:|---:|
| full | 100000 | 0.008377 | 0.007584 | 0.010250 | 0.022750 | 0.006340 |
| skip_lookups | 100000 | 0.007746 | 0.007417 | 0.008458 | 0.012792 | 0.003239 |
| ticket_trigger_full | 10000 | 0.037474 | 0.031541 | 0.092044 | 0.100418 | 0.029440 |
| ticket_trigger_skip | 10000 | 0.008742 | 0.007458 | 0.012625 | 0.036501 | 0.007676 |
| skip_hash | 100000 | 0.008556 | 0.007500 | 0.010333 | 0.024416 | 0.018322 |
| skip_binding | 100000 | 0.008467 | 0.007500 | 0.010334 | 0.022959 | 0.014135 |

## Noise floor (KERNEL_MCP_CMD_NOOP)

| metric | value (ms) |
|---|---:|
| avg  | 0.003144 |
| p50  | 0.003084 |
| p95  | 0.003292 |
| p99  | 0.004042 |

## Kernel arbitration total cost (primary number)

- full p50 (benign_large scenario): **0.007584 ms**
- noop p50 (Generic Netlink floor): **0.003084 ms**
- **arbitration = full_p50 − noop_p50 = 0.004500 ms**

The median (p50) is preferred over the mean because VMware preemption
events occasionally inject multi-millisecond outliers into single
samples. The noise floor (noop) captures everything Generic Netlink
and the minimum `KMCP_CMD_NOOP` handler contribute before any
registry, hash, binding, or ticket work is done. The full-path
measurement is taken at realistic registry scale
(1024 tools in the xarray,
64 agents in the hashtable), so the
xa_load and agent-lookup walks exercise real data structures instead
of single-entry trivial cases.

## Per-stage body cost (paired ablation)

These are the **meaningful** deltas — pairs of modes where the
bypass flag actually changes the kernel execution path under its
workload. Both the mean-based and p50-based delta are shown because
p50 is robust to hypervisor preemption outliers in individual
100k-sample cells.

| stage | baseline | bypass | Δ_avg (μs) | Δ_p50 (μs) | bootstrap 95% CI (μs) | note |
|---|---|---|---:|---:|---|---|
| registry+agent_lookup | full | skip_lookups | +0.631 | +0.167 | [+0.587, +0.674] | two mutex pairs + xa_load(N=1024) + agent hashtable walk(M=64) |
| approval_ticket_body | ticket_trigger_full | ticket_trigger_skip | +28.732 | +24.083 | [+28.137, +29.323] | kernel_mcp_consume_approval_ticket + kernel_mcp_issue_approval_ticket (approval_lock + hashtable insert) |

## Methodology-note deltas (not paper numbers)

`hash_guard_body` and `binding_guard_body` are reported for transparency
only. In any benign-credential benchmark workload, the `if (hash_mismatch
&& ...)` and `if (binding != registered)` guard bodies in
`kernel_mcp_cmd_tool_request` are short-circuited by the workload state
before the experiment flag is consulted; full and skip_{hash,binding}
therefore execute identical kernel code paths, and any measured delta
between them is noise on the same code, not a stage cost. We keep them
in the output so that the path-identity caveat is visible in the raw
data instead of requiring a source-level trace to rediscover.

| stage | baseline | bypass | Δ_avg (μs) | Δ_p50 (μs) | bootstrap 95% CI (μs) | note |
|---|---|---|---:|---:|---|---|
| hash_guard_body | full | skip_hash | -0.179 | +0.084 | [-0.310, -0.077] | hash_mismatch guard body is dead under valid hash (delta = noise floor) |
| binding_guard_body | full | skip_binding | -0.090 | +0.084 | [-0.191, +0.001] | binding_mismatch guard body is dead under valid binding (delta = noise floor) |

## Pairwise Welch t-tests (BH-corrected across all deltas)

| stage | baseline | bypass | t | p_raw | p_bh |
|---|---|---|---:|---:|---:|
| registry+agent_lookup | full | skip_lookups | 28.0240 | 0.000000 | 0.000000 |
| approval_ticket_body | ticket_trigger_full | ticket_trigger_skip | 94.4380 | 0.000000 | 0.000000 |
| hash_guard_body | full | skip_hash | -2.9202 | 0.003499 | 0.004665 |
| binding_guard_body | full | skip_binding | -1.8471 | 0.064728 | 0.064728 |

## Interpretation

The redesigned ablation (vs earlier runs that used a single-tool,
single-agent registry with only legal inputs) targets the two stages
whose guard bodies actually execute in the benchmark: the
registry+agent lookup under realistic scale, and the approval-ticket
machinery under a high-risk tool. All other skip_* flags are kept
for methodology transparency only — their deltas against full under
benign inputs are measurements of the same kernel path twice, not
per-stage cost.

On this aarch64 VMware guest, the full-path arbitration at
1024-tool / 64-agent scale
is 4.50 μs above a 3.08 μs Generic
Netlink floor. Of that budget, the measured per-stage contributions
are in the `meaningful_stage_deltas` table above. The residual that
does not appear in any stage delta is attributable to reply-skb
construction (`kernel_mcp_reply_tool_decision`, 5 × `nla_put_*` +
`genlmsg_reply`) — this is the dominant non-decomposable cost.
