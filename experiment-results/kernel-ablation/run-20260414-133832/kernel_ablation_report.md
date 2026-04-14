# Kernel Path Ablation (E1)

## Setup

- reps: 10
- pairs per phase (benign): 10000
- pairs per phase (ticket_trigger): 100
- benign registry scale: 1024 tools, 64 agents
- measurement method: **paired**, request-level alternation inside each phase
- order randomization: per-rep shuffle of phase list
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
| full | 300000 | 0.007969 | 0.007459 | 0.008958 | 0.015750 | 0.032444 |
| skip_lookups | 100000 | 0.007874 | 0.007500 | 0.008709 | 0.015625 | 0.002807 |
| ticket_trigger_full | 1000 | 0.010073 | 0.009083 | 0.016173 | 0.027220 | 0.003750 |
| ticket_trigger_skip | 1000 | 0.008061 | 0.007459 | 0.010088 | 0.019584 | 0.003208 |
| skip_hash | 100000 | 0.007948 | 0.007458 | 0.009000 | 0.015667 | 0.024959 |
| skip_binding | 100000 | 0.007818 | 0.007417 | 0.008958 | 0.014625 | 0.002833 |

## Noise floor (KERNEL_MCP_CMD_NOOP)

| metric | value (ms) |
|---|---:|
| avg  | 0.003330 |
| p50  | 0.003125 |
| p95  | 0.003669 |
| p99  | 0.004793 |

## Kernel arbitration total cost (primary number)

- full p50 (benign_large scenario): **0.007459 ms**
- noop p50 (Generic Netlink floor): **0.003125 ms**
- **arbitration = full_p50 − noop_p50 = 0.004334 ms**

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

Each row below was produced by a **paired measurement**: within a
single benchmark phase, the baseline mode and the bypass mode were
alternated request-by-request inside a tight loop, so the two
samples in each pair are collected ~μs apart and share the same
scheduler state, cache residency, and jiffies tick. The delta
column is the mean of `baseline[i] - bypass[i]` across all pairs,
not the difference of two independent means — which is why the
bootstrap CIs are much tighter than a naive sequential ablation
would produce. Hypervisor-level rep drift (the source of the ~200
ns run-to-run shift we observed in earlier runs) cancels out
inside the paired difference.

| stage | baseline | bypass | n_pairs | Δ_avg (μs) | Δ_p50 (μs) | bootstrap 95% CI (μs) | t_paired | p_paired | note |
|---|---|---|---:|---:|---:|---|---:|---:|---|
| registry+agent_lookup | full | skip_lookups | 100000 | +0.109 | +0.042 | [+0.087, +0.131] | +10.08 | 0 | two mutex pairs + xa_load(N=1024) + agent hashtable walk(M=64) |
| approval_ticket_body | ticket_trigger_full | ticket_trigger_skip | 1000 | +2.012 | +1.542 | [+1.760, +2.257] | +15.99 | 0 | kernel_mcp_consume_approval_ticket + kernel_mcp_issue_approval_ticket (approval_lock + hashtable insert) |

## Methodology-note deltas (not paper numbers)

`hash_guard_body` and `binding_guard_body` are reported for transparency
only. In any benign-credential benchmark workload, the `if (hash_mismatch
&& ...)` and `if (binding != registered)` guard bodies in
`kernel_mcp_cmd_tool_request` are short-circuited by the workload state
before the experiment flag is consulted; full and skip_{hash,binding}
therefore execute identical kernel code paths, and any measured delta
between them is noise on the same code, not a stage cost. Under
paired measurement this noise should cancel to within a few tens of
nanoseconds, so the rows below are a consistency check on the paired
method itself — if any of them reports a large non-zero delta,
something in the measurement is broken.

| stage | baseline | bypass | n_pairs | Δ_avg (μs) | Δ_p50 (μs) | bootstrap 95% CI (μs) | t_paired | p_paired | note |
|---|---|---|---:|---:|---:|---|---:|---:|---|
| hash_guard_body | full | skip_hash | 100000 | +0.163 | +0.000 | [-0.153, +0.541] | +0.88 | 0.38 | hash_mismatch guard body is dead under valid hash (delta = noise floor) |
| binding_guard_body | full | skip_binding | 100000 | -0.007 | +0.000 | [-0.027, +0.013] | -0.65 | 0.513 | binding_mismatch guard body is dead under valid binding (delta = noise floor) |

## Paired t-tests (BH-corrected across all four phases)

| stage | baseline | bypass | n_pairs | t | p_raw | p_bh |
|---|---|---|---:|---:|---:|---:|
| registry+agent_lookup | full | skip_lookups | 100000 | +10.0801 | 0.000000 | 0.000000 |
| approval_ticket_body | ticket_trigger_full | ticket_trigger_skip | 1000 | +15.9894 | 0.000000 | 0.000000 |
| hash_guard_body | full | skip_hash | 100000 | +0.8774 | 0.380294 | 0.507059 |
| binding_guard_body | full | skip_binding | 100000 | -0.6537 | 0.513304 | 0.513304 |

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
is 4.33 μs above a 3.12 μs Generic
Netlink floor. Of that budget, the measured per-stage contributions
are in the `meaningful_stage_deltas` table above. The residual that
does not appear in any stage delta is attributable to reply-skb
construction (`kernel_mcp_reply_tool_decision`, 5 × `nla_put_*` +
`genlmsg_reply`) — this is the dominant non-decomposable cost.

### Secondary finding: O(n) purge scan in approval-ticket issuance

The `approval_ticket_body` delta reported above is **not** the pure
intrinsic cost of the consume + issue logic. Tracing
`kernel_mcp_issue_approval_ticket` in `kernel-mcp/src/kernel_mcp_main.c`
reveals that every ticket issuance calls
`kernel_mcp_purge_expired_tickets_locked()`, which iterates the
full 256-bucket approval hashtable and checks `expires_jiffies`
on every live entry. The default approval TTL is 300 seconds, so
over a ~1-minute E1 run nothing in the table ever expires — the
scan cost therefore grows linearly with the total number of
tickets issued by the benchmark.

The runner caps ticket_trigger samples at `--ticket-requests` (default
100, vs 10,000 for benign modes) specifically to keep this O(n)
amplification small relative to the intrinsic issue+consume cost.
Even at this reduced sample count, some linear-growth contamination
remains; the figure should therefore be read as an **upper bound**
on the approval-ticket body cost under steady-state mcpd operation,
where tickets are decided and consumed quickly rather than
accumulating. A kernel-side optimization — moving the expiry scan
to the existing periodic `kernel_mcp_ticket_cleanup_timer` instead
of running it inline on every issuance — would eliminate the O(n)
component entirely. We flag this as a secondary microbench finding,
not a performance-characteristic claim about the kernel arbitration
fast path.
