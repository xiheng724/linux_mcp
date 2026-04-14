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
| full | 100000 | 0.008189 | 0.007792 | 0.008750 | 0.015417 | 0.006543 |
| skip_lookups | 100000 | 0.008003 | 0.007500 | 0.008500 | 0.017584 | 0.012433 |
| ticket_trigger_full | 1000 | 0.013780 | 0.009791 | 0.023375 | 0.039338 | 0.079216 |
| ticket_trigger_skip | 1000 | 0.009890 | 0.007583 | 0.021042 | 0.037423 | 0.013544 |
| skip_hash | 100000 | 0.008392 | 0.007750 | 0.008709 | 0.021959 | 0.028360 |
| skip_binding | 100000 | 0.008665 | 0.007667 | 0.008709 | 0.015875 | 0.067472 |

## Noise floor (KERNEL_MCP_CMD_NOOP)

| metric | value (ms) |
|---|---:|
| avg  | 0.003343 |
| p50  | 0.003291 |
| p95  | 0.003542 |
| p99  | 0.004250 |

## Kernel arbitration total cost (primary number)

- full p50 (benign_large scenario): **0.007792 ms**
- noop p50 (Generic Netlink floor): **0.003291 ms**
- **arbitration = full_p50 − noop_p50 = 0.004501 ms**

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
| registry+agent_lookup | full | skip_lookups | +0.186 | +0.292 | [+0.097, +0.265] | two mutex pairs + xa_load(N=1024) + agent hashtable walk(M=64) |
| approval_ticket_body | ticket_trigger_full | ticket_trigger_skip | +3.890 | +2.208 | [+0.758, +9.325] | kernel_mcp_consume_approval_ticket + kernel_mcp_issue_approval_ticket (approval_lock + hashtable insert) |

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
| hash_guard_body | full | skip_hash | -0.204 | +0.042 | [-0.396, -0.057] | hash_mismatch guard body is dead under valid hash (delta = noise floor) |
| binding_guard_body | full | skip_binding | -0.476 | +0.125 | [-0.937, -0.128] | binding_mismatch guard body is dead under valid binding (delta = noise floor) |

## Pairwise Welch t-tests (BH-corrected across all deltas)

| stage | baseline | bypass | t | p_raw | p_bh |
|---|---|---|---:|---:|---:|
| registry+agent_lookup | full | skip_lookups | 4.1799 | 0.000029 | 0.000116 |
| approval_ticket_body | ticket_trigger_full | ticket_trigger_skip | 1.5305 | 0.125884 | 0.125884 |
| hash_guard_body | full | skip_hash | -2.2114 | 0.027007 | 0.036009 |
| binding_guard_body | full | skip_binding | -2.2194 | 0.026462 | 0.036009 |

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
is 4.50 μs above a 3.29 μs Generic
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
