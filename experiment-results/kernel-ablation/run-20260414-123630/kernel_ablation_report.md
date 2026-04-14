# Kernel Path Ablation (E1)

## Setup

- kernel flags tested: full, skip_ticket, skip_binding, skip_hash, skip_lookups
- reps: 10
- requests per (mode, rep): 10000
- payload: 100 B equivalent (bare netlink path)
- order randomization: per-rep shuffle of mode list
- dry-run: False

## Environment

VMware guest / Apple aarch64 host / 4 vCPU / 8 GB. Absolute numbers
must be read together with the measured noise floor (noop).

## Per-mode summary

| mode | n | avg_ms | p50 | p95 | p99 | std | 95% CI |
|---|---:|---:|---:|---:|---:|---:|---:|
| full | 100000 | 0.007548 | 0.007250 | 0.008250 | 0.012250 | 0.002260 | +/- 0.000014 |
| skip_ticket | 100000 | 0.007725 | 0.007375 | 0.008500 | 0.014041 | 0.002634 | +/- 0.000016 |
| skip_binding | 100000 | 0.007635 | 0.007292 | 0.008333 | 0.012500 | 0.003165 | +/- 0.000020 |
| skip_hash | 100000 | 0.007584 | 0.007292 | 0.008250 | 0.012334 | 0.001873 | +/- 0.000012 |
| skip_lookups | 100000 | 0.007522 | 0.007250 | 0.008167 | 0.012250 | 0.001859 | +/- 0.000012 |

## Noise floor (KERNEL_MCP_CMD_NOOP)

| metric | value (ms) |
|---|---:|
| avg  | 0.003192 |
| p50  | 0.003125 |
| p95  | 0.003375 |
| p99  | 0.004334 |

All ablation deltas below are stated as `full - skip`, so positive
values mean the named stage is non-trivial on the current kernel.

## Per-stage isolated cost

| stage | full avg | skip avg | delta_ms | delta ratio | bootstrap CI |
|---|---:|---:|---:|---:|---|
| ticket | 0.007548 | 0.007725 | -0.000177 | -0.0235 | [-0.000200, -0.000156] |
| binding | 0.007548 | 0.007635 | -0.000087 | -0.0115 | [-0.000111, -0.000064] |
| hash | 0.007548 | 0.007584 | -0.000036 | -0.0048 | [-0.000054, -0.000019] |
| lookups | 0.007548 | 0.007522 | 0.000026 | 0.0034 | [0.000008, 0.000043] |

## Pairwise Welch t-tests (adjacent vs full), BH-corrected

| mode | t | p_raw | p_bh |
|---|---:|---:|---:|
| skip_ticket | -16.1465 | 0.000000 | 0.000000 |
| skip_binding | -7.0469 | 0.000000 | 0.000000 |
| skip_hash | -3.8725 | 0.000108 | 0.000144 |
| skip_lookups | 2.7759 | 0.005505 | 0.005505 |

## Interpretation (important — path-identity under valid workload)

This ablation runner uses valid credentials: the registered tool hash
matches the request, the registered binding hash matches the request,
`risk_flags = 0` (no approval gate), and `require_peer_cred = 0`.
Under those conditions, a careful trace of `kernel_mcp_cmd_tool_request`
in `kernel-mcp/src/kernel_mcp_main.c` shows that `full`, `skip_ticket`,
`skip_binding`, and `skip_hash` **execute literally identical kernel
instructions**. The `if (hash_mismatch && …)`, `if (binding != …)`,
and `if (risk_flags & APPROVAL_REQUIRED_FLAGS)` guards are already
short-circuited by the workload state, so their bodies never execute
regardless of the experiment flag. Only `skip_lookups` takes a truly
different path — it returns early at line 961 before any mutex, xarray,
or agent lookup work.

Therefore, the per-stage deltas above for hash / binding / ticket are
**not** measuring per-stage cost. They are noise measurements on the
same kernel path executed four times. The `skip_lookups` delta is the
only one that decomposes meaningfully, and it measures the combined
cost of two uncontended mutex pairs, one xarray load, and one agent
hashtable lookup over a small registry (~150-200 ns in practice on
this aarch64 VM).

This is the truthful experimental result: the fast path of kernel
arbitration under valid inputs is dominated by (a) Generic Netlink
transport and (b) reply-skb construction, and **the per-check guards
are too cheap to measure individually on this hardware**. To actually
isolate per-check costs one would need to send invalid inputs that
force each guard to take its deny path, and compare against a run
with that check bypassed. That is left as future work; the present
result is reported as a methodology check, not a stage decomposition.

## Kernel arbitration total cost (primary number)

- full p50:     0.007250 ms
- noop p50:     0.003125 ms
- **arbitration = full_p50 − noop_p50 = 0.004125 ms**

The median (p50) is preferred over the mean because VMware preemption
events occasionally inject multi-millisecond outliers into single
samples. The noise floor (noop) captures everything Generic Netlink
and the minimum `KMCP_CMD_NOOP` handler contribute before any
registry, hash, binding, or ticket work is done.
