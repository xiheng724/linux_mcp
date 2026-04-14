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
| full | 100000 | 0.006941 | 0.006792 | 0.007417 | 0.010167 | 0.000994 | +/- 0.000006 |
| skip_ticket | 100000 | 0.007372 | 0.007208 | 0.007958 | 0.010833 | 0.000950 | +/- 0.000006 |
| skip_binding | 100000 | 0.007329 | 0.007208 | 0.007625 | 0.010542 | 0.001150 | +/- 0.000007 |
| skip_hash | 100000 | 0.007385 | 0.007209 | 0.007958 | 0.010959 | 0.001193 | +/- 0.000007 |
| skip_lookups | 100000 | 0.007333 | 0.007167 | 0.007834 | 0.011250 | 0.001738 | +/- 0.000011 |

## Noise floor (KERNEL_MCP_CMD_NOOP)

| metric | value (ms) |
|---|---:|
| avg  | 0.003150 |
| p50  | 0.003083 |
| p95  | 0.003292 |
| p99  | 0.004542 |

All ablation deltas below are stated as `full - skip`, so positive
values mean the named stage is non-trivial on the current kernel.

## Per-stage isolated cost

| stage | full avg | skip avg | delta_ms | delta ratio | bootstrap CI |
|---|---:|---:|---:|---:|---|
| ticket | 0.006941 | 0.007372 | -0.000431 | -0.0621 | [-0.000439, -0.000423] |
| binding | 0.006941 | 0.007329 | -0.000388 | -0.0559 | [-0.000398, -0.000379] |
| hash | 0.006941 | 0.007385 | -0.000445 | -0.0641 | [-0.000454, -0.000435] |
| lookups | 0.006941 | 0.007333 | -0.000392 | -0.0565 | [-0.000406, -0.000381] |

## Pairwise Welch t-tests (adjacent vs full), BH-corrected

| mode | t | p_raw | p_bh |
|---|---:|---:|---:|
| skip_ticket | -99.1278 | 0.000000 | 0.000000 |
| skip_binding | -80.7386 | 0.000000 | 0.000000 |
| skip_hash | -90.5760 | 0.000000 | 0.000000 |
| skip_lookups | -61.9398 | 0.000000 | 0.000000 |

## Caveats

- Delta estimates near the sub-microsecond range should be read
  together with the noop noise floor above.
- This is single-factor ablation: cross-interactions between stages
  are not measured. The absolute per-stage costs do not sum to
  `full - skip_lookups` exactly because the kernel path has shared
  prologue work that all non-skip modes still pay.
