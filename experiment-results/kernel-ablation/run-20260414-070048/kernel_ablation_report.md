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
| full | 100000 | 0.007297 | 0.006916 | 0.007792 | 0.011625 | 0.016916 | +/- 0.000105 |
| skip_ticket | 100000 | 0.007646 | 0.007333 | 0.008458 | 0.013416 | 0.002425 | +/- 0.000015 |
| skip_binding | 100000 | 0.007489 | 0.007292 | 0.008125 | 0.010875 | 0.001665 | +/- 0.000010 |
| skip_hash | 100000 | 0.007507 | 0.007334 | 0.008125 | 0.010709 | 0.001283 | +/- 0.000008 |
| skip_lookups | 100000 | 0.007412 | 0.007250 | 0.007959 | 0.010834 | 0.000980 | +/- 0.000006 |

## Noise floor (KERNEL_MCP_CMD_NOOP)

| metric | value (ms) |
|---|---:|
| avg  | 0.003187 |
| p50  | 0.003125 |
| p95  | 0.003375 |
| p99  | 0.004333 |

All ablation deltas below are stated as `full - skip`, so positive
values mean the named stage is non-trivial on the current kernel.

## Per-stage isolated cost

| stage | full avg | skip avg | delta_ms | delta ratio | bootstrap CI |
|---|---:|---:|---:|---:|---|
| ticket | 0.007297 | 0.007646 | -0.000348 | -0.0477 | [-0.000429, -0.000221] |
| binding | 0.007297 | 0.007489 | -0.000192 | -0.0262 | [-0.000269, -0.000071] |
| hash | 0.007297 | 0.007507 | -0.000210 | -0.0287 | [-0.000287, -0.000090] |
| lookups | 0.007297 | 0.007412 | -0.000115 | -0.0158 | [-0.000191, 0.000006] |

## Pairwise Welch t-tests (adjacent vs full), BH-corrected

| mode | t | p_raw | p_bh |
|---|---:|---:|---:|
| skip_ticket | -6.4462 | 0.000000 | 0.000000 |
| skip_binding | -3.5630 | 0.000367 | 0.000489 |
| skip_hash | -3.9104 | 0.000092 | 0.000184 |
| skip_lookups | -2.1465 | 0.031834 | 0.031834 |

## Caveats

- Delta estimates near the sub-microsecond range should be read
  together with the noop noise floor above.
- This is single-factor ablation: cross-interactions between stages
  are not measured. The absolute per-stage costs do not sum to
  `full - skip_lookups` exactly because the kernel path has shared
  prologue work that all non-skip modes still pay.
