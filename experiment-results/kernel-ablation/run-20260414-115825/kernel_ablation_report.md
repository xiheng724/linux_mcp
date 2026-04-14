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
| full | 100000 | 0.008143 | 0.007500 | 0.009583 | 0.018500 | 0.026177 | +/- 0.000162 |
| skip_ticket | 100000 | 0.008044 | 0.007458 | 0.009833 | 0.016583 | 0.019350 | +/- 0.000120 |
| skip_binding | 100000 | 0.008044 | 0.007500 | 0.010125 | 0.018583 | 0.004022 | +/- 0.000025 |
| skip_hash | 100000 | 0.008277 | 0.007625 | 0.010208 | 0.021334 | 0.009851 | +/- 0.000061 |
| skip_lookups | 100000 | 0.008218 | 0.007458 | 0.010417 | 0.022167 | 0.005124 | +/- 0.000032 |

## Noise floor (KERNEL_MCP_CMD_NOOP)

| metric | value (ms) |
|---|---:|
| avg  | 0.003243 |
| p50  | 0.003166 |
| p95  | 0.003375 |
| p99  | 0.004543 |

All ablation deltas below are stated as `full - skip`, so positive
values mean the named stage is non-trivial on the current kernel.

## Per-stage isolated cost

| stage | full avg | skip avg | delta_ms | delta ratio | bootstrap CI |
|---|---:|---:|---:|---:|---|
| ticket | 0.008143 | 0.008044 | 0.000099 | 0.0121 | [-0.000099, 0.000313] |
| binding | 0.008143 | 0.008044 | 0.000099 | 0.0122 | [-0.000021, 0.000278] |
| hash | 0.008143 | 0.008277 | -0.000134 | -0.0165 | [-0.000279, 0.000053] |
| lookups | 0.008143 | 0.008218 | -0.000075 | -0.0092 | [-0.000196, 0.000105] |

## Pairwise Welch t-tests (adjacent vs full), BH-corrected

| mode | t | p_raw | p_bh |
|---|---:|---:|---:|
| skip_ticket | 0.9591 | 0.337485 | 0.376846 |
| skip_binding | 1.1847 | 0.236144 | 0.376846 |
| skip_hash | -1.5189 | 0.128798 | 0.376846 |
| skip_lookups | -0.8837 | 0.376846 | 0.376846 |

## Caveats

- Delta estimates near the sub-microsecond range should be read
  together with the noop noise floor above.
- This is single-factor ablation: cross-interactions between stages
  are not measured. The absolute per-stage costs do not sum to
  `full - skip_lookups` exactly because the kernel path has shared
  prologue work that all non-skip modes still pay.
