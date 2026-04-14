# Registry Scaling Experiment Report

## Setup

- host: `lixiheng-server` (Linux-6.8.0-107-generic-aarch64-with-glibc2.39)
- kernel: `6.8.0-107-generic`
- reps_per_N: 5
- lookup_samples_per_rep: 2000
- N values: 8, 64, 512, 4096, 16384
- dry_run: False

## Per-N summary

| N | register_total_ms | tools_per_sec | lookup_avg_ms | lookup_p95_ms | lookup_p99_ms | user_dict_avg_ms | sysfs_ls_ms |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 0.065 | 125827.4 | 0.007362 | 0.009416 | 0.012834 | 0.000064 | 0.645 |
| 64 | 0.439 | 147470.5 | 0.007400 | 0.008583 | 0.012417 | 0.000062 | 0.515 |
| 512 | 2.904 | 176922.3 | 0.007140 | 0.007458 | 0.010000 | 0.000056 | 0.648 |
| 4096 | 24.887 | 165419.1 | 0.007393 | 0.008209 | 0.012167 | 0.000069 | 3.411 |
| 16384 | 104.568 | 161384.6 | 0.008072 | 0.011000 | 0.015667 | 0.000120 | 13.245 |

## Log-linear fit (lookup_ms ~ a + b*log2(N))

- intercept a = 0.007067 ms
- slope b = 0.000046 ms/doubling
- R^2 = 0.3406
- slope 95% bootstrap CI: [-0.000043, 0.000194] ms/doubling

A slope near zero supports the ~O(1) lookup claim; a non-zero slope
at the given R^2 indicates log-scale behavior (expected for balanced
trees, not for hashed/xarray lookups).
