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
| 8 | 0.056 | 151148.6 | 0.007380 | 0.009250 | 0.011126 | 0.000059 | 0.519 |
| 64 | 0.374 | 171766.8 | 0.006953 | 0.007750 | 0.009708 | 0.000059 | 0.371 |
| 512 | 2.790 | 183764.0 | 0.007097 | 0.008209 | 0.009958 | 0.000058 | 0.692 |
| 4096 | 22.988 | 178259.8 | 0.007229 | 0.008000 | 0.010208 | 0.000069 | 3.220 |
| 16384 | 90.906 | 180336.9 | 0.007241 | 0.007709 | 0.010292 | 0.000081 | 12.372 |

## Log-linear fit (lookup_ms ~ a + b*log2(N))

- intercept a = 0.007187 ms
- slope b = -0.000001 ms/doubling
- R^2 = 0.0005
- slope 95% bootstrap CI: [-0.000059, 0.000046] ms/doubling

A slope near zero supports the ~O(1) lookup claim; a non-zero slope
at the given R^2 indicates log-scale behavior (expected for balanced
trees, not for hashed/xarray lookups).
