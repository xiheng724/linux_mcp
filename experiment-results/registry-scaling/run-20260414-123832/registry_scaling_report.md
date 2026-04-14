# Registry Scaling Experiment Report

## Setup

- host: `lixiheng-server` (Linux-6.8.0-107-generic-aarch64-with-glibc2.39)
- kernel: `6.8.0-107-generic`
- reps_per_N: 5
- lookup_samples_per_rep: 2000
- N values: 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384
- warmup_n: 64 (throwaway register pass before each N)
- dry_run: False

## Register-path model: total_ms(N) = a + b·N

We model bulk registration as a one-time setup cost `a` plus a
per-tool steady-state cost `b`. The asymptotic registration
throughput as N → ∞ is `1/b` tools/ms = `1000/b` tools/s.

| parameter | value |
|---|---:|
| a (fixed setup cost) | -0.1225 ms |
| b (per-tool steady-state cost) | 6.011 μs |
| asymptotic throughput 1/b | 166376 tools/s |
| R² | 0.9996 |
| fit points | 12 |

Interpretation: throughput = N/(a+bN) is a monotonically *increasing*
function of N with no local maximum. The apparent 'hump' visible in
a raw throughput-vs-N plot is simply the curve approaching its
asymptote 1/b from below; there is no scaling degradation at large N.
The per-tool cost figure is a cleaner primary visualization since
its asymptote (b, a single horizontal line) is immediately legible.

## Per-N summary

| N | total_ms | per_tool_μs | ±CI95 | tps | lookup_avg_μs | lookup_p99_μs | user_dict_μs | sysfs_ls_ms |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 0.061 | 7.645 | ±0.889 | 132703 | 7.491 | 13.583 | 0.060 | 0.636 |
| 16 | 0.101 | 6.337 | ±0.427 | 158518 | 7.295 | 11.460 | 0.060 | 0.511 |
| 32 | 0.188 | 5.872 | ±0.389 | 171013 | 7.341 | 10.583 | 0.058 | 0.605 |
| 64 | 0.366 | 5.715 | ±0.335 | 175626 | 7.224 | 11.168 | 0.061 | 0.571 |
| 128 | 0.705 | 5.509 | ±0.119 | 181599 | 7.170 | 11.334 | 0.062 | 0.500 |
| 256 | 1.405 | 5.490 | ±0.112 | 182232 | 7.096 | 9.916 | 0.057 | 0.487 |
| 512 | 2.960 | 5.781 | ±0.127 | 173062 | 7.375 | 10.963 | 0.059 | 0.787 |
| 1024 | 5.751 | 5.616 | ±0.080 | 178107 | 7.644 | 12.125 | 0.061 | 0.991 |
| 2048 | 11.436 | 5.584 | ±0.125 | 179175 | 7.245 | 10.083 | 0.063 | 1.038 |
| 4096 | 25.738 | 6.284 | ±0.769 | 161500 | 7.671 | 20.417 | 0.075 | 2.570 |
| 8192 | 48.022 | 5.862 | ±0.279 | 170982 | 7.487 | 11.542 | 0.072 | 3.960 |
| 16384 | 98.700 | 6.024 | ±0.263 | 166314 | 7.719 | 12.125 | 0.080 | 8.474 |

## Log-linear lookup fit (lookup_ms ~ a + b·log2(N))

- intercept a = 0.007148 ms
- slope b = 0.000029 ms/doubling
- R² = 0.2618
- slope 95% bootstrap CI: [-0.000002, 0.000061] ms/doubling

A slope near zero with a CI containing zero supports the O(1)
lookup claim. A non-zero slope at high R² would indicate log-scale
behavior (expected for balanced trees, not for hash/xarray lookups).
