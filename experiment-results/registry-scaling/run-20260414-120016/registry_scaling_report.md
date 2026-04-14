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
| a (fixed setup cost) | -0.0682 ms |
| b (per-tool steady-state cost) | 6.017 μs |
| asymptotic throughput 1/b | 166197 tools/s |
| R² | 0.9994 |
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
| 8 | 0.055 | 6.832 | ±1.267 | 150877 | 7.101 | 11.625 | 0.060 | 0.590 |
| 16 | 0.091 | 5.679 | ±0.186 | 176277 | 7.086 | 11.792 | 0.058 | 0.440 |
| 32 | 0.182 | 5.684 | ±0.358 | 176609 | 7.219 | 11.375 | 0.058 | 0.603 |
| 64 | 0.384 | 5.993 | ±0.296 | 167293 | 7.179 | 11.959 | 0.060 | 0.555 |
| 128 | 0.787 | 6.146 | ±0.734 | 165026 | 7.067 | 10.418 | 0.070 | 0.531 |
| 256 | 1.436 | 5.610 | ±0.183 | 178434 | 7.048 | 9.958 | 0.057 | 0.502 |
| 512 | 3.028 | 5.914 | ±0.503 | 170248 | 7.547 | 15.375 | 0.055 | 0.791 |
| 1024 | 5.688 | 5.555 | ±0.107 | 180087 | 7.475 | 13.166 | 0.064 | 1.011 |
| 2048 | 11.713 | 5.719 | ±0.129 | 174947 | 7.464 | 15.542 | 0.062 | 1.144 |
| 4096 | 26.225 | 6.403 | ±0.808 | 158651 | 7.979 | 18.291 | 0.075 | 2.828 |
| 8192 | 47.807 | 5.836 | ±0.301 | 171816 | 7.304 | 13.711 | 0.073 | 3.408 |
| 16384 | 98.901 | 6.036 | ±0.292 | 166056 | 7.766 | 18.297 | 0.115 | 7.767 |

## Log-linear lookup fit (lookup_ms ~ a + b·log2(N))

- intercept a = 0.006826 ms
- slope b = 0.000062 ms/doubling
- R² = 0.5574
- slope 95% bootstrap CI: [0.000030, 0.000098] ms/doubling

A slope near zero with a CI containing zero supports the O(1)
lookup claim. A non-zero slope at high R² would indicate log-scale
behavior (expected for balanced trees, not for hash/xarray lookups).
