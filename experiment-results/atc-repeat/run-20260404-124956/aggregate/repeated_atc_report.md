# Repeated ATC Aggregate

## E2E Aggregate

| mode | concurrency | runs | throughput_mean | p95_mean | p99_mean |
|---|---:|---:|---:|---:|---:|
| direct | 1 | 3 | 645.701 | 7.338333 | 15.383 |
| direct | 4 | 3 | 1316.591 | 15.803333 | 32.839667 |
| direct | 8 | 3 | 1882.637 | 16.797667 | 27.498667 |
| mcpd | 1 | 3 | 254.769 | 11.750333 | 24.291 |
| mcpd | 4 | 3 | 348.187667 | 21.687 | 43.404333 |
| mcpd | 8 | 3 | 447.584333 | 35.164333 | 48.285 |

## Variant Aggregate

| variant | concurrency | runs | throughput_mean | p95_mean | p99_mean |
|---|---:|---:|---:|---:|---:|
| forwarder_only | 1 | 3 | 228.803333 | 11.737667 | 23.618333 |
| forwarder_only | 4 | 3 | 430.501333 | 19.271 | 36.855 |
| forwarder_only | 8 | 3 | 496.341 | 39.733 | 55.213 |
| userspace_semantic_plane | 1 | 3 | 204.231 | 17.314667 | 33.144667 |
| userspace_semantic_plane | 4 | 3 | 369.136667 | 30.805 | 55.440667 |
| userspace_semantic_plane | 8 | 3 | 425.370667 | 42.594 | 68.125333 |
