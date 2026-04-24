# linux-mcp

![status](https://img.shields.io/badge/status-active%20prototype-2f855a)
![platform](https://img.shields.io/badge/platform-Linux-1f6feb)
![kernel](https://img.shields.io/badge/kernel-control%20plane-informational)
![transport](https://img.shields.io/badge/transport-UDS%20RPC-orange)

`linux-mcp` is a clean-room prototype for a kernel-assisted MCP-style control plane on Linux. It combines:

- a Linux kernel module for control-plane arbitration and state exposure
- a userspace gateway that understands tool semantics and runtime endpoints
- demo tool services exposed over Unix domain sockets
- an LLM-driven CLI and GUI client

The repository is not a phase-based sketch. It is a runnable end-to-end system with a concrete request path, a concrete tool manifest format, and a maintained experiment workflow.

## At a Glance

| Topic | Summary |
|---|---|
| Core idea | Keep execution in userspace, but move control-plane arbitration and durable visibility into the kernel |
| Execution path | `llm-app -> mcpd -> kernel arbitration -> tool-app -> mcpd -> llm-app` |
| Semantic source of truth | `tool-app/manifests/*.json` |
| Runtime gateway | `mcpd` |
| Kernel interface | Generic Netlink + sysfs |
| Main experiments | linux_mcp comparative evaluation plus two supplementary experiments: semantic-hash runtime substitution and Generic Netlink RTT microbenchmark |
| Retained results | 3 actively referenced snapshots under [experiment-results/](experiment-results/): 1 main run and 2 supplementary experiments |

## Highlights

- Kernel-visible control-plane state without moving tool execution into the kernel
- Manifest-driven catalog export through `list_apps` and `list_tools`
- Session binding against real UDS peer credentials, enforced by `allowed_backend_uids` on every probe and exec dial
- Incremental catalog reconciliation with kernel-enforced **per-tool** `registered_at_epoch` and `llm-app` auto-rebind on stale sessions (adding or changing one tool no longer invalidates sessions bound to unrelated tools)
- TOFU-locked backend `binary_hash` so manifest-stable tools cannot silently swap executables at runtime. For native backends the kernel pin is the full SHA-256 of `/proc/<pid>/exe`; for interpreter-hosted backends (Python, Ruby, ...) the pin is `sha256(interpreter_digest ":" script_digest)` so swapping the script on disk invalidates the pin on the next restart. Application code cannot be verified live because interpreters only read the script at startup.
- Explicit `binary_hash_state` (`unpinned` / `live_pinned`) exported under sysfs so a half-failed probe cannot masquerade as a freshly-started tool via an empty digest string
- Approval-gated mediation for risky tools
- Per-agent kernel `call_log` with payload/response summary hashes for post-crash audit
- Operator-configurable transport policy in `mcpd` (`uds_rpc` + `uds_abstract`; `vsock_rpc` is a reserved name that is intentionally not implemented)
- Capability-based runtime path: `mcpd` can run as a dedicated service user with only `CAP_NET_ADMIN + CAP_SYS_PTRACE` instead of full root — see [deploy/systemd/mcpd.service](deploy/systemd/mcpd.service)
- Fail-closed security policy: when `mcpd` runs privileged without an explicit `allowed_backend_uids`, it refuses to start instead of defaulting to a self-only allowlist that silently rejects every non-root backend
- A paper-ready `linux_mcp` snapshot with controlled-noise latency, throughput, attack, and daemon-failure results
- Sysfs-backed observability for debugging and post-crash inspection

## seccomp in this repo

`seccomp` (secure computing mode) is Linux syscall filtering.
In this repository, `seccomp` means a hardened userspace baseline (`userspace + sandbox + audit logging + stricter checks`) used as the comparison target.

## Overview

### What this project demonstrates

- Kernel-visible control-plane state for tool mediation
- Userspace execution with kernel-backed arbitration
- Manifest-driven app and tool discovery
- Session binding between a client process and mediated tool requests
- Dynamic tool catalog updates without restarting the whole stack
- Post-crash inspection of recent mediated calls through kernel-held summaries
- Approval-gated execution for risky tools
- Sysfs visibility for post-mortem inspection and debugging

### What this project does not try to do

- It does not move tool execution into the kernel
- It does not parse JSON in kernel space
- It is not a general policy engine
- It does not claim complete execution security

## Architecture

### End-to-end request path

```mermaid
flowchart LR
    A[llm-app<br/>CLI / GUI] -->|UDS JSON RPC| B[mcpd]
    B -->|Generic Netlink| C[kernel_mcp]
    C -->|ALLOW / DENY / DEFER| B
    B -->|UDS JSON RPC| D[tool-app service]
    D --> B
    B --> A
    C --> E[/sys/kernel/mcp/.../]
```

### Control-plane split

```mermaid
flowchart TB
    subgraph Semantics[Manifest semantics]
        M1[tool-app/manifests/*.json]
        M2[tool id / app id / risk tags / input schema / examples]
    end

    subgraph Gateway[Userspace runtime bridge]
        G1[mcpd]
        G2[list_apps / list_tools / open_session / tool:exec]
        G3[session binding + payload validation + RPC forwarding]
    end

    subgraph Kernel[Kernel arbitration]
        K1[kernel_mcp]
        K2[tool registry]
        K3[agent registry]
        K4[approval tickets + sysfs state]
    end

    M1 --> G1
    M2 --> G1
    G1 --> K1
```

### Request lifecycle

```text
1. mcpd loads tool manifests
2. mcpd registers manifest tools in the kernel
3. llm-app queries list_apps / list_tools
4. llm-app opens a short-lived session
5. mcpd binds the session to UDS peer credentials
6. tool:exec is arbitrated by the kernel
7. mcpd forwards the call to the selected tool-app service
8. completion is reported back to the kernel
9. state remains inspectable through sysfs
```

### Design principles

| Principle | How the repository applies it |
|---|---|
| Kernel is control plane only | No JSON parsing or tool execution in kernel space |
| Userspace owns semantics | `mcpd` loads manifests, validates payloads, and knows endpoints |
| Manifest is authoritative | Tool identity, hash, risk tags, examples, and input schema come from manifests |
| Client is mediated | `llm-app` never talks directly to tool services |
| Observability matters | Agent and tool state remain visible through sysfs |

## Repository Layout

```text
linux-mcp/
├── kernel-mcp/        Linux kernel module and UAPI-facing control-plane logic
├── mcpd/              Userspace gateway, manifest loader, session store, RPC server
├── tool-app/          Demo tool services and manifest definitions
├── llm-app/           CLI and GUI client
├── client/            Schema constants and low-level client/debug helpers
├── scripts/           Build, launch, stop, smoke, acceptance, and experiment entrypoints
├── experiment-results/ Retained final and repeated experiment outputs
└── README.md
```

### Directory guide

| Path | Purpose |
|---|---|
| [kernel-mcp/](/home/lxh/Code/linux-mcp/kernel-mcp) | Kernel module source. Implements Generic Netlink commands, tool and agent state, approval tickets, and sysfs exposure. |
| [mcpd/](/home/lxh/Code/linux-mcp/mcpd) | Control-plane gateway. Loads manifests, reconciles tool state with the kernel, validates requests, and forwards tool RPCs. |
| [tool-app/](/home/lxh/Code/linux-mcp/tool-app) | Demo app backends and manifest files. This repository intentionally treats this directory as the semantic source of truth. |
| [llm-app/](/home/lxh/Code/linux-mcp/llm-app) | User-facing clients. The CLI and GUI both route exclusively through `mcpd`. |
| [client/](/home/lxh/Code/linux-mcp/client) | Shared schema constants and simple helpers for debugging or low-level interaction. |
| [scripts/](/home/lxh/Code/linux-mcp/scripts) | Operational entrypoints for build, launch, smoke checks, acceptance, and experiments. |
| [experiment-results/](/home/lxh/Code/linux-mcp/experiment-results) | Curated experiment artifacts kept in-tree for reference. |

## Component Responsibilities

### `kernel-mcp`

The kernel module is the control-plane enforcement point, not the execution engine.
It provides the `KERNEL_MCP` Generic Netlink family, tool/agent state, approval tickets, catalog epoch tracking, backend identity checks, per-agent call summaries, and sysfs exposure under `/sys/kernel/mcp/...`.
The demo policy is intentionally simple: deny unknown agents, stale bindings, hash mismatches, and backend binary mismatches; defer risky tools; allow the rest.

### `mcpd`

`mcpd` is the only component that understands both tool semantics and runtime endpoints.
It loads manifests, computes full SHA-256 semantic hashes, incrementally reconciles the kernel tool registry, exposes `/tmp/mcpd.sock`, binds sessions to UDS peers plus catalog epoch, validates payloads, forwards tool RPCs across the configured transport policy, and reports completion summaries back to the kernel.

### `tool-app`

`tool-app` contains demo backends and manifest definitions. The authoritative catalog lives in `tool-app/manifests/*.json` and is surfaced at runtime through `mcpd`.

### `llm-app`

`llm-app` provides both CLI and GUI frontends. It talks only to `mcpd` through `list_apps`, `list_tools`, `open_session`, and `tool:exec`. The planner speaks to any OpenAI-compatible `/chat/completions` endpoint — OpenAI, DeepSeek, Groq, Together, OpenRouter, or a local Ollama/vLLM/LM Studio — selected via `--model-url` and `--model-name`; the API key is read from `LLM_API_KEY` (with `DEEPSEEK_API_KEY` accepted as a legacy fallback).

## Manifest Model

The manifest layer is the semantic source of truth for the system.

### Current constraints

- manifest semantics are hashed into exported tool identity with full 64-hex SHA-256
- `uds_rpc` remains the primary transport; `uds_abstract` is wired into the default demo path via [tool-app/manifests/16_abstract_demo_app.json](tool-app/manifests/16_abstract_demo_app.json) and [config/mcpd.demo.toml](config/mcpd.demo.toml)
- `vsock_rpc` is **not implemented** — the transport validator refuses it on purpose; peer-attestation design is a future item
- path-based `uds_rpc` endpoints must match the configured allow prefixes; the built-in default is `/tmp/linux-mcp-apps/`

## Getting Started

### Requirements

| Category | Requirement |
|---|---|
| OS | Linux |
| Build | `bash`, `make`, `gcc`, `python3` |
| Kernel build | headers for `$(uname -r)` at `/lib/modules/$(uname -r)/build` |
| Privileges | root for kernel module load/unload; `mcpd` needs `CAP_NET_ADMIN` + `CAP_SYS_PTRACE` (root or systemd `AmbientCapabilities`) |
| LLM client | any OpenAI-compatible endpoint; `LLM_API_KEY` (or legacy `DEEPSEEK_API_KEY`) |
| GUI | `PySide6` |

### Quick start

```bash
cd ~/Code/linux-mcp
bash scripts/run_smoke.sh
sudo bash scripts/build_kernel.sh
sudo bash scripts/unload_module.sh || true
sudo bash scripts/load_module.sh
make schema-verify
bash scripts/run_tool_services.sh
sudo bash scripts/run_mcpd.sh
export LLM_API_KEY="your_key"     # or legacy DEEPSEEK_API_KEY
python3 llm-app/cli.py --once "show system info"
```

The planner defaults to DeepSeek's endpoint for backward compatibility; point it elsewhere with `--model-url` + `--model-name` (e.g. `https://api.openai.com/v1/chat/completions` + `gpt-4o-mini`, or a local `http://localhost:11434/v1/chat/completions` + `llama3.1`).

`run_tool_services.sh` will auto-build the bundled native demo binaries on first use if they are missing.

### Shutdown

```bash
sudo bash scripts/stop_mcpd.sh
bash scripts/stop_tool_services.sh
sudo bash scripts/unload_module.sh
```

### GUI

```bash
cd ~/Code/linux-mcp
source .venv/bin/activate
python llm-app/gui_app.py
```

## Observability

### Kernel state

```bash
ls /sys/kernel/mcp/tools
cat /sys/kernel/mcp/tools/2/name
cat /sys/kernel/mcp/tools/2/hash
cat /sys/kernel/mcp/tools/2/binary_hash
cat /sys/kernel/mcp/tools/2/binary_hash_state      # unpinned | live_pinned
cat /sys/kernel/mcp/tools/2/registered_at_epoch
cat /sys/kernel/mcp/tool_catalog_epoch

ls /sys/kernel/mcp/agents
cat /sys/kernel/mcp/agents/a1/allow
cat /sys/kernel/mcp/agents/a1/defer
cat /sys/kernel/mcp/agents/a1/completed_ok
cat /sys/kernel/mcp/agents/a1/last_reason
cat /sys/kernel/mcp/agents/a1/last_exec_ms
cat /sys/kernel/mcp/agents/a1/opened_at_epoch
sudo python3 scripts/mcpctl_dump_calls.py a1
```

`binary_hash_state` is the authoritative signal for "did registration successfully TOFU-lock a backend identity?". An empty `binary_hash` string alone used to conflate "never pinned" with "pinned to a currently-empty value after a reset"; the explicit state string removes that ambiguity and is what `scripts/accept_new_features.sh` asserts on.

### Userspace logs

```bash
sudo cat /tmp/mcpd-0.log
ls /tmp/linux-mcp-app-*.log
```

## Experiments

> All the experiments are conducted on experiment/evaluation-suite-20260403 branch.

Experiment-specific details live in [scripts/experiments/README.md](scripts/experiments/README.md).

At repository level, the curated outputs are the main linux_mcp comparative run plus two supplementary experiments.

### Experiment entrypoints

| Command | Scope |
|---|---|
| `bash scripts/run_linux_mcp_evaluation.sh` | Single linux_mcp evaluation |
| `bash scripts/run_repeated_linux_mcp.sh` | Repeated linux_mcp runs |
| `bash scripts/run_security_evaluation.sh` | Attack-driven security evaluation (optional, not part of current curated snapshots) |
| `bash scripts/run_repeated_security.sh` | Repeated security aggregation (optional, not part of current curated snapshots) |

### Retained result snapshots

Currently referenced snapshots:

- [linux-mcp-paper-final-n5/run-20260405-173020](experiment-results/linux-mcp-paper-final-n5/run-20260405-173020)
- [semantic-hash-injection-a/run-20260406-111420](experiment-results/semantic-hash-injection-a/run-20260406-111420)
- [netlink-microbench-e/run-20260406-111914](experiment-results/netlink-microbench-e/run-20260406-111914)

### Latest paper-ready run summary (n=5)

Primary run:

- [linux-mcp-paper-final-n5/run-20260405-173020](experiment-results/linux-mcp-paper-final-n5/run-20260405-173020)
- report: [linux_mcp_report.md](experiment-results/linux-mcp-paper-final-n5/run-20260405-173020/linux_mcp_report.md)
- concise interpretation: [experiment_report.md](experiment_report.md)
- figures: [plots/](experiment-results/linux-mcp-paper-final-n5/run-20260405-173020/plots)

Key observations:

- Small and medium payload (`100 B`, `10 KB`) end-to-end latency differences are small.
- At `1 MB`, userspace and kernel stay close (`7.226 ms` vs `6.908 ms`), while seccomp is slower (`9.330 ms`).
- Throughput stays in the same order of magnitude across modes (about `1000-1220 RPS` under this demo workload).
- Attack matrix shows kernel path blocks all maintained spoof/replay/substitute/escalation cases in this run.
- Kernel-held approval state remains visible across daemon failure in this setup.

### Supplementary experiment snapshots

- Semantic-hash runtime substitution: [semantic-hash-injection-a/run-20260406-111420](experiment-results/semantic-hash-injection-a/run-20260406-111420)
  - `30/30` live-planned chains selected the legitimate `notes_app`
  - `30/30` runtime `tool_hash` substitutions were denied by kernel with `reason=hash_mismatch`
  - figures: [plots/](experiment-results/semantic-hash-injection-a/run-20260406-111420/plots)
- Generic Netlink RTT microbenchmark: [netlink-microbench-e/run-20260406-111914](experiment-results/netlink-microbench-e/run-20260406-111914)
  - bare RTT: `0.008196 ms`
  - full RTT: `0.009315 ms`
  - lookup overhead mean: `0.001119 ms`
  - figures: [plots/](experiment-results/netlink-microbench-e/run-20260406-111914/plots)

### How to reproduce the retained results

Main comparative run (`linux-mcp-paper-final-n5` style):

```bash
sudo bash scripts/build_kernel.sh
sudo bash scripts/unload_module.sh || true
sudo bash scripts/load_module.sh
bash scripts/run_linux_mcp_evaluation.sh --output-dir experiment-results/linux-mcp-paper-final-n5
```

Purpose: reproduce the main userspace / seccomp / kernel comparison.

Semantic-hash runtime substitution:

```bash
export LLM_API_KEY="your_key"     # or legacy DEEPSEEK_API_KEY
bash scripts/run_semantic_hash_prompt_injection.sh --output-dir experiment-results/semantic-hash-injection-a
```

Purpose: reproduce the supplementary security result for runtime `tool_hash` substitution.

Generic Netlink RTT microbenchmark:

```bash
sudo bash scripts/build_kernel.sh
sudo bash scripts/unload_module.sh || true
sudo bash scripts/load_module.sh
bash scripts/run_netlink_microbenchmark.sh --output-dir experiment-results/netlink-microbench-e
```

Purpose: reproduce the supplementary microbenchmark separating bare Generic Netlink RTT from the full `TOOL_REQUEST` path.

### Where to look first

- Latency overview figure: [figure_latency_by_payload.png](experiment-results/linux-mcp-paper-final-n5/run-20260405-173020/plots/figure_latency_by_payload.png)
- Throughput figure: [figure_throughput_by_agents.png](experiment-results/linux-mcp-paper-final-n5/run-20260405-173020/plots/figure_throughput_by_agents.png)
- Attack heatmap: [figure_attack_heatmap.png](experiment-results/linux-mcp-paper-final-n5/run-20260405-173020/plots/figure_attack_heatmap.png)
- Semantic-hash block rate figure: [figure_kernel_block_rate_by_case.png](experiment-results/semantic-hash-injection-a/run-20260406-111420/plots/figure_kernel_block_rate_by_case.png)
- Netlink RTT boxplot: [figure_netlink_rtt_boxplot.png](experiment-results/netlink-microbench-e/run-20260406-111914/plots/figure_netlink_rtt_boxplot.png)

## Limitations

- tool planning and payload construction depend on an OpenAI-compatible Chat Completions endpoint (DeepSeek/OpenAI/Groq/Ollama/vLLM/etc.); there is no offline planner
- kernel policy is a demo policy, not a general authorization framework
- retained experiment snapshots were captured before `uds_abstract` entered the default demo flow; new runs exercise both `uds_rpc` and `uds_abstract`
- `vsock_rpc` is a reserved transport name only — the dialer is deliberately not implemented and there is no peer-attestation story yet
- the data plane still uses framed JSON RPC
- session state is userspace-owned and does not survive daemon restart the way approval state can

## Acceptance Workflow

For the most complete local confidence check (includes an `llm-app` end-to-end call, so requires `LLM_API_KEY` — or legacy `DEEPSEEK_API_KEY`):

```bash
sudo bash scripts/demo_acceptance.sh
```

It covers kernel/module lifecycle, tool and `mcpd` startup, LLM-key validation, a small end-to-end CLI flow, sysfs inspection, shutdown, and reload validation.

For the control-plane / runtime-hardening regressions on their own (no LLM key, no planner; 14 focused steps):

```bash
sudo bash scripts/accept_new_features.sh
```

Covers registration-time `binary_hash` pin via `binary_hash_state=live_pinned`, the `uds_abstract` demo path, native binary replacement, same-PID `execve` replacement, interpreter-hosted Python script swap, probe-failure-must-not-reuse-cached-digest, dynamic manifest re-registration with per-tool epoch semantics, and kernel `call_log` readability after an `mcpd` crash.

### Running `mcpd` unprivileged under systemd

`deploy/systemd/mcpd.service` runs `mcpd` as a dedicated `mcpd` service user with `AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_PTRACE` instead of full root. See [deploy/systemd/README.md](deploy/systemd/README.md) for the one-time `useradd` / config-install / `daemon-reload` steps. Under this path, `LINUX_MCP_TRUST_SUDO_UID` is intentionally not honored — backend uid trust must be declared in `/etc/linux-mcp/mcpd.toml`.
