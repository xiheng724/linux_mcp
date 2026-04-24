# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Big picture

`linux-mcp` is a kernel-assisted MCP-style control plane for Linux. Execution stays in userspace; arbitration and durable visibility move into a kernel module. The end-to-end request path is:

```
llm-app  ──UDS JSON RPC──▶  mcpd  ──Generic Netlink──▶  kernel_mcp
                              │                             │
                              ▼                             ▼
                        tool-app (UDS)               /sys/kernel/mcp/...
```

Key invariant: `llm-app` never talks directly to a tool service. Every `tool:exec` is arbitrated by the kernel and forwarded by `mcpd`. The authoritative semantic catalog lives in `tool-app/manifests/*.json` — tool identity, risk tags, and input schemas all come from there, are hashed by `mcpd`, and registered into the kernel's tool registry. The kernel's policy is deliberately narrow: deny unknown agents or hash mismatches, defer risky tools, allow the rest. No JSON parsing and no tool execution happens in kernel space.

## Component responsibilities

- **[kernel-mcp/](kernel-mcp/)** — Linux kernel module. Owns the `KERNEL_MCP` Generic Netlink family, tool/agent registries, approval tickets, session-binding checks, and sysfs exposure under `/sys/kernel/mcp/`. Built out-of-tree against `/lib/modules/$(uname -r)/build`.
- **[mcpd/](mcpd/)** — Python userspace gateway. The only component that understands both manifest semantics and runtime endpoints. Loads manifests ([manifest_loader.py](mcpd/manifest_loader.py)), reconciles tool state with the kernel ([reconcile_kernel.py](mcpd/reconcile_kernel.py)), binds sessions to UDS peer credentials ([session_store.py](mcpd/session_store.py)), validates payloads, and forwards RPCs. Listens on `/tmp/mcpd.sock`. Entrypoint [mcpd/server.py](mcpd/server.py).
- **[tool-app/](tool-app/)** — Demo tool backends plus the manifest directory that is the semantic source of truth. Default endpoints live under `/tmp/linux-mcp-apps/` (`uds_rpc`); the demo also ships one `uds_abstract` backend ([16_abstract_demo_app.json](tool-app/manifests/16_abstract_demo_app.json)) so the abstract-namespace path is exercised end-to-end.
- **[llm-app/](llm-app/)** — CLI ([cli.py](llm-app/cli.py)) and PySide6 GUI ([gui_app.py](llm-app/gui_app.py)) frontends. Planner speaks any OpenAI-compatible `/chat/completions` endpoint (OpenAI, DeepSeek, Groq, Together, OpenRouter, or a local Ollama/vLLM/LM Studio) via `--model-url` + `--model-name`; reads `LLM_API_KEY` (or legacy `DEEPSEEK_API_KEY`). Only speaks `list_apps` / `list_tools` / `open_session` / `tool:exec` to `mcpd`.
- **[client/](client/)** — Shared schema constants and low-level debug helpers.
- **[scripts/](scripts/)** — Operational entrypoints for build, launch, smoke, and acceptance.

When changing wire schemas, both `mcpd` and `client/` share constants — run `make schema-verify` to catch drift.

## Common commands

Build and load the kernel module (root required):

```bash
sudo bash scripts/build_kernel.sh
sudo bash scripts/unload_module.sh || true
sudo bash scripts/load_module.sh
```

Verify schema sync between `mcpd` and `client/`:

```bash
make schema-verify   # wraps scripts/verify_schema_sync.py
```

Bring up the full stack:

```bash
bash scripts/run_smoke.sh            # preflight checks
bash scripts/run_tool_services.sh    # start demo tool-app services
bash scripts/run_mcpd.sh             # start the gateway
```

Exercise end-to-end:

```bash
export LLM_API_KEY="your_key"     # or legacy DEEPSEEK_API_KEY
# Default endpoint is DeepSeek for backward compat; any OpenAI-compatible
# provider works via --model-url + --model-name, e.g.
#   --model-url https://api.openai.com/v1/chat/completions --model-name gpt-4o-mini
#   --model-url http://localhost:11434/v1/chat/completions --model-name llama3.1
python3 llm-app/cli.py --once "show system info"
# GUI:
source .venv/bin/activate && python llm-app/gui_app.py
```

Shutdown:

```bash
bash scripts/stop_mcpd.sh
bash scripts/stop_tool_services.sh
sudo bash scripts/unload_module.sh
```

Full local confidence check (kernel lifecycle, startup, end-to-end, sysfs, reload):

```bash
sudo bash scripts/demo_acceptance.sh
```

Focused acceptance for the recent control-plane / runtime hardening work (no LLM API key required — covers registration-time `binary_hash` pin, `uds_abstract`, native / same-PID-execve / python-script swap regressions, probe-failure fail-closed, dynamic re-registration, and post-crash `call_log` readability):

```bash
sudo bash scripts/accept_new_features.sh
```

Run under systemd with reduced privileges ([deploy/systemd/mcpd.service](deploy/systemd/mcpd.service) — dedicated `mcpd` user + `AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_PTRACE`; see [deploy/systemd/README.md](deploy/systemd/README.md) for one-time setup).

## Observability

Kernel state is inspectable via sysfs even across `mcpd` restart:

```bash
ls /sys/kernel/mcp/tools        /sys/kernel/mcp/agents
cat /sys/kernel/mcp/tools/<id>/{name,hash,binary_hash,binary_hash_state,registered_at_epoch}
cat /sys/kernel/mcp/tool_catalog_epoch
cat /sys/kernel/mcp/agents/<id>/{allow,defer,completed_ok,last_reason,last_exec_ms,opened_at_epoch}
```

`binary_hash_state ∈ {unpinned, live_pinned}` disambiguates the two reasons `binary_hash` can read empty: "probe never successfully locked an identity" vs. "pinned to some value now". Acceptance scripts check state rather than string length so a silent half-failed state cannot hide behind an empty digest.

Userspace logs: `/tmp/mcpd-$(id -u).log` and `/tmp/linux-mcp-app-*.log`.

## Experiments

Experiment scripts (`run_linux_mcp_evaluation.sh`, `run_repeated_linux_mcp.sh`, `run_security_evaluation.sh`, `run_netlink_microbenchmark.sh`, etc.) and `scripts/experiments/` live on the `experiment/evaluation-suite-20260403` branch, **not on main**. Curated result snapshots remain in [experiment-results/](experiment-results/) on main for reference. If a user asks to run or modify an experiment, check out that branch first.

## Constraints to respect

- Do not add JSON parsing or tool execution inside the kernel module — the split is intentional.
- Manifests are authoritative; do not hardcode tool identity or endpoints in `mcpd` or `llm-app`.
- Session state is userspace-owned and does not survive `mcpd` restart; approval state in the kernel does.
- Transport policy is operator-configurable via [mcpd/transport.py](mcpd/transport.py) and [mcpd/config.py](mcpd/config.py) (`$LINUX_MCP_CONFIG` or `/etc/linux-mcp/mcpd.toml`). The **defaults** are `transport = "uds_rpc"` with endpoints under `/tmp/linux-mcp-apps/`; `uds_abstract` is also available but disabled until `allow_name_pattern` is configured. `vsock_rpc` is a reserved name without a dialer yet.
- `mcpd` requires `CAP_NET_ADMIN` (netlink ops are `GENL_ADMIN_PERM`) and `CAP_SYS_PTRACE` (probe reads `/proc/<pid>/exe` across uids). Either run as root or grant those caps via a systemd unit — `run_mcpd.sh` accepts both.
- When `mcpd` runs privileged, [security].`allowed_backend_uids` must be set explicitly in the TOML, OR the launcher must set `LINUX_MCP_TRUST_SUDO_UID=1` to opt into trusting `$SUDO_UID`. The implicit-`{0}` default was removed on purpose: it silently rejected every non-root backend and left `binary_hash` unpinned. `mcpd` now refuses to start rather than fall back.
- The planner has no offline fallback — features that require planning will fail without an LLM API key (`LLM_API_KEY`, or the legacy `DEEPSEEK_API_KEY`). Any OpenAI-compatible `/chat/completions` endpoint works (OpenAI, DeepSeek, Groq, Together, OpenRouter, local Ollama/vLLM/LM Studio, etc.); select it via `--model-url` + `--model-name`.
- Per-tool catalog epoch semantics (commit `23351a5`): only tools whose own `registered_at_epoch` advanced past a session's `opened_at_epoch` DENY with `catalog_stale_rebind_required`. Adding/removing an unrelated manifest no longer invalidates every existing session — `llm-app` still auto-rebinds on the stale reason so this stays invisible to clients. Tests that expect global invalidation are out of date with the implementation.
