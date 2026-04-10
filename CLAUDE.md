# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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
- **[tool-app/](tool-app/)** — Demo tool backends plus the manifest directory that is the semantic source of truth. Endpoints must live under `/tmp/linux-mcp-apps/` and only `transport = "uds_rpc"` is supported.
- **[llm-app/](llm-app/)** — CLI ([cli.py](llm-app/cli.py)) and PySide6 GUI ([gui_app.py](llm-app/gui_app.py)) frontends. Planner depends on `DEEPSEEK_API_KEY`. Only speaks `list_apps` / `list_tools` / `open_session` / `tool:exec` to `mcpd`.
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
export DEEPSEEK_API_KEY="your_key"
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

## Observability

Kernel state is inspectable via sysfs even across `mcpd` restart:

```bash
ls /sys/kernel/mcp/tools        /sys/kernel/mcp/agents
cat /sys/kernel/mcp/tools/<id>/{name,hash}
cat /sys/kernel/mcp/agents/<id>/{allow,defer,completed_ok,last_reason,last_exec_ms}
```

Userspace logs: `/tmp/mcpd-$(id -u).log` and `/tmp/linux-mcp-app-*.log`.

## Experiments

Experiment scripts (`run_linux_mcp_evaluation.sh`, `run_repeated_linux_mcp.sh`, `run_security_evaluation.sh`, `run_netlink_microbenchmark.sh`, etc.) and `scripts/experiments/` live on the `experiment/evaluation-suite-20260403` branch, **not on main**. Curated result snapshots remain in [experiment-results/](experiment-results/) on main for reference. If a user asks to run or modify an experiment, check out that branch first.

## Constraints to respect

- Do not add JSON parsing or tool execution inside the kernel module — the split is intentional.
- Manifests are authoritative; do not hardcode tool identity or endpoints in `mcpd` or `llm-app`.
- Session state is userspace-owned and does not survive `mcpd` restart; approval state in the kernel does.
- Only `uds_rpc` transport is supported; endpoints must live under `/tmp/linux-mcp-apps/`.
- The planner has no offline fallback — features that require planning will fail without `DEEPSEEK_API_KEY`.
