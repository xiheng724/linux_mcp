# CLAUDE.md

## Architecture

Kernel-assisted MCP control plane. Userspace executes; the kernel module arbitrates and persists audit state.

```
llm-app  ──UDS JSON──▶  mcpd  ──Generic Netlink──▶  kernel_mcp
                          │                            │
                          ▼                            ▼
                    tool-app (UDS)              /sys/kernel/mcp/...
```

Hard invariants — violating any of these is an architectural regression:

- `llm-app` never connects to a tool service directly; every `tool:exec` is arbitrated by the kernel and forwarded by `mcpd`.
- `tool-app/manifests/*.json` is the only source of tool identity, risk tags, and input schemas. Do not hardcode these in `mcpd` or `llm-app`.
- The kernel module does not parse JSON and does not execute tools. Adding either collapses the split.
- Wire-schema constants are shared between `mcpd/` and `client/`. After changing either, run `make schema-verify`.

## Kernel C modification protocol

**Dev environment**: build and load happen **only inside the VMware Linux VM**. Never `insmod` against any kernel that hosts work you care about — take a VM snapshot before each load.

The target kernel is whatever `uname -r` reports inside the VM. If the version is not already pinned in this conversation, ask before writing kernel code.

### Before writing

1. **Plan first.** Output: files touched, function signatures, locking discipline (lock state at entry/exit, acquisition order), error-path cleanup, refcount lifecycle. Wait for review before implementing.
2. **Mutate from existing code.** New sysfs attrs, netlink ops, or show handlers must be modeled on an existing one in [kernel-mcp/src/kernel_mcp_main.c](kernel-mcp/src/kernel_mcp_main.c) — match its locking order, snapshot pattern, and `goto err_*` labels. Do not start from a blank file.
3. **Pin every kernel API call.** Before using any of `genlmsg_*`, `nla_*`, `proc_create*`, `kobject_*`, RCU helpers, `copy_*_user`, etc., grep the in-tree headers under `/lib/modules/$(uname -r)/build/include/` inside the VM and confirm the signature for that exact kernel version. Do not rely on memory.
4. **Declare context up front.** State whether the function runs in process / softirq / atomic context, whether it may sleep, and what locks the caller holds.

### After writing

5. **Self-audit checklist** — answer yes/no per item, not "looks fine":
   - All allocations (`kmalloc`, `alloc_skb`, `kobject_create_*`) freed on every error path?
   - Every `mutex_lock` / `spin_lock*` released on every return path?
   - No sleeping calls (`kmalloc(GFP_KERNEL)`, `mutex_lock`, `copy_*_user`) while holding a spinlock?
   - All user-controlled lengths bounded before use?
   - Every `nla_put_*` failure jumps to err?
   - RCU readers use `*_rcu` accessors and matching `rcu_read_lock`?
   - genl callbacks return 0 or a negative errno only?
   - Admin-only ops carry `GENL_ADMIN_PERM`?
6. **Lint must be green** before declaring done:
   - `scripts/checkpatch.pl --no-tree -f kernel-mcp/src/kernel_mcp_main.c`
   - `make W=1 C=2 -C /lib/modules/$(uname -r)/build M=$PWD/kernel-mcp` (sparse must be clean)
   - `make coccicheck M=$PWD/kernel-mcp` if available
7. **Load only inside the VMware VM**, after a fresh snapshot. The VM's kernel cmdline must include `panic_on_warn=1`; `CONFIG_PROVE_LOCKING`, `CONFIG_KASAN`, and `CONFIG_DEBUG_KMEMLEAK` must be on. If anything fires, paste the full oops/lockdep trace back.

### Off-limits without explicit human review

Draft only — final version is hand-written and merged by me:

- Changing sysfs / procfs ABI signatures.
- Changing lock acquisition order anywhere in the module.
- Introducing a new RCU grace-period dependency.
- Modifying `nla_policy` for an existing op.
- Touching `copy_from_user` paths.

## Userspace constraints

- Session state is userspace-only and dies with `mcpd`; approval/audit state lives in the kernel and survives. Don't write tests that expect sessions to outlast a daemon restart.
- Per-tool catalog epoch (commit `23351a5`): only the *affected* tool's session sees `catalog_stale_rebind_required` on manifest reload — `llm-app` auto-rebinds. Tests expecting global invalidation are out of date; fix the test, not the kernel.
- `mcpd` privileged-run trap: `[security].allowed_backend_uids` must be set explicitly OR `LINUX_MCP_TRUST_SUDO_UID=1` must be set. The implicit `{0}` fallback was removed on purpose because it silently rejected every non-root backend and left `binary_hash` unpinned. Don't add it back; `mcpd` refuses to start instead.
- `vsock_rpc` is a reserved transport name with no dialer wired up — configuring it will not work.


## Operational essentials

```bash
# Kernel module lifecycle (inside VM, root)
sudo bash scripts/build_kernel.sh
sudo bash scripts/unload_module.sh || true
sudo bash scripts/load_module.sh

# Stack up
make schema-verify
bash scripts/run_tool_services.sh
bash scripts/run_mcpd.sh

# Acceptance
sudo bash scripts/demo_acceptance.sh         # full lifecycle + e2e + sysfs (no LLM key needed)
sudo bash scripts/accept_new_features.sh     # control-plane / runtime-hardening focused

# Frontends
python3 llm-app/cli.py --once "<prompt>"
python  llm-app/gui_app.py                   # PySide6
```
