#!/usr/bin/env bash
# Focused acceptance for the recent control-plane/runtime hardening work.
#
# Covers:
#   - registration-time binary_hash pin visibility in sysfs
#   - uds_abstract demo path
#   - native binary replacement regression
#   - same-PID execve replacement regression
#   - interpreter-hosted script swap regression
#   - probe failure must not reuse cached digest
#   - dynamic manifest re-registration + catalog_epoch invalidation
#   - kernel call_log survives mcpd crash
#
# Unlike scripts/demo_acceptance.sh, this path does not invoke llm-app
# and does not require an LLM API key (LLM_API_KEY / DEEPSEEK_API_KEY).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SUDO="sudo"
if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
fi

NORMAL_USER="${SUDO_USER:-}"
if [[ -z "$NORMAL_USER" || "$NORMAL_USER" == "root" ]]; then
  NORMAL_USER="$(id -un)"
fi

run_as_user() {
  if [[ "$(id -u)" -eq 0 && "$NORMAL_USER" != "root" ]]; then
    sudo -u "$NORMAL_USER" "$@"
  else
    "$@"
  fi
}

tool_binary_hash() {
  local tool_id="$1"
  local path="/sys/kernel/mcp/tools/${tool_id}/binary_hash"
  [[ -r "$path" ]] || return 1
  tr -d '\n\0 ' <"$path"
}

tool_binary_hash_state() {
  local tool_id="$1"
  local path="/sys/kernel/mcp/tools/${tool_id}/binary_hash_state"
  [[ -r "$path" ]] || return 1
  tr -d '\n\0 ' <"$path"
}

cleanup() {
  set +e
  run_as_user bash scripts/stop_tool_services.sh >/dev/null 2>&1 || true
  ${SUDO} bash scripts/stop_mcpd.sh >/dev/null 2>&1 || true
  ${SUDO} bash scripts/unload_module.sh >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[accept-new] step 0: basic smoke and schema sync"
run_as_user bash scripts/run_smoke.sh

echo "[accept-new] step 1: build native demo binaries"
run_as_user make -C "$ROOT_DIR" native-demos

echo "[accept-new] step 2: build and reload kernel module"
${SUDO} bash scripts/build_kernel.sh
${SUDO} bash scripts/unload_module.sh >/dev/null 2>&1 || true
${SUDO} bash scripts/load_module.sh

echo "[accept-new] step 3: stop stale user-space services"
run_as_user bash scripts/stop_tool_services.sh >/dev/null 2>&1 || true
${SUDO} bash scripts/stop_mcpd.sh >/dev/null 2>&1 || true

echo "[accept-new] step 4: start demo tool services"
run_as_user bash scripts/run_tool_services.sh

# mcpd must run privileged (CAP_NET_ADMIN for netlink, CAP_SYS_PTRACE
# for cross-uid /proc/<pid>/exe reads). In the demo flow that means
# root. run_mcpd.sh itself exports LINUX_MCP_TRUST_SUDO_UID=1 so mcpd's
# allowed_backend_uids resolves to {0, $SUDO_UID} and accepts the
# tool-app backends that step 4 launched as the invoking user.
echo "[accept-new] step 5: start mcpd"
${SUDO} bash scripts/run_mcpd.sh

echo "[accept-new] step 6: unit probe regressions"
run_as_user python3 scripts/test_probe_unit.py

echo "[accept-new] step 7: registration-time binary_hash and catalog epoch visible"
for tool_id in 2 44 45; do
  state="$(tool_binary_hash_state "$tool_id" || true)"
  if [[ "$state" != "live_pinned" ]]; then
    echo "FAIL: tool ${tool_id} binary_hash_state=${state:-<missing>} (expected live_pinned)"
    echo "  hint: check mcpd log for probe failures (uid allowlist, endpoint refused, interpreter detection, ...)"
    exit 1
  fi
  pinned="$(tool_binary_hash "$tool_id" || true)"
  if [[ -z "$pinned" ]]; then
    echo "FAIL: tool ${tool_id} state=live_pinned but binary_hash is empty — kernel/sysfs disagreement"
    exit 1
  fi
  echo "  tool ${tool_id} state=live_pinned hash=${pinned:0:16}..."
done
epoch="$(cat /sys/kernel/mcp/tool_catalog_epoch | tr -d '\n\0 ')" || {
  echo "FAIL: cannot read /sys/kernel/mcp/tool_catalog_epoch"
  exit 1
}
echo "  catalog_epoch=$epoch"

echo "[accept-new] step 8: uds_abstract demo path"
# Assignment RHS does not word-split, so we can drop the outer double
# quotes and use plain single quotes for the JSON payload. Wrapping
# this in "$(...)" would re-parse the inner \" escapes and hand python
# literal-backslash JSON that json.loads rejects.
abstract_out=$(run_as_user python3 scripts/mcpctl_exec_smoke.py \
  --app-id abstract_demo_app --tool-id 45 \
  --payload '{"note":"hello via abstract acceptance"}' 2>&1)
echo "$abstract_out"
if ! grep -q "status=ok" <<<"$abstract_out"; then
  echo "FAIL: uds_abstract demo call did not succeed"
  exit 1
fi

echo "[accept-new] step 9: native binary replacement regression"
run_as_user bash scripts/smoke_binary_replacement.sh

echo "[accept-new] step 10: same-PID execve replacement regression"
run_as_user bash scripts/smoke_same_pid_replacement.sh

echo "[accept-new] step 11: interpreter-hosted script swap regression"
run_as_user bash scripts/smoke_python_script_swap.sh

echo "[accept-new] step 12: probe failure must not reuse cached digest"
run_as_user bash scripts/smoke_probe_failure_after_cache.sh

echo "[accept-new] step 13: dynamic manifest re-registration and stale-session rebind"
run_as_user bash scripts/acceptance_dynamic_reregister.sh

echo "[accept-new] step 14: kernel call_log survives mcpd crash"
bash scripts/acceptance_call_log_after_crash.sh

echo "[accept-new] PASS"
