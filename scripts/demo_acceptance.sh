#!/usr/bin/env bash
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

cleanup() {
  set +e
  run_as_user bash scripts/stop_tool_services.sh >/dev/null 2>&1 || true
  run_as_user bash scripts/stop_mcpd.sh >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[demo] step 0: build native demo binaries"
run_as_user make -C "$ROOT_DIR" native-demos

echo "[demo] step 1: build kernel module"
${SUDO} bash scripts/build_kernel.sh

echo "[demo] step 2: unload old module (ignore errors)"
${SUDO} bash scripts/unload_module.sh || true

echo "[demo] step 3: load module"
${SUDO} bash scripts/load_module.sh

echo "[demo] step 4: ensure no stale user-space services remain"
run_as_user bash scripts/stop_mcpd.sh >/dev/null 2>&1 || true
run_as_user bash scripts/stop_tool_services.sh >/dev/null 2>&1 || true

echo "[demo] step 5: start demo app services"
run_as_user bash scripts/run_tool_services.sh

echo "[demo] step 6: start mcpd"
run_as_user bash scripts/run_mcpd.sh

echo "[demo] step 7: verify DeepSeek API key is configured"
run_as_user bash -lc 'test -n "${DEEPSEEK_API_KEY:-}"' || {
  echo "[demo] missing DEEPSEEK_API_KEY"
  exit 1
}

echo "[demo] step 8: llm-app once: create a note for today's standup"
run_as_user python3 llm-app/cli.py --once "create a work note titled Daily Standup saying blocked on review"

echo "[demo] step 9: llm-app once: show workspace overview"
run_as_user python3 llm-app/cli.py --once "show me an overview of the tool-app folder"

echo "[demo] step 10: verify sysfs agent completion counters"
${SUDO} ls -l /sys/kernel/mcp/agents/a1/
${SUDO} cat /sys/kernel/mcp/agents/a1/completed_ok
${SUDO} cat /sys/kernel/mcp/agents/a1/last_exec_ms
${SUDO} cat /sys/kernel/mcp/agents/a1/last_status

echo "[demo] step 10b: probe unit tests (cache fallback, identity race, uid allowlist)"
run_as_user python3 scripts/test_probe_unit.py

echo "[demo] step 10c: binary-replacement attack regression (distinct PID)"
run_as_user bash scripts/smoke_binary_replacement.sh

echo "[demo] step 10d: binary-replacement attack regression (same PID via execve)"
run_as_user bash scripts/smoke_same_pid_replacement.sh

echo "[demo] step 10e: python script-swap regression (interpreter-hosted backends)"
run_as_user bash scripts/smoke_python_script_swap.sh

echo "[demo] step 10f: probe failure refuses cached digest after cache warmup"
run_as_user bash scripts/smoke_probe_failure_after_cache.sh

echo "[demo] step 10g: dynamic manifest re-registration races"
run_as_user bash scripts/acceptance_dynamic_reregister.sh

echo "[demo] step 10h: call_log survives mcpd crash"
bash scripts/acceptance_call_log_after_crash.sh

echo "[demo] step 11: stop mcpd"
run_as_user bash scripts/stop_mcpd.sh

echo "[demo] step 12: stop demo app services"
run_as_user bash scripts/stop_tool_services.sh

echo "[demo] step 13: unload module"
${SUDO} bash scripts/unload_module.sh

echo "[demo] step 14: reload_10x"
${SUDO} bash scripts/reload_10x.sh

echo "[demo] PASS"
