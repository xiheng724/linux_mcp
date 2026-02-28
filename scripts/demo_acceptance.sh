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

echo "[demo] step 1: build kernel module"
${SUDO} bash scripts/build_kernel.sh

echo "[demo] step 2: unload old module (ignore errors)"
${SUDO} bash scripts/unload_module.sh || true

echo "[demo] step 3: load module"
${SUDO} bash scripts/load_module.sh

echo "[demo] step 4: build client tools"
make -C client clean
make -C client

echo "[demo] step 5: start resident tool services"
run_as_user bash scripts/run_tool_services.sh

echo "[demo] step 6: start mcpd"
run_as_user bash scripts/run_mcpd.sh

echo "[demo] step 7: llm-app once: hello"
run_as_user python3 llm-app/cli.py --selector auto --once "hello"

echo "[demo] step 8: llm-app once: burn cpu for a bit"
run_as_user python3 llm-app/cli.py --selector auto --once "burn cpu for a bit"

echo "[demo] step 9: verify sysfs agent completion counters"
${SUDO} ls -l /sys/kernel/mcp/agents/a1/
${SUDO} cat /sys/kernel/mcp/agents/a1/completed_ok
${SUDO} cat /sys/kernel/mcp/agents/a1/last_exec_ms
${SUDO} cat /sys/kernel/mcp/agents/a1/last_status

echo "[demo] step 10: stop mcpd"
run_as_user bash scripts/stop_mcpd.sh

echo "[demo] step 11: stop resident tool services"
run_as_user bash scripts/stop_tool_services.sh

echo "[demo] step 12: unload module"
${SUDO} bash scripts/unload_module.sh

echo "[demo] step 13: reload_10x"
${SUDO} bash scripts/reload_10x.sh

echo "[demo] PASS"
