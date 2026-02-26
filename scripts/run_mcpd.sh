#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SOCK_PATH="/tmp/mcpd.sock"
RUNTIME_UID="$(id -u)"
PID_PATH="/tmp/mcpd-${RUNTIME_UID}.pid"
LOG_PATH="/tmp/mcpd-${RUNTIME_UID}.log"
LEGACY_PID_PATH="/tmp/mcpd.pid"

if ! lsmod | awk '{print $1}' | grep -qx kernel_mcp; then
  echo "kernel_mcp module is not loaded; run: sudo bash scripts/load_module.sh"
  exit 1
fi

if [[ ! -x ./client/bin/genl_register_tool || ! -x ./client/bin/genl_list_tools || ! -x ./client/bin/genl_register_agent || ! -x ./client/bin/genl_tool_request || ! -x ./client/bin/genl_tool_complete ]]; then
  echo "missing client binaries; run: make -C client clean && make -C client"
  exit 1
fi

echo "reconciling manifests with kernel registry"
python3 mcpd/reconcile_kernel.py

if [[ -f "$LEGACY_PID_PATH" && ! -f "$PID_PATH" ]]; then
  old_pid="$(cat "$LEGACY_PID_PATH" 2>/dev/null || true)"
  if [[ -n "${old_pid}" ]] && kill -0 "$old_pid" 2>/dev/null; then
    echo "mcpd already running pid=$old_pid (legacy pid file)"
    exit 0
  fi
  rm -f "$LEGACY_PID_PATH"
fi

if [[ -f "$PID_PATH" ]]; then
  old_pid="$(cat "$PID_PATH" 2>/dev/null || true)"
  if [[ -n "${old_pid}" ]] && kill -0 "$old_pid" 2>/dev/null; then
    echo "mcpd already running pid=$old_pid"
    exit 0
  fi
  rm -f "$PID_PATH"
fi

rm -f "$LOG_PATH"
python3 mcpd/server.py >"$LOG_PATH" 2>&1 &
pid=$!
echo "$pid" >"$PID_PATH"
echo "started mcpd pid=$pid pid_file=$PID_PATH log_file=$LOG_PATH"

for _ in $(seq 1 50); do
  if [[ -S "$SOCK_PATH" ]]; then
    echo "mcpd socket ready: $SOCK_PATH"
    exit 0
  fi
  sleep 0.1
done

echo "mcpd failed to create socket: $SOCK_PATH"
exit 1
