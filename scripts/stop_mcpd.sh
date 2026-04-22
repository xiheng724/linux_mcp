#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "stop_mcpd.sh must be run as root because mcpd is started via sudo/root"
  echo "use: sudo bash scripts/stop_mcpd.sh"
  exit 1
fi

RUNTIME_UID="$(id -u)"
PID_PATH="/tmp/mcpd-${RUNTIME_UID}.pid"
SOCK_PATH="/tmp/mcpd.sock"
LOG_PATH="/tmp/mcpd-${RUNTIME_UID}.log"

stop_by_pid_file() {
  local pfile="$1"
  if [[ ! -f "$pfile" ]]; then
    return 0
  fi
  pid="$(cat "$pfile" 2>/dev/null || true)"
  if [[ -n "${pid}" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    for _ in $(seq 1 50); do
      if ! kill -0 "$pid" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$pfile"
}

stop_by_pid_file "$PID_PATH"

rm -f "$SOCK_PATH"
rm -f "$LOG_PATH"
echo "mcpd stopped"
