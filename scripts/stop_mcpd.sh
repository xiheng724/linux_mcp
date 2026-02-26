#!/usr/bin/env bash
set -euo pipefail

RUNTIME_UID="$(id -u)"
PID_PATH="/tmp/mcpd-${RUNTIME_UID}.pid"
LEGACY_PID_PATH="/tmp/mcpd.pid"
SOCK_PATH="/tmp/mcpd.sock"
LOG_PATH="/tmp/mcpd-${RUNTIME_UID}.log"
LEGACY_LOG_PATH="/tmp/mcpd.log"

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
stop_by_pid_file "$LEGACY_PID_PATH"

rm -f "$SOCK_PATH"
rm -f "$LOG_PATH" "$LEGACY_LOG_PATH"
echo "mcpd stopped"
