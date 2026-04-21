#!/usr/bin/env bash
# Binary-replacement attack regression — SAME PID variant.
#
# The companion test scripts/smoke_binary_replacement.sh covers the easy
# case: the old process dies and a new one starts with a different file
# on disk, so both PID and /proc/<pid>/exe change. That alone would pass
# even a naive PID-keyed cache.
#
# This script covers the harder case: the backend execve()s itself
# (systemd ExecReload, supervisord hot-reload, an attacker-driven
# execve). execve preserves PID, so a probe cache keyed only on PID
# would happily hand back the old digest and let the swapped binary
# slip past the kernel's TOFU guard. mcpd has to key cache validity on
# an exe_identity tuple drawn from /proc/<pid>/exe (readlink target +
# dev/inode/size/mtime).
#
# Prereqs:
#   - kernel_mcp module loaded
#   - mcpd running at /tmp/mcpd.sock
#   - `make native-demos` has produced native_echo and native_echo_swap
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NATIVE_BIN="$ROOT_DIR/tool-app/demo_apps/native_echo/bin/native_echo"
SWAP_BIN="$ROOT_DIR/tool-app/demo_apps/native_echo/bin/native_echo_swap"
MANIFEST="$ROOT_DIR/tool-app/manifests/15_native_echo_app.json"
APP_ID="native_echo_app"
TOOL_ID=44
ENDPOINT="/tmp/linux-mcp-apps/native_echo.sock"
PIDFILE="/tmp/linux-mcp-app-${APP_ID}.pid"
LOGFILE="/tmp/linux-mcp-app-${APP_ID}.log"

if [[ ! -x "$NATIVE_BIN" || ! -x "$SWAP_BIN" ]]; then
  echo "FAIL: native_echo binaries missing; run 'make native-demos' first"
  exit 1
fi
if [[ ! -S /tmp/mcpd.sock ]]; then
  echo "FAIL: mcpd socket missing; bring the stack up first"
  exit 1
fi

kill_pid_from_file() {
  [[ -f "$PIDFILE" ]] || return 0
  local p
  p="$(cat "$PIDFILE" 2>/dev/null || true)"
  [[ -z "$p" ]] && return 0
  kill "$p" 2>/dev/null || true
  for _ in $(seq 1 40); do
    kill -0 "$p" 2>/dev/null || return 0
    sleep 0.05
  done
  kill -9 "$p" 2>/dev/null || true
}

start_native_echo_with_swap_env() {
  # Pre-arm the execve target via env. SIGUSR1 will cause native_echo
  # to execve() into this path, preserving its PID — the whole point
  # of the regression.
  rm -f "$ENDPOINT"
  NATIVE_ECHO_SWAP_TARGET="$SWAP_BIN" \
    nohup setsid "$NATIVE_BIN" \
        --endpoint "$ENDPOINT" \
        --manifest "$MANIFEST" \
        >"$LOGFILE" 2>&1 </dev/null &
  local p=$!
  echo "$p" >"$PIDFILE"
  for _ in $(seq 1 40); do
    [[ -S "$ENDPOINT" ]] && return 0
    sleep 0.1
  done
  echo "FAIL: native_echo did not come up on $ENDPOINT"
  return 1
}

cleanup() {
  local rc=$?
  kill_pid_from_file || true
  # Respawn in the normal (no-swap-target) way so subsequent acceptance
  # steps see a clean native_echo.
  rm -f "$ENDPOINT"
  nohup setsid "$NATIVE_BIN" --endpoint "$ENDPOINT" --manifest "$MANIFEST" \
    >"$LOGFILE" 2>&1 </dev/null &
  local newpid=$!
  echo "$newpid" >"$PIDFILE"
  for _ in $(seq 1 40); do
    [[ -S "$ENDPOINT" ]] && break
    sleep 0.1
  done
  exit "$rc"
}
trap cleanup EXIT

echo "=== step 1: restart native_echo with SIGUSR1 swap target armed ==="
kill_pid_from_file
start_native_echo_with_swap_env
pid="$(cat "$PIDFILE")"
echo "  backend pid=$pid, exe -> $(readlink "/proc/$pid/exe" 2>/dev/null || echo '<unreadable>')"

echo "=== step 2: baseline exec -> expect ALLOW and a pinned hash ==="
out="$(python3 scripts/mcpctl_exec_smoke.py \
  --app-id "$APP_ID" --tool-id "$TOOL_ID" --payload '{"note":"pre-execve"}' 2>&1)"
echo "$out"
if ! grep -q "status=ok" <<<"$out"; then
  echo "FAIL: baseline call did not succeed"
  exit 1
fi

pinned_before="$(cat "/sys/kernel/mcp/tools/${TOOL_ID}/binary_hash" 2>/dev/null | tr -d '\n\0 ')"
if [[ -z "$pinned_before" ]]; then
  echo "FAIL: sysfs binary_hash empty after baseline"
  exit 1
fi
echo "  pinned=${pinned_before:0:16}..."

echo "=== step 3: send SIGUSR1 -> backend execves (same PID, different binary) ==="
pre_exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
pre_ino="$(stat -c '%i' "/proc/$pid/exe" 2>/dev/null || stat -f '%i' "/proc/$pid/exe" 2>/dev/null || echo unknown)"
kill -USR1 "$pid"
# Give the process a moment to process the signal and finish execve.
sleep 0.4
if ! kill -0 "$pid" 2>/dev/null; then
  echo "FAIL: pid $pid disappeared instead of execve-in-place"
  exit 1
fi
post_exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
post_ino="$(stat -c '%i' "/proc/$pid/exe" 2>/dev/null || stat -f '%i' "/proc/$pid/exe" 2>/dev/null || echo unknown)"
echo "  before: exe=$pre_exe ino=$pre_ino"
echo "  after : exe=$post_exe ino=$post_ino"
if [[ "$pre_exe" == "$post_exe" && "$pre_ino" == "$post_ino" ]]; then
  echo "FAIL: /proc/$pid/exe identity did not change — execve handler likely didn't fire"
  exit 1
fi
# Wait for the swap binary to re-bind the socket.
for _ in $(seq 1 40); do
  [[ -S "$ENDPOINT" ]] && break
  sleep 0.1
done
[[ -S "$ENDPOINT" ]] || { echo "FAIL: endpoint missing after execve"; exit 1; }

echo "=== step 4: post-execve exec -> expect DENY binary_mismatch ==="
out2="$(python3 scripts/mcpctl_exec_smoke.py \
  --app-id "$APP_ID" --tool-id "$TOOL_ID" --payload '{"note":"post-execve"}' 2>&1 || true)"
echo "$out2"
if grep -q "decision=DENY" <<<"$out2" && grep -qi "binary_mismatch" <<<"$out2"; then
  echo "OK: mcpd detected exe-identity drift and kernel DENY'd binary_mismatch"
else
  echo "FAIL: expected decision=DENY reason=binary_mismatch after same-PID execve"
  exit 1
fi

echo "=== pass: same-pid execve regression green ==="
