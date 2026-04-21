#!/usr/bin/env bash
# Binary-replacement attack regression.
#
# Proof: if a backend's on-disk executable changes after mcpd pinned a
# binary_hash in the kernel TOFU slot, the next tool:exec should be
# denied with reason=binary_mismatch. Relies on the native_echo demo
# because the probe hashes /proc/<pid>/exe — replacing a Python .py
# script doesn't change the interpreter's exe hash and wouldn't trigger
# the guard.
#
# Prerequisites:
#   - kernel_mcp module loaded
#   - scripts/run_tool_services.sh + scripts/run_mcpd.sh already brought
#     up the stack (native_echo_app included via 15_native_echo_app.json)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

NATIVE_BIN="$ROOT_DIR/tool-app/demo_apps/native_echo/bin/native_echo"
NATIVE_BIN_SWAP="$ROOT_DIR/tool-app/demo_apps/native_echo/bin/native_echo_swap"
APP_ID="native_echo_app"
TOOL_ID=44
PIDFILE="/tmp/linux-mcp-app-${APP_ID}.pid"
ENDPOINT="/tmp/linux-mcp-apps/native_echo.sock"
BACKUP="${NATIVE_BIN}.bak"

if [[ ! -x "$NATIVE_BIN" || ! -x "$NATIVE_BIN_SWAP" ]]; then
  echo "FAIL: native_echo binaries missing; run 'make native-demos' first"
  exit 1
fi
if [[ ! -S /tmp/mcpd.sock ]]; then
  echo "FAIL: mcpd socket missing; start the stack before running this test"
  exit 1
fi

sysfs_binary_hash() {
  local tid="$1"
  local path="/sys/kernel/mcp/tools/${tid}/binary_hash"
  [[ -r "$path" ]] || { echo ""; return; }
  cat "$path" 2>/dev/null | tr -d '\n\0 '
}

respawn_native_echo() {
  local old_pid=""
  if [[ -f "$PIDFILE" ]]; then
    old_pid="$(cat "$PIDFILE" 2>/dev/null || true)"
  fi
  if [[ -n "$old_pid" ]]; then
    kill "$old_pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$old_pid" 2>/dev/null || break
      sleep 0.05
    done
  fi
  rm -f "$ENDPOINT"
  nohup setsid "$NATIVE_BIN" --endpoint "$ENDPOINT" \
    --manifest "$ROOT_DIR/tool-app/manifests/15_native_echo_app.json" \
    >/tmp/linux-mcp-app-${APP_ID}.log 2>&1 </dev/null &
  local new_pid=$!
  echo "$new_pid" >"$PIDFILE"
  for _ in $(seq 1 40); do
    [[ -S "$ENDPOINT" ]] && return 0
    sleep 0.1
  done
  echo "FAIL: native_echo did not come up on $ENDPOINT"
  return 1
}

cleanup() {
  local rc=$?
  if [[ -f "$BACKUP" ]]; then
    mv -f "$BACKUP" "$NATIVE_BIN"
    chmod +x "$NATIVE_BIN" 2>/dev/null || true
    respawn_native_echo || true
  fi
  exit "$rc"
}
trap cleanup EXIT

echo "=== step 1: confirm binary_hash pinned at registration ==="
pinned="$(sysfs_binary_hash "$TOOL_ID")"
if [[ -z "$pinned" ]]; then
  echo "FAIL: /sys/kernel/mcp/tools/${TOOL_ID}/binary_hash is empty — registration-time pinning did not run"
  exit 1
fi
echo "  pinned=${pinned:0:16}..."

echo "=== step 2: baseline tool:exec should ALLOW ==="
out="$(python3 scripts/mcpctl_exec_smoke.py \
  --app-id "$APP_ID" --tool-id "$TOOL_ID" --payload '{"note":"baseline"}' 2>&1)"
echo "$out"
if ! grep -q "status=ok" <<<"$out"; then
  echo "FAIL: baseline call did not succeed"
  exit 1
fi

echo "=== step 3: swap backend binary for the BUILD_TAG=v2-swap variant ==="
# Swap in a separately-built variant that speaks the same protocol but
# has a different SHA-256 (different -DBUILD_TAG). That way mcpd's
# probe still succeeds (so we exercise the mismatch path, not the
# probe-failure path) and the test is deterministic.
cp -f "$NATIVE_BIN" "$BACKUP"
cp -f "$NATIVE_BIN_SWAP" "$NATIVE_BIN"
chmod +x "$NATIVE_BIN"
respawn_native_echo
sleep 0.2

echo "=== step 4: post-swap tool:exec should DENY with binary_mismatch ==="
out2="$(python3 scripts/mcpctl_exec_smoke.py \
  --app-id "$APP_ID" --tool-id "$TOOL_ID" --payload '{"note":"after-swap"}' 2>&1 || true)"
echo "$out2"
if grep -q "decision=DENY" <<<"$out2" && grep -qi "binary_mismatch" <<<"$out2"; then
  echo "OK: binary_mismatch enforced"
else
  echo "FAIL: expected decision=DENY with reason=binary_mismatch"
  exit 1
fi

echo "=== step 5: restore and respawn native_echo ==="
mv -f "$BACKUP" "$NATIVE_BIN"
chmod +x "$NATIVE_BIN"
respawn_native_echo
trap - EXIT

echo "=== pass: binary-replacement attack regression green ==="
