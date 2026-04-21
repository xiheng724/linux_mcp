#!/usr/bin/env bash
# Regression: mcpd must DENY tool:exec when the live probe fails, even
# after a successful probe has populated the cache. Otherwise a stale
# digest could pass the kernel TOFU check for a swapped backend.
#
# This test warms the cache with a successful exec, then makes the
# backend's endpoint unreachable (kill + remove socket), and asserts
# the next tool:exec hits the probe-failed DENY path instead of being
# served by the stale digest.
#
# Prereqs: full stack running; native_echo_app registered.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

APP_ID="native_echo_app"
TOOL_ID=44
PIDFILE="/tmp/linux-mcp-app-${APP_ID}.pid"
ENDPOINT="/tmp/linux-mcp-apps/native_echo.sock"

if [[ ! -S /tmp/mcpd.sock ]]; then
  echo "FAIL: mcpd socket missing; bring the stack up first"
  exit 1
fi

cleanup() {
  local rc=$?
  if [[ ! -S "$ENDPOINT" ]]; then
    bash "$ROOT_DIR/scripts/run_tool_services.sh" >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap cleanup EXIT

echo "=== step 1: warm the probe cache with one successful exec ==="
out="$(python3 scripts/mcpctl_exec_smoke.py \
  --app-id "$APP_ID" --tool-id "$TOOL_ID" --payload '{"note":"warmup"}' 2>&1)"
echo "$out"
grep -q "status=ok" <<<"$out" || { echo "FAIL: warmup exec did not succeed"; exit 1; }

echo "=== step 2: take the backend offline so the live probe will fail ==="
if [[ -f "$PIDFILE" ]]; then
  backend_pid="$(cat "$PIDFILE")"
  kill "$backend_pid" 2>/dev/null || true
  for _ in $(seq 1 40); do
    kill -0 "$backend_pid" 2>/dev/null || break
    sleep 0.05
  done
fi
rm -f "$ENDPOINT"
[[ ! -S "$ENDPOINT" ]] || { echo "FAIL: socket still present after kill"; exit 1; }

echo "=== step 3: exec after probe failure -> expect DENY probe_failed ==="
out2="$(python3 scripts/mcpctl_exec_smoke.py \
  --app-id "$APP_ID" --tool-id "$TOOL_ID" --payload '{"note":"post-warm"}' 2>&1 || true)"
echo "$out2"
if grep -q "decision=DENY" <<<"$out2" && grep -qi "probe_failed" <<<"$out2"; then
  echo "OK: refused to serve the cached digest after probe failure"
else
  echo "FAIL: expected decision=DENY reason=probe_failed, got above"
  exit 1
fi

echo "=== pass: probe-failure-after-cache-warm regression green ==="
