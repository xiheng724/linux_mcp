#!/usr/bin/env bash
# Regression: swapping the on-disk .py script of an interpreter-hosted
# backend must invalidate the kernel's TOFU pin on next restart.
#
# Why this test exists: /proc/<pid>/exe for a Python backend points to
# the python3 interpreter, not the .py script. Hashing only
# /proc/<pid>/exe would pin the interpreter — swapping notes_app.py
# with a malicious copy would pass the old TOFU check. The fix builds
# a composite binary_hash from (interpreter_digest, script_digest)
# where script_digest is computed from the demo_entrypoint .py file at
# manifest load time. This test proves the composite moves when the
# script file moves.
#
# Prereqs: full stack running; notes_app_tool_id=2 registered.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SCRIPT_PATH="$ROOT_DIR/tool-app/demo_apps/notes_app.py"
BACKUP="${SCRIPT_PATH}.bak.$$"
APP_ID="notes_app"
TOOL_ID=2  # note_list
PIDFILE="/tmp/linux-mcp-app-${APP_ID}.pid"
ENDPOINT="/tmp/linux-mcp-apps/notes_app.sock"

if [[ ! -S /tmp/mcpd.sock ]]; then
  echo "FAIL: mcpd socket missing; bring the stack up first"
  exit 1
fi
if [[ ! -f "$SCRIPT_PATH" ]]; then
  echo "FAIL: $SCRIPT_PATH missing"
  exit 1
fi

respawn_backend() {
  local oldpid=""
  [[ -f "$PIDFILE" ]] && oldpid="$(cat "$PIDFILE" 2>/dev/null || true)"
  if [[ -n "$oldpid" ]]; then
    kill "$oldpid" 2>/dev/null || true
    for _ in $(seq 1 40); do
      kill -0 "$oldpid" 2>/dev/null || break
      sleep 0.05
    done
  fi
  rm -f "$PIDFILE" "$ENDPOINT"
  # Re-use the normal launcher.
  bash "$ROOT_DIR/scripts/run_tool_services.sh" >/dev/null 2>&1
  for _ in $(seq 1 40); do
    [[ -S "$ENDPOINT" ]] && return 0
    sleep 0.1
  done
  echo "FAIL: notes_app backend did not come up on $ENDPOINT"
  return 1
}

cleanup() {
  local rc=$?
  if [[ -f "$BACKUP" ]]; then
    mv -f "$BACKUP" "$SCRIPT_PATH"
    respawn_backend || true
    # Force mcpd to re-probe on the next call — the old cached digest
    # (of the swapped script) would otherwise linger until an identity
    # drift is detected.
    bash "$ROOT_DIR/scripts/stop_mcpd.sh" >/dev/null 2>&1 || true
    bash "$ROOT_DIR/scripts/run_mcpd.sh" >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap cleanup EXIT

echo "=== step 1: baseline tool:exec -> ALLOW; record pinned hash ==="
out="$(python3 scripts/mcpctl_exec_smoke.py \
  --app-id "$APP_ID" --tool-id "$TOOL_ID" --payload '{"limit":1}' 2>&1)"
echo "$out"
grep -q "status=ok" <<<"$out" || { echo "FAIL: baseline call did not succeed"; exit 1; }
pinned_before="$(cat "/sys/kernel/mcp/tools/${TOOL_ID}/binary_hash" 2>/dev/null | tr -d '\n\0 ')"
[[ -n "$pinned_before" ]] || { echo "FAIL: sysfs binary_hash empty after baseline"; exit 1; }
echo "  pinned=${pinned_before:0:16}..."

echo "=== step 2: swap the .py on disk and restart the backend ==="
cp -f "$SCRIPT_PATH" "$BACKUP"
# Append a harmless but content-changing line so the script's sha256
# moves. The script still imports and runs normally.
printf '\n# swapped-by-regression\n' >> "$SCRIPT_PATH"
respawn_backend

# NOTE: mcpd is intentionally NOT bounced here. The probe now re-reads
# the script file at every call (see _fresh_script_digest in
# mcpd/server.py), so a mid-flight swap must be detected against a
# still-running daemon. Requiring an mcpd restart to re-hash the script
# was the hole the adversarial review flagged: "a backend code swap
# after restart can bypass the advertised TOFU guarantee until the
# daemon reloads". Keep this test catching regressions where the
# manifest-cached digest leaks back in.

echo "=== step 3: post-swap tool:exec -> expect DENY binary_mismatch ==="
out2="$(python3 scripts/mcpctl_exec_smoke.py \
  --app-id "$APP_ID" --tool-id "$TOOL_ID" --payload '{"limit":1}' 2>&1 || true)"
echo "$out2"
if grep -q "decision=DENY" <<<"$out2" && grep -qi "binary_mismatch" <<<"$out2"; then
  echo "OK: composite hash detected the .py swap"
else
  echo "FAIL: expected decision=DENY reason=binary_mismatch after .py swap"
  exit 1
fi

echo "=== step 4: restore, respawn, reset mcpd ==="
mv -f "$BACKUP" "$SCRIPT_PATH"
respawn_backend
bash "$ROOT_DIR/scripts/stop_mcpd.sh" >/dev/null 2>&1 || true
bash "$ROOT_DIR/scripts/run_mcpd.sh" >/dev/null
trap - EXIT

echo "=== pass: python-script swap regression green ==="
