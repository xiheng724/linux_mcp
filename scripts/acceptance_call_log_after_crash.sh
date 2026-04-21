#!/usr/bin/env bash
# Acceptance: kernel call_log survives mcpd crash.
#
# Sequence:
#   1. open a session + run one tool:exec (ALLOW)
#   2. kill -9 mcpd
#   3. read /sys/kernel/mcp/agents/<agent>/call_log via the decoder
#      and assert the record we just produced is visible
#
# This is the whole point of pushing audit into the kernel: userspace
# can die and the last N arbitrations remain inspectable.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

SUDO="sudo"
if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
fi

APP_ID="${APP_ID:-notes_app}"
TOOL_ID="${TOOL_ID:-2}"

if [[ ! -S /tmp/mcpd.sock ]]; then
  echo "FAIL: mcpd socket missing; bring the stack up first"
  exit 1
fi

echo "=== step 1: run one tool:exec and capture agent_id ==="
run_out="$("$PYTHON_BIN" - <<PY
import json, socket, struct, sys

def rpc(req, timeout=3.0):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
        c.settimeout(timeout)
        c.connect("/tmp/mcpd.sock")
        raw = json.dumps(req).encode()
        c.sendall(struct.pack(">I", len(raw)) + raw)
        hdr = c.recv(4)
        (n,) = struct.unpack(">I", hdr)
        buf = b""
        while len(buf) < n:
            chunk = c.recv(n - len(buf))
            if not chunk:
                raise RuntimeError("short body")
            buf += chunk
    return json.loads(buf.decode())

sess = rpc({"sys": "open_session", "req_id": 1, "client_name": "call-log-acceptance"})
sid = sess["session_id"]
agent_id = sess["agent_id"]
req_id = 20260421
resp = rpc({
    "kind": "tool:exec",
    "req_id": req_id,
    "session_id": sid,
    "app_id": "${APP_ID}",
    "tool_id": int("${TOOL_ID}"),
    "payload": {},
})
if resp.get("status") != "ok":
    sys.stderr.write(f"baseline exec not ok: {resp}\n")
    sys.exit(1)
print(f"{agent_id} {req_id}")
PY
)"
agent_id="$(awk '{print $1}' <<<"$run_out")"
req_id="$(awk '{print $2}' <<<"$run_out")"
if [[ -z "$agent_id" || -z "$req_id" ]]; then
  echo "FAIL: could not capture agent_id/req_id"
  exit 1
fi
echo "  agent_id=$agent_id req_id=$req_id"

echo "=== step 2: kill -9 mcpd ==="
pkill -9 -f 'python.*mcpd/server.py' || true
sleep 0.3
if [[ -S /tmp/mcpd.sock ]]; then
  # stale file — remove so a later run_mcpd.sh doesn't get confused
  rm -f /tmp/mcpd.sock 2>/dev/null || ${SUDO} rm -f /tmp/mcpd.sock
fi

echo "=== step 3: dump call_log via decoder ==="
dump="$(${SUDO} "$PYTHON_BIN" scripts/mcpctl_dump_calls.py "$agent_id")"
echo "$dump"

if ! grep -qE "req=${req_id}[[:space:]]" <<<"$dump"; then
  echo "FAIL: req_id=${req_id} not present in kernel call_log after mcpd crash"
  exit 1
fi
if ! grep -qE "req=${req_id}[[:space:]].*status=OK" <<<"$dump"; then
  echo "FAIL: record for req_id=${req_id} is not status=OK"
  exit 1
fi
if ! grep -qE "req=${req_id}[[:space:]].*tsc=OK" <<<"$dump"; then
  echo "FAIL: record for req_id=${req_id} missing tool_status_code=OK"
  exit 1
fi

echo "=== pass: call_log survived mcpd crash and shows the expected record ==="
