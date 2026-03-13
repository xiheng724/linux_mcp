#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

SOCK_PATH="/tmp/mcpd.sock"
RUNTIME_UID="$(id -u)"
PID_PATH="/tmp/mcpd-${RUNTIME_UID}.pid"
LOG_PATH="/tmp/mcpd-${RUNTIME_UID}.log"
LEGACY_PID_PATH="/tmp/mcpd.pid"

if ! lsmod | awk '{print $1}' | grep -qx kernel_mcp; then
  echo "kernel_mcp module is not loaded; run: sudo bash scripts/load_module.sh"
  exit 1
fi

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

missing_sockets="$("$PYTHON_BIN" - <<'PY'
import glob,json,os,stat
missing=[]
for p in sorted(glob.glob("tool-app/manifests/*.json")):
    raw=json.load(open(p,encoding="utf-8"))
    if raw.get("mode")!="uds_service":
        continue
    ep=raw.get("endpoint","")
    if not isinstance(ep,str) or not ep:
        missing.append(f"{p}: <invalid-endpoint>")
        continue
    try:
        st=os.stat(ep)
    except FileNotFoundError:
        missing.append(ep)
        continue
    if not stat.S_ISSOCK(st.st_mode):
        missing.append(ep)
if missing:
    print("\n".join(missing))
PY
)"

if [[ -n "$missing_sockets" ]]; then
  echo "app services are not ready. missing/non-socket endpoints:"
  echo "$missing_sockets"
  echo "run first: bash scripts/run_tool_services.sh"
  exit 1
fi

rm -f "$LOG_PATH"
"$PYTHON_BIN" mcpd/server.py >"$LOG_PATH" 2>&1 &
pid=$!
echo "$pid" >"$PID_PATH"
echo "started mcpd pid=$pid pid_file=$PID_PATH log_file=$LOG_PATH"

for _ in $(seq 1 50); do
  if [[ -S "$SOCK_PATH" ]]; then
    echo "mcpd socket ready: $SOCK_PATH"
    break
  fi
  sleep 0.1
done

if [[ ! -S "$SOCK_PATH" ]]; then
  echo "mcpd failed to create socket: $SOCK_PATH"
  exit 1
fi

expected_actions="$("$PYTHON_BIN" - <<'PY'
import glob,json
count=0
for p in sorted(glob.glob("tool-app/manifests/*.json")):
    raw=json.load(open(p,encoding="utf-8"))
    tools=raw.get("tools", [])
    if isinstance(tools, list):
        count += len(tools)
print(count)
PY
)"

for _ in $(seq 1 80); do
  registered_actions="$("$PYTHON_BIN" - <<'PY'
import json,socket,struct
sock_path="/tmp/mcpd.sock"
req=json.dumps({"sys":"list_actions"}, ensure_ascii=True).encode("utf-8")
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
    conn.settimeout(2.0)
    conn.connect(sock_path)
    conn.sendall(struct.pack(">I", len(req)))
    conn.sendall(req)
    hdr=conn.recv(4)
    if len(hdr) != 4:
        raise SystemExit(1)
    (length,) = struct.unpack(">I", hdr)
    data=b""
    while len(data) < length:
        chunk=conn.recv(length-len(data))
        if not chunk:
            raise SystemExit(1)
        data += chunk
resp=json.loads(data.decode("utf-8"))
actions=resp.get("actions", [])
print(len(actions) if isinstance(actions, list) else -1)
PY
)"
  if [[ "$registered_actions" == "$expected_actions" ]]; then
    echo "provider actions registered: $registered_actions/$expected_actions"
    break
  fi
  sleep 0.25
done

if [[ "$registered_actions" != "$expected_actions" ]]; then
  echo "timed out waiting for provider action registration: expected=$expected_actions got=$registered_actions"
  echo "see log: $LOG_PATH"
  exit 1
fi

echo "reconciling tool-app manifests with kernel registry"
"$PYTHON_BIN" mcpd/reconcile_kernel.py
