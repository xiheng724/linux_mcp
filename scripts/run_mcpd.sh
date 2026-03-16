#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]] && "$ROOT_DIR/.venv/bin/python" - <<'PY' >/dev/null 2>&1
import yaml
PY
then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

readarray -t SERVER_DEFAULTS < <("$PYTHON_BIN" - <<'PY'
import os
import sys
from pathlib import Path

root = Path.cwd()
sys.path.insert(0, str(root / "mcpd"))
from config_loader import load_server_defaults_config

raw = load_server_defaults_config()
manifest_dirs = list(raw.get("manifest_dirs", []))
if os.getenv("MCPD_MANIFEST_DIRS", "").strip():
    manifest_dirs = [entry for entry in os.getenv("MCPD_MANIFEST_DIRS", "").split(os.pathsep) if entry]
sock_path = os.getenv("MCPD_SOCKET_PATH", "").strip() or raw.get("default_socket_paths", {}).get("mcpd", "/tmp/mcpd.sock")
print(sock_path)
for entry in manifest_dirs:
    path = Path(entry).expanduser()
    if not path.is_absolute():
        path = root / path
    print(path)
PY
)
SOCK_PATH="${SERVER_DEFAULTS[0]}"
MANIFEST_DIRS=("${SERVER_DEFAULTS[@]:1}")
MCPD_SCRIPT_MANIFEST_DIRS="$(IFS=:; echo "${MANIFEST_DIRS[*]}")"
export MCPD_SCRIPT_MANIFEST_DIRS
export MCPD_SCRIPT_SOCKET_PATH="$SOCK_PATH"
RUNTIME_UID="$(id -u)"
PID_PATH="/tmp/mcpd-${RUNTIME_UID}.pid"
LOG_PATH="/tmp/mcpd-${RUNTIME_UID}.log"

if ! lsmod | awk '{print $1}' | grep -qx kernel_mcp; then
  echo "kernel_mcp module is not loaded; run: sudo bash scripts/load_module.sh"
  exit 1
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
import json,os,stat
from pathlib import Path
missing=[]
dirs = [Path(entry) for entry in os.environ.get("MCPD_SCRIPT_MANIFEST_DIRS", "").split(os.pathsep) if entry]
for manifest_dir in dirs:
    if manifest_dir.is_file():
        manifest_paths=[manifest_dir]
    elif manifest_dir.exists():
        manifest_paths=sorted(manifest_dir.glob("*.json"))
    else:
        manifest_paths=[]
    for p in manifest_paths:
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
  echo "provider services are not ready. missing/non-socket endpoints:"
  echo "$missing_sockets"
  echo "run first: bash scripts/run_provider_services.sh"
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
import json, os
from pathlib import Path
count=0
dirs = [Path(entry) for entry in os.environ.get("MCPD_SCRIPT_MANIFEST_DIRS", "").split(os.pathsep) if entry]
for manifest_dir in dirs:
    if manifest_dir.is_file():
        manifest_paths=[manifest_dir]
    elif manifest_dir.exists():
        manifest_paths=sorted(manifest_dir.glob("*.json"))
    else:
        manifest_paths=[]
    for p in manifest_paths:
        raw=json.load(open(p,encoding="utf-8"))
        actions=raw.get("actions", [])
        if isinstance(actions, list):
            count += len(actions)
print(count)
PY
)"

for _ in $(seq 1 80); do
  registered_actions="$("$PYTHON_BIN" - <<'PY'
import json,socket,struct
import os
sock_path=os.environ.get("MCPD_SCRIPT_SOCKET_PATH", "/tmp/mcpd.sock")
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

echo "reconciling provider-app manifests with kernel registry"
"$PYTHON_BIN" mcpd/reconcile_kernel.py
