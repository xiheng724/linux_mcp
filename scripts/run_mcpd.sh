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

manifest_signature() {
  "$PYTHON_BIN" - <<'PY'
import glob
import hashlib
import json

catalog = []
for path in sorted(glob.glob("tool-app/manifests/*.json")):
    raw = json.load(open(path, encoding="utf-8"))
    tools = raw.get("tools", [])
    app = {
        "app_id": raw.get("app_id", ""),
        "app_name": raw.get("app_name", ""),
        "tools": [],
    }
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            app["tools"].append(
                {
                    "tool_id": tool.get("tool_id"),
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "risk_tags": tool.get("risk_tags", []),
                    "input_schema": tool.get("input_schema", {}),
                    "examples": tool.get("examples", []),
                }
            )
    catalog.append(app)

payload = json.dumps(catalog, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
print(hashlib.sha256(payload).hexdigest()[:16])
PY
}

live_signature() {
  "$PYTHON_BIN" - <<'PY'
import hashlib
import json
import socket
import struct
import sys

sock_path = "/tmp/mcpd.sock"

def rpc(req):
    raw = json.dumps(req, ensure_ascii=True).encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(2.0)
        conn.connect(sock_path)
        conn.sendall(struct.pack(">I", len(raw)))
        conn.sendall(raw)
        hdr = conn.recv(4)
        if len(hdr) != 4:
            raise RuntimeError("short header")
        (length,) = struct.unpack(">I", hdr)
        data = b""
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                raise RuntimeError("short body")
            data += chunk
    return json.loads(data.decode("utf-8"))

try:
    apps_resp = rpc({"sys": "list_apps"})
    tools_resp = rpc({"sys": "list_tools"})
except Exception:
    sys.exit(2)

apps = apps_resp.get("apps", [])
tools = tools_resp.get("tools", [])
if not isinstance(apps, list) or not isinstance(tools, list):
    sys.exit(2)

tool_map = {}
for tool in tools:
    if not isinstance(tool, dict):
        continue
    app_id = tool.get("app_id", "")
    tool_map.setdefault(app_id, []).append(
        {
            "tool_id": tool.get("tool_id"),
            "name": tool.get("name", ""),
            "description": tool.get("description", ""),
            "risk_tags": tool.get("risk_tags", []),
            "input_schema": tool.get("input_schema", {}),
            "examples": tool.get("examples", []),
        }
    )

catalog = []
for app in sorted((item for item in apps if isinstance(item, dict)), key=lambda item: str(item.get("app_id", ""))):
    app_id = app.get("app_id", "")
    catalog.append(
        {
            "app_id": app_id,
            "app_name": app.get("app_name", ""),
            "tools": sorted(tool_map.get(app_id, []), key=lambda item: (item.get("tool_id"), item.get("name", ""))),
        }
    )

payload = json.dumps(catalog, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
print(hashlib.sha256(payload).hexdigest()[:16])
PY
}

if ! lsmod | awk '{print $1}' | grep -qx kernel_mcp; then
  echo "kernel_mcp module is not loaded; run: sudo bash scripts/load_module.sh"
  exit 1
fi

if [[ ! -d /sys/kernel/mcp/tools || ! -d /sys/kernel/mcp/agents ]]; then
  echo "loaded kernel_mcp module does not match this repo's ABI"
  echo "expected sysfs directories: /sys/kernel/mcp/tools and /sys/kernel/mcp/agents"
  echo "reload the module from this repo:"
  echo "  sudo bash scripts/unload_module.sh"
  echo "  sudo bash scripts/load_module.sh"
  exit 1
fi

if [[ ! -x ./client/bin/genl_register_tool || ! -x ./client/bin/genl_list_tools ]]; then
  echo "missing client binaries; run: make -C client clean && make -C client"
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
    expected_sig="$(manifest_signature)"
    live_sig="$(live_signature || true)"
    if [[ -n "$live_sig" && "$live_sig" == "$expected_sig" ]]; then
      echo "mcpd already running pid=$old_pid"
      exit 0
    fi
    echo "mcpd running pid=$old_pid but catalog is stale; restarting"
    bash scripts/stop_mcpd.sh >/dev/null
  fi
  rm -f "$PID_PATH"
fi

rm -f "$LOG_PATH"
nohup setsid "$PYTHON_BIN" -u mcpd/server.py >"$LOG_PATH" 2>&1 </dev/null &
pid=$!
echo "$pid" >"$PID_PATH"
echo "started mcpd pid=$pid pid_file=$PID_PATH log_file=$LOG_PATH"

for _ in $(seq 1 50); do
  if [[ -S "$SOCK_PATH" ]]; then
    echo "mcpd socket ready: $SOCK_PATH"
    break
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if [[ ! -S "$SOCK_PATH" ]]; then
  echo "mcpd failed to create socket: $SOCK_PATH"
  if [[ -f "$LOG_PATH" ]]; then
    echo "mcpd startup log:"
    cat "$LOG_PATH"
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "mcpd exited during startup; if you changed the kernel MCP protocol, rebuild/reload the kernel module first"
  fi
  rm -f "$PID_PATH"
  exit 1
fi

expected_tools="$("$PYTHON_BIN" - <<'PY'
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
  registered_tools="$("$PYTHON_BIN" - <<'PY'
import json,socket,struct
sock_path="/tmp/mcpd.sock"
req=json.dumps({"sys":"list_tools"}, ensure_ascii=True).encode("utf-8")
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
tools=resp.get("tools", [])
print(len(tools) if isinstance(tools, list) else -1)
PY
)"
  if [[ "$registered_tools" == "$expected_tools" ]]; then
    echo "tool manifests registered: $registered_tools/$expected_tools"
    break
  fi
  sleep 0.25
done

if [[ "$registered_tools" != "$expected_tools" ]]; then
  echo "timed out waiting for tool manifest registration: expected=$expected_tools got=$registered_tools"
  echo "see log: $LOG_PATH"
  exit 1
fi

echo "reconciling tool-app manifests with kernel registry"
"$PYTHON_BIN" mcpd/reconcile_kernel.py
