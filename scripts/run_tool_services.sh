#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

# Auto-select the repo demo config if the operator did not specify one.
# This keeps uds_abstract manifests (16_*) valid out of the box without
# requiring /etc/linux-mcp/mcpd.toml. Exported so mcpd picks up the same
# file when run_mcpd.sh is invoked after us.
if [[ -z "${LINUX_MCP_CONFIG:-}" ]] && [[ -f "$ROOT_DIR/config/mcpd.demo.toml" ]]; then
  export LINUX_MCP_CONFIG="$ROOT_DIR/config/mcpd.demo.toml"
fi

# Transport policy comes from mcpd config. uds_rpc allow_prefixes[0] is
# the directory we eagerly mkdir; uds_abstract doesn't need a directory.
read -r UDS_RPC_DIR < <(
  "$PYTHON_BIN" - <<'PY'
import sys
sys.path.insert(0, "mcpd")
from config import load_transport_config
cfg = load_transport_config()
prefix = cfg.uds_rpc_allow_prefixes[0] if cfg.uds_rpc_allow_prefixes else ""
print(prefix)
PY
)
UDS_RPC_DIR="${UDS_RPC_DIR:-/tmp/linux-mcp-apps/}"
if [[ -n "$UDS_RPC_DIR" ]]; then
  mkdir -p "$UDS_RPC_DIR"
fi

native_demos_built=0

ensure_native_demo_built() {
  if [[ "$native_demos_built" -eq 1 ]]; then
    return 0
  fi
  echo "building native demo binaries via 'make native-demos'"
  make -C "$ROOT_DIR" native-demos
  native_demos_built=1
}

# Wait for a backend to be reachable. For uds_rpc we can stat the socket
# file; for uds_abstract we try an actual connect because abstract names
# don't exist in the filesystem.
wait_ready() {
  local transport="$1"
  local endpoint="$2"
  local i
  for i in $(seq 1 40); do
    case "$transport" in
      uds_rpc)
        if [[ -S "$endpoint" ]]; then return 0; fi
        ;;
      uds_abstract)
        if "$PYTHON_BIN" - "$endpoint" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(0.2)
s.connect(b"\x00" + sys.argv[1].encode("utf-8"))
s.close()
PY
        then
          return 0
        fi
        ;;
    esac
    sleep 0.1
  done
  return 1
}

found_manifest=0
for manifest in "$ROOT_DIR"/tool-app/manifests/*.json; do
  [[ -f "$manifest" ]] || continue
  found_manifest=1
  IFS=$'\t' read -r app_id app_name demo_entrypoint endpoint transport < <(
    "$PYTHON_BIN" - "$manifest" <<'PY'
import json,sys
raw=json.load(open(sys.argv[1],encoding="utf-8"))
print(
    f"{raw.get('app_id','')}\t"
    f"{raw.get('app_name','')}\t"
    f"{raw.get('demo_entrypoint','')}\t"
    f"{raw.get('endpoint','')}\t"
    f"{raw.get('transport','')}"
)
PY
  )

  if [[ -z "$app_id" || -z "$app_name" ]]; then
    echo "invalid manifest missing app id/name: $manifest"
    exit 1
  fi

  case "$transport" in
    uds_rpc|uds_abstract)
      : ;;
    vsock_rpc)
      echo "warn: skipping app_id=$app_id transport=vsock_rpc (not implemented in demo tree — future work)"
      continue
      ;;
    *)
      echo "skip app_id=$app_id app_name=$app_name transport=$transport (unknown transport)"
      continue
      ;;
  esac

  if [[ -z "$endpoint" ]]; then
    echo "invalid manifest missing endpoint: $manifest"
    exit 1
  fi
  if [[ -z "$demo_entrypoint" ]]; then
    echo "skip app_id=$app_id app_name=$app_name (no demo_entrypoint configured)"
    continue
  fi

  pidfile="/tmp/linux-mcp-app-${app_id}.pid"
  logfile="/tmp/linux-mcp-app-${app_id}.log"
  service_file="$ROOT_DIR/$demo_entrypoint"
  if [[ "$demo_entrypoint" != *.py ]] && [[ ! -x "$service_file" ]]; then
    ensure_native_demo_built
  fi
  if [[ ! -f "$service_file" ]]; then
    echo "missing service file for app_id=$app_id: $service_file"
    exit 1
  fi

  if [[ -f "$pidfile" ]]; then
    old_pid="$(cat "$pidfile" 2>/dev/null || true)"
    alive=0
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      if wait_ready "$transport" "$endpoint"; then alive=1; fi
    fi
    if [[ "$alive" -eq 1 ]]; then
      echo "app service already running: id=$app_id name=$app_name pid=$old_pid endpoint=$endpoint transport=$transport"
      continue
    fi
    rm -f "$pidfile"
  fi

  # Only a path-UDS endpoint has a filesystem artefact to clean up.
  if [[ "$transport" == "uds_rpc" ]]; then
    rm -f "$endpoint"
  fi

  # Python demos get invoked via the interpreter and pass --manifest so
  # they can read endpoint/operations themselves. Native binaries are
  # exec'd directly with --endpoint because a full JSON parser in C is
  # overkill; the manifest is the wire authority, the binary just needs
  # to know where to bind.
  if [[ "$demo_entrypoint" == *.py ]]; then
    nohup setsid "$PYTHON_BIN" -u "$service_file" --manifest "$manifest" >"$logfile" 2>&1 </dev/null &
  elif [[ -x "$service_file" ]]; then
    nohup setsid "$service_file" --endpoint "$endpoint" --manifest "$manifest" >"$logfile" 2>&1 </dev/null &
  else
    echo "demo entrypoint is neither a .py script nor an executable: $service_file"
    exit 1
  fi
  pid=$!
  echo "$pid" >"$pidfile"

  if ! wait_ready "$transport" "$endpoint"; then
    echo "failed to start app service: app_id=$app_id transport=$transport endpoint=$endpoint (see $logfile)"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$pidfile"
    [[ "$transport" == "uds_rpc" ]] && rm -f "$endpoint"
    exit 1
  fi

  echo "started app service: id=$app_id name=$app_name pid=$pid endpoint=$endpoint transport=$transport"
done

if [[ "$found_manifest" -ne 1 ]]; then
  echo "no manifests found in tool-app/manifests"
  exit 1
fi
