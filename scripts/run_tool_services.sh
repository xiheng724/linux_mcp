#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

SOCK_DIR="/tmp/linux-mcp-apps"
SANDBOX_MODE=""
SANDBOX_FSIZE_BYTES="1048576"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sandbox)
      SANDBOX_MODE="$2"; shift 2 ;;
    --sandbox-fsize-bytes)
      SANDBOX_FSIZE_BYTES="$2"; shift 2 ;;
    *)
      echo "unknown option: $1"
      exit 1 ;;
  esac
done

mkdir -p "$SOCK_DIR"

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
  if [[ "$transport" != "uds_rpc" ]]; then
    echo "skip app_id=$app_id app_name=$app_name transport=$transport"
    continue
  fi
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
  if [[ ! -f "$service_file" ]]; then
    echo "missing service file for app_id=$app_id: $service_file"
    exit 1
  fi

  if [[ -f "$pidfile" ]]; then
    old_pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null && [[ -S "$endpoint" ]]; then
      echo "app service already running: id=$app_id name=$app_name pid=$old_pid endpoint=$endpoint"
      continue
    fi
    rm -f "$pidfile"
  fi

  rm -f "$endpoint"
  # Delete any stale logfile left over from a previous run before redirecting
  # into it. On Debian/Ubuntu kernels with fs.protected_regular=2 (default),
  # bash's `>"$logfile"` fails with EACCES when the sticky /tmp directory
  # already holds a regular file owned by a different user — even for root.
  # Unlinking first and letting the shell recreate the file under the current
  # uid side-steps the protection entirely.
  rm -f "$logfile"
  if [[ -n "$SANDBOX_MODE" ]]; then
    nohup env \
      LINUX_MCP_SIMPLE_SANDBOX="$SANDBOX_MODE" \
      LINUX_MCP_SANDBOX_FSIZE_BYTES="$SANDBOX_FSIZE_BYTES" \
      setsid "$PYTHON_BIN" -u "$service_file" --manifest "$manifest" >"$logfile" 2>&1 </dev/null &
  else
    nohup setsid "$PYTHON_BIN" -u "$service_file" --manifest "$manifest" >"$logfile" 2>&1 </dev/null &
  fi
  pid=$!
  echo "$pid" >"$pidfile"

  ready=0
  for _ in $(seq 1 20); do
    if [[ -S "$endpoint" ]]; then
      ready=1
      break
    fi
    sleep 0.1
  done

  if [[ "$ready" -ne 1 ]]; then
    echo "failed to start app service: app_id=$app_id endpoint=$endpoint (see $logfile)"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$pidfile" "$endpoint"
    exit 1
  fi

  echo "started app service: id=$app_id name=$app_name pid=$pid endpoint=$endpoint"
done

if [[ "$found_manifest" -ne 1 ]]; then
  echo "no manifests found in tool-app/manifests"
  exit 1
fi
