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
mkdir -p "$SOCK_DIR"

found_manifest=0
for manifest in "$ROOT_DIR"/tool-app/manifests/*.json; do
  [[ -f "$manifest" ]] || continue
  found_manifest=1
  IFS=$'\t' read -r app_id app_name service_path endpoint mode < <(
    "$PYTHON_BIN" - "$manifest" <<'PY'
import json,sys
raw=json.load(open(sys.argv[1],encoding="utf-8"))
print(
    f"{raw.get('app_id','')}\t"
    f"{raw.get('app_name','')}\t"
    f"{raw.get('service_path','tool-app/app_service.py')}\t"
    f"{raw.get('endpoint','')}\t"
    f"{raw.get('mode','')}"
)
PY
  )

  if [[ -z "$app_id" || -z "$app_name" ]]; then
    echo "invalid manifest missing app id/name: $manifest"
    exit 1
  fi
  if [[ "$mode" != "uds_service" ]]; then
    echo "skip app_id=$app_id app_name=$app_name mode=$mode"
    continue
  fi
  if [[ -z "$endpoint" ]]; then
    echo "invalid manifest missing endpoint: $manifest"
    exit 1
  fi

  pidfile="/tmp/linux-mcp-app-${app_id}.pid"
  logfile="/tmp/linux-mcp-app-${app_id}.log"
  service_file="$ROOT_DIR/$service_path"
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
  "$PYTHON_BIN" "$service_file" --manifest "$manifest" --serve "$endpoint" >"$logfile" 2>&1 &
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
