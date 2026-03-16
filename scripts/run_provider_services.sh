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

SOCK_DIR="/tmp/linux-mcp-providers"
mkdir -p "$SOCK_DIR"

readarray -t MANIFEST_PATHS < <("$PYTHON_BIN" - <<'PY'
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
for entry in manifest_dirs:
    path = Path(entry).expanduser()
    if not path.is_absolute():
        path = root / path
    if path.is_file():
        print(path)
        continue
    if path.exists():
        for manifest_path in sorted(path.glob("*.json")):
            print(manifest_path)
PY
)

found_manifest=0
for manifest in "${MANIFEST_PATHS[@]}"; do
  [[ -f "$manifest" ]] || continue
  found_manifest=1
  IFS=$'\t' read -r provider_id display_name endpoint mode < <(
    "$PYTHON_BIN" - "$manifest" <<'PY'
import json,sys
raw=json.load(open(sys.argv[1],encoding="utf-8"))
print(
    f"{raw.get('provider_id','')}\t"
    f"{raw.get('display_name', raw.get('provider_name', raw.get('provider_id','')))}\t"
    f"{raw.get('endpoint','')}\t"
    f"{raw.get('mode','')}"
)
PY
  )

  if [[ -z "$provider_id" || -z "$display_name" ]]; then
    echo "invalid manifest missing provider id/display name: $manifest"
    exit 1
  fi
  if [[ "$mode" != "uds_service" ]]; then
    echo "skip provider_id=$provider_id display_name=$display_name mode=$mode"
    continue
  fi
  if [[ -z "$endpoint" ]]; then
    echo "invalid manifest missing endpoint: $manifest"
    exit 1
  fi

  pidfile="/tmp/linux-mcp-provider-${provider_id}.pid"
  logfile="/tmp/linux-mcp-provider-${provider_id}.log"
  service_file="$ROOT_DIR/provider-app/provider_service.py"
  if [[ ! -f "$service_file" ]]; then
    echo "missing provider service file: $service_file"
    exit 1
  fi

  if [[ -f "$pidfile" ]]; then
    old_pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null && [[ -S "$endpoint" ]]; then
      echo "provider service already running: id=$provider_id name=$display_name pid=$old_pid endpoint=$endpoint"
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
    echo "failed to start provider service: provider_id=$provider_id endpoint=$endpoint (see $logfile)"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$pidfile" "$endpoint"
    exit 1
  fi

  echo "started provider service: id=$provider_id name=$display_name pid=$pid endpoint=$endpoint"
done

if [[ "$found_manifest" -ne 1 ]]; then
  echo "no manifests found in configured manifest directories"
  exit 1
fi
