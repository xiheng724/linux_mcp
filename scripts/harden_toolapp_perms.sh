#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET_USER="${SUDO_USER:-$(id -un)}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "WARN: harden_toolapp_perms requires root; skipping (demo mode unchanged)."
  exit 0
fi

if ! getent group mcpd >/dev/null 2>&1; then
  groupadd --system mcpd
  echo "created group: mcpd"
fi

if ! id -u mcpd >/dev/null 2>&1; then
  useradd --system --gid mcpd --home-dir /nonexistent --shell /usr/sbin/nologin mcpd
  echo "created user: mcpd"
fi

if [[ "$TARGET_USER" != "root" ]]; then
  if ! id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx mcpd; then
    echo "WARN: user '$TARGET_USER' is not in group 'mcpd'; skip hardening to keep run_mcpd usable."
    echo "WARN: run 'sudo usermod -aG mcpd $TARGET_USER' and re-login, then rerun this script."
    exit 0
  fi
fi

chown -R mcpd:mcpd tool-app mcpd/tools.d
chmod 750 tool-app mcpd
if ls mcpd/tools.d/*.json >/dev/null 2>&1; then
  chmod 640 mcpd/tools.d/*.json
fi

if [[ "$TARGET_USER" != "root" ]]; then
  if ! sudo -u "$TARGET_USER" test -r mcpd/tools.d/1_echo.json; then
    echo "WARN: post-check failed: $TARGET_USER cannot read manifests; keeping current state, please review manually."
    exit 0
  fi
fi

echo "hardened: owner=mcpd:mcpd, tool-app/mcpd=750, manifests=640"

