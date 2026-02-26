#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "reload_10x requires root privileges"
  exit 1
fi

bash scripts/build_kernel.sh

mod_name="kernel_mcp"
ko_path="kernel-mcp/kernel_mcp.ko"
start_epoch="$(date +%s)"

for i in $(seq 1 10); do
  echo "[reload_10x] cycle ${i}/10: insmod"
  insmod "$ko_path"
  echo "[reload_10x] cycle ${i}/10: rmmod"
  rmmod "$mod_name"
done

echo "[reload_10x] scan dmesg for OOPS/WARN since @${start_epoch}"
set +e
dmesg_out="$(dmesg --since "@${start_epoch}" 2>/dev/null)"
dmesg_rc=$?
set -e
if [[ $dmesg_rc -ne 0 ]]; then
  echo "failed to read dmesg; cannot verify OOPS/WARN condition"
  exit 1
fi

if echo "$dmesg_out" | grep -E -i "BUG:|OOPS:|WARNING:|KASAN:|UBSAN:" >/dev/null; then
  echo "detected kernel warning/oops in dmesg"
  echo "----- dmesg (filtered) -----"
  echo "$dmesg_out" | grep -E -i "BUG:|OOPS:|WARNING:|KASAN:|UBSAN:"
  echo "----------------------------"
  exit 1
fi

echo "[reload_10x] PASS: insmod/rmmod x10 and no OOPS/WARN detected"

