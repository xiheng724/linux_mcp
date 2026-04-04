#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MCPD_SOCK="/tmp/mcpd.sock"
TIMEOUT_S=5
REPEATS=20
MIXED_REQUESTS=500
MIXED_CONCURRENCY=8
MIXED_MALICIOUS_PCT="0,5,10,20"
MAX_TOOLS=20
OUTPUT_DIR="experiment-results/security"
SKIP_START=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mcpd-sock) MCPD_SOCK="$2"; shift 2 ;;
    --timeout-s) TIMEOUT_S="$2"; shift 2 ;;
    --repeats) REPEATS="$2"; shift 2 ;;
    --mixed-requests) MIXED_REQUESTS="$2"; shift 2 ;;
    --mixed-concurrency) MIXED_CONCURRENCY="$2"; shift 2 ;;
    --mixed-malicious-pct) MIXED_MALICIOUS_PCT="$2"; shift 2 ;;
    --max-tools) MAX_TOOLS="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --skip-start) SKIP_START=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ "$SKIP_START" -eq 0 ]]; then
  bash scripts/run_tool_services.sh
  bash scripts/run_mcpd.sh
fi

echo "[security] running evaluation"
python3 scripts/experiments/security_eval.py \
  --mcpd-sock "$MCPD_SOCK" \
  --timeout-s "$TIMEOUT_S" \
  --repeats "$REPEATS" \
  --mixed-requests "$MIXED_REQUESTS" \
  --mixed-concurrency "$MIXED_CONCURRENCY" \
  --mixed-malicious-pct "$MIXED_MALICIOUS_PCT" \
  --max-tools "$MAX_TOOLS" \
  --output-dir "$OUTPUT_DIR"

latest_run="$(ls -1dt "${OUTPUT_DIR}"/run-* 2>/dev/null | head -n1 || true)"
if [[ -n "$latest_run" ]]; then
  python3 scripts/experiments/plot_security_results.py \
    --security-dir "$latest_run" \
    --output-dir "$latest_run/plots"
fi
