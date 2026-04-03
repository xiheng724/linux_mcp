#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

REQUESTS="4000"
CONCURRENCY="1,4,8,16,32"
NEGATIVE_REPEATS="500"
APPROVAL_REPEATS="100"
RPC_REPEATS="300"
SCALE_REPEATS="10"
MANIFEST_SCALES="1,2,4,8"
TRACE_REQUESTS="1000"
POLICY_REQUESTS="1000"
RESTART_REQUESTS="1000"
RESTART_AFTER="300"
MAX_TOOLS="20"
OUTPUT_DIR="experiment-results/atc"
TIMEOUT_S="10"
INCLUDE_WRITE=0
SKIP_START=0
SKIP_DIRECT=0
SKIP_RELOAD_10X=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --requests)
      REQUESTS="$2"; shift 2 ;;
    --concurrency)
      CONCURRENCY="$2"; shift 2 ;;
    --negative-repeats)
      NEGATIVE_REPEATS="$2"; shift 2 ;;
    --approval-repeats)
      APPROVAL_REPEATS="$2"; shift 2 ;;
    --rpc-repeats)
      RPC_REPEATS="$2"; shift 2 ;;
    --scale-repeats)
      SCALE_REPEATS="$2"; shift 2 ;;
    --manifest-scales)
      MANIFEST_SCALES="$2"; shift 2 ;;
    --trace-requests)
      TRACE_REQUESTS="$2"; shift 2 ;;
    --policy-requests)
      POLICY_REQUESTS="$2"; shift 2 ;;
    --restart-requests)
      RESTART_REQUESTS="$2"; shift 2 ;;
    --restart-after)
      RESTART_AFTER="$2"; shift 2 ;;
    --max-tools)
      MAX_TOOLS="$2"; shift 2 ;;
    --output-dir)
      OUTPUT_DIR="$2"; shift 2 ;;
    --timeout-s)
      TIMEOUT_S="$2"; shift 2 ;;
    --include-write-tools)
      INCLUDE_WRITE=1; shift ;;
    --skip-start)
      SKIP_START=1; shift ;;
    --skip-direct)
      SKIP_DIRECT=1; shift ;;
    --skip-reload-10x)
      SKIP_RELOAD_10X=1; shift ;;
    *)
      echo "unknown option: $1"
      exit 1 ;;
  esac
done

if [[ "$SKIP_START" -eq 0 ]]; then
  echo "[atc] starting tool services"
  bash scripts/run_tool_services.sh
  echo "[atc] starting mcpd"
  bash scripts/run_mcpd.sh
fi

ARGS=(
  --mcpd-sock /tmp/mcpd.sock
  --timeout-s "$TIMEOUT_S"
  --output-dir "$OUTPUT_DIR"
  --requests "$REQUESTS"
  --concurrency "$CONCURRENCY"
  --negative-repeats "$NEGATIVE_REPEATS"
  --approval-repeats "$APPROVAL_REPEATS"
  --rpc-repeats "$RPC_REPEATS"
  --scale-repeats "$SCALE_REPEATS"
  --manifest-scales "$MANIFEST_SCALES"
  --trace-requests "$TRACE_REQUESTS"
  --policy-requests "$POLICY_REQUESTS"
  --restart-requests "$RESTART_REQUESTS"
  --restart-after "$RESTART_AFTER"
  --max-tools "$MAX_TOOLS"
)

if [[ "$INCLUDE_WRITE" -eq 1 ]]; then
  ARGS+=(--include-write-tools)
fi
if [[ "$SKIP_DIRECT" -eq 1 ]]; then
  ARGS+=(--skip-direct)
fi
if [[ "$SKIP_RELOAD_10X" -eq 1 ]]; then
  ARGS+=(--skip-reload-10x)
fi

echo "[atc] running evaluation"
"$PYTHON_BIN" scripts/experiments/atc_eval.py "${ARGS[@]}"

LATEST_RUN="$(ls -1dt "$OUTPUT_DIR"/run-* 2>/dev/null | head -n1 || true)"
if [[ -z "$LATEST_RUN" ]]; then
  echo "[atc] failed: no run directory found under $OUTPUT_DIR"
  exit 1
fi

echo "[atc] rendering report"
"$PYTHON_BIN" scripts/experiments/render_atc_report.py "$LATEST_RUN/atc_summary.json" --output "$LATEST_RUN/atc_report.md"

echo "[atc] done"
echo "[atc] result dir: $LATEST_RUN"
echo "[atc] summary: $LATEST_RUN/atc_summary.json"
echo "[atc] report:  $LATEST_RUN/atc_report.md"
