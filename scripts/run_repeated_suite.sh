#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

REPEATS="5"
REQUESTS="4000"
CONCURRENCY="1,4,8,16,32"
NEGATIVE_REPEATS="500"
MAX_TOOLS="20"
OUTPUT_DIR="experiment-results/repeated-suite"
TIMEOUT_S="10"
INCLUDE_WRITE=0
SKIP_DIRECT=0
SKIP_START=0
SLEEP_S="1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repeats)
      REPEATS="$2"; shift 2 ;;
    --requests)
      REQUESTS="$2"; shift 2 ;;
    --concurrency)
      CONCURRENCY="$2"; shift 2 ;;
    --negative-repeats)
      NEGATIVE_REPEATS="$2"; shift 2 ;;
    --max-tools)
      MAX_TOOLS="$2"; shift 2 ;;
    --output-dir)
      OUTPUT_DIR="$2"; shift 2 ;;
    --timeout-s)
      TIMEOUT_S="$2"; shift 2 ;;
    --sleep-s)
      SLEEP_S="$2"; shift 2 ;;
    --include-write-tools)
      INCLUDE_WRITE=1; shift ;;
    --skip-direct)
      SKIP_DIRECT=1; shift ;;
    --skip-start)
      SKIP_START=1; shift ;;
    *)
      echo "unknown option: $1"
      exit 1 ;;
  esac
done

RUN_TS="$(date -u +%Y%m%d-%H%M%S)"
RUN_DIR="$OUTPUT_DIR/run-$RUN_TS"
RAW_DIR="$RUN_DIR/raw"
AGG_DIR="$RUN_DIR/aggregate"
mkdir -p "$RAW_DIR" "$AGG_DIR"

if [[ "$SKIP_START" -eq 0 ]]; then
  echo "[repeat] starting tool services"
  bash scripts/run_tool_services.sh
  echo "[repeat] starting mcpd"
  bash scripts/run_mcpd.sh
fi

for ((i=1; i<=REPEATS; i++)); do
  echo "[repeat] run $i/$REPEATS"
  ARGS=(
    --skip-start
    --output-dir "$RAW_DIR"
    --requests "$REQUESTS"
    --concurrency "$CONCURRENCY"
    --negative-repeats "$NEGATIVE_REPEATS"
    --max-tools "$MAX_TOOLS"
    --timeout-s "$TIMEOUT_S"
  )
  if [[ "$INCLUDE_WRITE" -eq 1 ]]; then
    ARGS+=(--include-write-tools)
  fi
  if [[ "$SKIP_DIRECT" -eq 1 ]]; then
    ARGS+=(--skip-direct)
  fi
  bash scripts/run_experiment_suite.sh "${ARGS[@]}"
  if [[ "$i" -lt "$REPEATS" ]]; then
    sleep "$SLEEP_S"
  fi
done

echo "[repeat] aggregating repeated runs"
"$PYTHON_BIN" scripts/experiments/aggregate_eval.py \
  --suite-summary "$RAW_DIR/run-*/summary.json" \
  --output-dir "$AGG_DIR"

echo "[repeat] done"
echo "[repeat] run dir:   $RUN_DIR"
echo "[repeat] raw runs:   $RAW_DIR"
echo "[repeat] aggregate:  $AGG_DIR"
