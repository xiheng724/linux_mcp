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
OUTPUT_DIR="experiment-results/atc-repeat"
SLEEP_S="1"
ATC_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repeats)
      REPEATS="$2"; shift 2 ;;
    --output-dir)
      OUTPUT_DIR="$2"; shift 2 ;;
    --sleep-s)
      SLEEP_S="$2"; shift 2 ;;
    *)
      ATC_ARGS+=("$1")
      shift ;;
  esac
done

RUN_TS="$(date -u +%Y%m%d-%H%M%S)"
RUN_DIR="$OUTPUT_DIR/run-$RUN_TS"
RAW_DIR="$RUN_DIR/raw"
AGG_DIR="$RUN_DIR/aggregate"
mkdir -p "$RAW_DIR" "$AGG_DIR"

for ((i=1; i<=REPEATS; i++)); do
  echo "[repeat-atc] run $i/$REPEATS"
  bash scripts/run_atc_evaluation.sh --output-dir "$RAW_DIR" "${ATC_ARGS[@]}"
  if [[ "$i" -lt "$REPEATS" ]]; then
    sleep "$SLEEP_S"
  fi
done

echo "[repeat-atc] aggregating"
"$PYTHON_BIN" scripts/experiments/aggregate_atc_runs.py \
  --summary "$RAW_DIR/run-*/atc_summary.json" \
  --output-dir "$AGG_DIR"

"$PYTHON_BIN" scripts/experiments/plot_repeated_atc.py \
  --aggregate-dir "$AGG_DIR" \
  --output-dir "$AGG_DIR/plots"

echo "[repeat-atc] done"
echo "[repeat-atc] run dir:  $RUN_DIR"
echo "[repeat-atc] raw dir:  $RAW_DIR"
echo "[repeat-atc] agg dir:  $AGG_DIR"
