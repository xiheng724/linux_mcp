#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

CAMPAIGN_REPEATS="5"
OUTPUT_DIR="experiment-results/security-repeat"
SLEEP_S="1"
SECURITY_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --campaign-repeats)
      CAMPAIGN_REPEATS="$2"; shift 2 ;;
    --output-dir)
      OUTPUT_DIR="$2"; shift 2 ;;
    --sleep-s)
      SLEEP_S="$2"; shift 2 ;;
    *)
      SECURITY_ARGS+=("$1")
      shift ;;
  esac
done

RUN_TS="$(date -u +%Y%m%d-%H%M%S)"
RUN_DIR="$OUTPUT_DIR/run-$RUN_TS"
RAW_DIR="$RUN_DIR/raw"
AGG_DIR="$RUN_DIR/aggregate"
mkdir -p "$RAW_DIR" "$AGG_DIR"

for ((i=1; i<=CAMPAIGN_REPEATS; i++)); do
  echo "[repeat-security] run $i/$CAMPAIGN_REPEATS"
  bash scripts/run_security_evaluation.sh --output-dir "$RAW_DIR" "${SECURITY_ARGS[@]}"
  if [[ "$i" -lt "$CAMPAIGN_REPEATS" ]]; then
    sleep "$SLEEP_S"
  fi
done

echo "[repeat-security] aggregating"
"$PYTHON_BIN" scripts/experiments/aggregate_security_runs.py \
  --summary "$RAW_DIR/run-*/security_summary.json" \
  --output-dir "$AGG_DIR"

"$PYTHON_BIN" scripts/experiments/plot_repeated_security.py \
  --aggregate-dir "$AGG_DIR" \
  --output-dir "$AGG_DIR/plots"

echo "[repeat-security] done"
echo "[repeat-security] run dir:  $RUN_DIR"
echo "[repeat-security] raw dir:  $RAW_DIR"
echo "[repeat-security] agg dir:  $AGG_DIR"
