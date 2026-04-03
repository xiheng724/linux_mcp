#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# Large-volume matrix: request volume x concurrency profile.
REQUEST_LEVELS=(2000 8000 20000)
CONCURRENCY_PROFILES=("1,4,8,16" "1,8,16,32" "1,16,32,64")
NEGATIVE_REPEATS=(300 800 1500)

if [[ ${#REQUEST_LEVELS[@]} -ne ${#CONCURRENCY_PROFILES[@]} ]]; then
  echo "matrix size mismatch"
  exit 1
fi

for i in "${!REQUEST_LEVELS[@]}"; do
  req="${REQUEST_LEVELS[$i]}"
  conc="${CONCURRENCY_PROFILES[$i]}"
  neg="${NEGATIVE_REPEATS[$i]}"

  echo "[matrix] run=$((i+1)) requests=$req concurrency=$conc negative_repeats=$neg"
  bash scripts/run_experiment_suite.sh \
    --requests "$req" \
    --concurrency "$conc" \
    --negative-repeats "$neg" \
    --max-tools 24 \
    --output-dir "experiment-results/matrix"

done

echo "[matrix] all runs completed"
