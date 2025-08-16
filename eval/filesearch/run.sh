#!/bin/bash
# File search run script (Figure 9)
set -eu -o pipefail

if ! uname -r | grep -q "cache-ext"; then
	echo "This script is intended to be run on a cache_ext kernel."
	echo "Please switch to the cache_ext kernel and try again."
	exit 1
fi

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/bench"
POLICY_PATH="$BASE_DIR/policies"
FILES_PATH=$(realpath "$BASE_DIR/../linux")
RESULTS_PATH="$BASE_DIR/results"

ITERATIONS=3

mkdir -p "$RESULTS_PATH"

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Baseline and cache_ext
python3 "$BENCH_PATH/bench_filesearch.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_mru.out" \
	--results-file "$RESULTS_PATH/filesearch_results.json" \
	--data-dir "$FILES_PATH" \
	--iterations "$ITERATIONS"

# Enable MGLRU
if ! "$BASE_DIR/utils/enable-mglru.sh"; then
	echo "Failed to enable MGLRU. Please check the script."
	exit 1
fi

# MGLRU
python3 "$BENCH_PATH/bench_filesearch.py" \
	--cpu 8 \
	--results-file "$RESULTS_PATH/filesearch_results_mglru.json" \
	--data-dir "$FILES_PATH" \
	--iterations "$ITERATIONS" \
	--default-only

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

echo "File search benchmark completed. Results saved to $RESULTS_PATH."
