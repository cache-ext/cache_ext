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
FIO_DIR=$(realpath "$BASE_DIR/../fio_dir")
RESULTS_PATH="$BASE_DIR/results"

ITERATIONS=1

mkdir -p "$FIO_DIR"
mkdir -p "$RESULTS_PATH"

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Microbenchmark with fio for CPU overhead
python3 "$BENCH_PATH/bench_fio.py" \
	--cpu 8 \
	--target-dir "$FIO_DIR" \
	--policy-loader "" \
	--iterations "$ITERATIONS" \
	--results-file "$RESULTS_PATH/cpu_overhead_results.json"

echo "CPU overhead benchmark completed. Results saved to $RESULTS_PATH."
