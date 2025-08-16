#!/bin/bash
# GET-SCAN run script (Figure 8)
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
YCSB_PATH="$BASE_DIR/My-YCSB"
DB_PATH=$(realpath "$BASE_DIR/../leveldb")
RESULTS_PATH="$BASE_DIR/results"

ITERATIONS=3

mkdir -p "$RESULTS_PATH"

# Build correct My-YCSB version (leveldb-scan branch)
# This branch includes SCAN changes to enable the GET-SCAN benchmark.
cd "$YCSB_PATH/build"
git checkout leveldb-scan
make clean
make -j run_leveldb

cd -

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Baseline and cache_ext
python3 "$BENCH_PATH/bench_leveldb.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_get_scan.out" \
	--results-file "$RESULTS_PATH/get_scan_results.json" \
	--leveldb-db "$DB_PATH" \
	--fadvise-hints ",SEQUENTIAL,NOREUSE,DONTNEED" \
	--iterations "$ITERATIONS" \
	--bench-binary-dir "$YCSB_PATH/build" \
	--benchmark mixed_get_scan

# Enable MGLRU
if ! "$BASE_DIR/utils/enable-mglru.sh"; then
	echo "Failed to enable MGLRU. Please check the script."
	exit 1
fi

# MGLRU
# TODO: Remove --policy-loader requirement when using --default-only
python3 "$BENCH_PATH/bench_leveldb.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_get_scan.out" \
	--results-file "$RESULTS_PATH/get_scan_results_mglru.json" \
	--leveldb-db "$DB_PATH" \
	--fadvise-hints "" \
	--iterations "$ITERATIONS" \
	--bench-binary-dir "$YCSB_PATH/build" \
	--benchmark mixed_get_scan \
	--default-only

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

echo "GET-SCAN benchmark completed. Results saved to $RESULTS_PATH."
