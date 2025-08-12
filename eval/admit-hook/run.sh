#!/bin/bash
# Admit-hook RocksDB benchmark run script
set -eu -o pipefail

if ! uname -r | grep -q "cache-ext"; then
	echo "This script is intended to be run on a cache_ext kernel."
	echo "Please switch to the cache_ext kernel and try again."
	exit 1
fi

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/bench"
YCSB_PATH="$BASE_DIR/My-YCSB"
ROCKSDB_DB="/mydata/rocksdb-data"
ROCKSDB_BACKUP="/mydata/rocksdb-backup"
RESULTS_PATH="$BASE_DIR/results"

ITERATIONS=3

mkdir -p "$RESULTS_PATH"

# Build correct My-YCSB version for RocksDB
mkdir -p "$YCSB_PATH/build"
cd "$YCSB_PATH"
git checkout master 2>/dev/null || true
cd "$YCSB_PATH/build"
cmake .. 2>/dev/null || true
make clean 2>/dev/null || true
make -j run_rocksdb

cd -

# Run baseline (without admit-hook)
echo "Running baseline"
python3 "$BENCH_PATH/bench_admit_hook.py" \
    --cpu 3 \
    --bench-binary-dir "$YCSB_PATH/build" \
    --benchmark "uniform_read_write,ycsb_a" \
    --rocksdb-db "$ROCKSDB_DB" \
    --rocksdb-backup "$ROCKSDB_BACKUP" \
    --iterations "$ITERATIONS" \
    --results-file "$RESULTS_PATH/admit_hook_results.json"

# Run with admit-hook enabled
echo "Running admit-hook"
python3 "$BENCH_PATH/bench_admit_hook.py" \
    --cpu 3 \
    --bench-binary-dir "$YCSB_PATH/build" \
    --benchmark "uniform_read_write,ycsb_a" \
    --rocksdb-db "$ROCKSDB_DB" \
    --rocksdb-backup "$ROCKSDB_BACKUP" \
    --iterations "$ITERATIONS" \
    --results-file "$RESULTS_PATH/admit_hook_results.json" \
    --use-admit-hook

echo "Admit-hook benchmark completed. Results saved to $RESULTS_PATH."