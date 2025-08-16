#!/bin/bash
# Isolation benchmark run script (Figure 10)
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
SEARCH_PATH=$(realpath "$BASE_DIR/../cgroup")
FILES_PATH="$SEARCH_PATH/linux"
TEMP_DB_PATH="$SEARCH_PATH/leveldb_temp"
RESULTS_PATH="$BASE_DIR/results"

ITERATIONS=3

# Check if the search path exists
if [ ! -d "$SEARCH_PATH" ]; then
    echo "Search path $SEARCH_PATH does not exist."
    echo "Please run the 'setup_isolation.sh' script to set up the environment."
    exit 1
fi

mkdir -p "$RESULTS_PATH"

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# TODO: Convert the following to a loop

python3 "$BENCH_PATH/bench_per_cgroup.py" \
	--cpu 8 \
	--search-path "$SEARCH_PATH" \
	--data-dir "$FILES_PATH" \
	--results-file $RESULTS_PATH/per_cgroup_baseline_results.json \
	--leveldb-db "$DB_PATH" \
	--leveldb-temp-db "$TEMP_DB_PATH" \
	--bench-binary-dir "$YCSB_PATH/build" \
	--iterations "$ITERATIONS" \
	--benchmark ycsb_c \
	--default

python3 "$BENCH_PATH/bench_per_cgroup.py" \
	--cpu 8 \
	--search-path "$SEARCH_PATH" \
	--data-dir "$FILES_PATH" \
	--policy-loader "$POLICY_PATH/cache_ext_sampling.out" \
	--second-policy-loader "$POLICY_PATH/cache_ext_sampling.out" \
	--results-file "$RESULTS_PATH/per_cgroup_both_lfu_results.json" \
	--leveldb-db "$DB_PATH" \
	--leveldb-temp-db "$TEMP_DB_PATH" \
	--bench-binary-dir "$YCSB_PATH/build" \
	--iterations "$ITERATIONS" \
	--benchmark ycsb_c

python3 "$BENCH_PATH/bench_per_cgroup.py" \
	--cpu 8 \
	--search-path "$SEARCH_PATH" \
	--data-dir "$FILES_PATH" \
	--policy-loader "$POLICY_PATH/cache_ext_mru.out" \
	--second-policy-loader "$POLICY_PATH/cache_ext_mru.out" \
	--results-file "$RESULTS_PATH/per_cgroup_both_mru_results.json" \
	--leveldb-db "$DB_PATH" \
	--leveldb-temp-db "$TEMP_DB_PATH" \
	--bench-binary-dir "$YCSB_PATH/build" \
	--iterations "$ITERATIONS" \
	--benchmark ycsb_c

python3 "$BENCH_PATH/bench_per_cgroup.py" \
	--cpu 8 \
	--search-path "$SEARCH_PATH" \
	--data-dir "$FILES_PATH" \
	--policy-loader "$POLICY_PATH/cache_ext_sampling.out" \
	--second-policy-loader "$POLICY_PATH/cache_ext_mru.out" \
	--results-file "$RESULTS_PATH/per_cgroup_split_results.json" \
	--leveldb-db "$DB_PATH" \
	--leveldb-temp-db "$TEMP_DB_PATH" \
	--bench-binary-dir "$YCSB_PATH/build" \
	--iterations "$ITERATIONS" \
	--benchmark ycsb_c

echo "Isolation benchmark completed. Results saved to $RESULTS_PATH."
