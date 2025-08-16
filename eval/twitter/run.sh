#!/bin/bash
# Twitter trace run script (Figure 7)
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
DB_DIRS=$(realpath "$BASE_DIR/../")
RESULTS_PATH="$BASE_DIR/results"

ITERATIONS=3

POLICIES=(
	"cache_ext_lhd"
	"cache_ext_s3fifo"
	"cache_ext_sampling"
)

CLUSTERS=(17 18 24 34 52)

mkdir -p "$RESULTS_PATH"

# Build correct My-YCSB version (leveldb-latency branch)
# This branch disables latency tracking to minimize memory usage due to the
# small cgroup sizes used in these experiments.
cd "$YCSB_PATH/build"
git checkout leveldb-latency
make clean
make -j run_leveldb

cd -

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Baseline and cache_ext
# TODO: Get rid of the CLUSTER loop and pass a comma-separated list of benchmarks
#	We already support this in the bench script.
for POLICY in "${POLICIES[@]}"; do
	for CLUSTER in "${CLUSTERS[@]}"; do
		echo "Running policy: ${POLICY} on cluster ${CLUSTER}"
		python3 "$BENCH_PATH/bench_twitter_trace.py" \
			--cpu 8 \
			--policy-loader "$POLICY_PATH/${POLICY}.out" \
			--results-file "$RESULTS_PATH/twitter_traces_${CLUSTER}_results.json" \
			--leveldb-db "$DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db" \
			--iterations "$ITERATIONS" \
			--bench-binary-dir "$YCSB_PATH/build" \
			--twitter-traces-dir "$DB_DIRS/twitter-traces" \
			--benchmark "twitter_cluster${CLUSTER}_bench"
	done
done

# Enable MGLRU
if ! "$BASE_DIR/utils/enable-mglru.sh"; then
	echo "Failed to enable MGLRU. Please check the script."
	exit 1
fi

# MGLRU
# TODO: Get rid of the CLUSTER loop and pass a comma-separated list of benchmarks
#	We already support this in the bench script.
# TODO: Remove --policy-loader requirement when using --default-only
for CLUSTER in "${CLUSTERS[@]}"; do
	echo "Running baseline MGLRU on cluster ${CLUSTER}"
	python3 "$BENCH_PATH/bench_twitter_trace.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/${POLICIES[0]}.out" \
		--results-file "$RESULTS_PATH/twitter_traces_${CLUSTER}_results_mglru.json" \
		--leveldb-db "$DB_DIRS/leveldb_twitter_cluster${CLUSTER}_db" \
		--iterations "$ITERATIONS" \
		--bench-binary-dir "$YCSB_PATH/build" \
		--twitter-traces-dir "$DB_DIRS/twitter-traces" \
		--benchmark "twitter_cluster${CLUSTER}_bench" \
		--default-only
done

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

echo "Twitter traces benchmark completed. Results saved to $RESULTS_PATH."
