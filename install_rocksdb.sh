#!/bin/bash
set -eu -o pipefail

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
ROCKSDB_PATH="$BASE_DIR/rocksdb"

cd "$ROCKSDB_PATH"
if [[ ! -e "CMakeLists.txt" ]]; then
	git submodule update --init --recursive
fi

echo "Building and installing RocksDB..."
echo "Note: This requires bpftool and the cache_ext libbpf changes."
./build.sh
