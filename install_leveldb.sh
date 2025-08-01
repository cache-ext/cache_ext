#!/bin/bash
set -eu -o pipefail

echo "Installing LevelDB dependencies..."
sudo apt-get update
sudo apt-get install -y cmake libsnappy-dev

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
LEVELDB_PATH="$BASE_DIR/leveldb"

cd "$LEVELDB_PATH"
if [[ ! -e "CMakeLists.txt" ]]; then
	git submodule update --init --recursive
fi

git checkout cache_ext

echo "Building LevelDB..."
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j

echo "Installing LevelDB..."
# Default location:
#	Library: /usr/local/lib/libleveldb.a
#	Headers: /usr/local/include/leveldb
sudo make install
