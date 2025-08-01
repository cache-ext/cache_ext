#!/bin/bash
set -eu -o pipefail

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
YCSB_PATH="$BASE_DIR/My-YCSB/"

echo "Installing YCSB dependencies..."
sudo apt-get update
# Depends on libsnappy-dev for LevelDB drivers
sudo apt-get install -y unzip libsnappy-dev

# TODO: switch to libyaml-cpp-dev if available
wget -O /tmp/yaml-cpp-0.8.0.zip https://github.com/jbeder/yaml-cpp/archive/refs/tags/0.8.0.zip
pushd /tmp
unzip yaml-cpp-0.8.0.zip
cd yaml-cpp-0.8.0
mkdir build
cd build
cmake ..
make -j
sudo make install
popd

cd "$YCSB_PATH"
if [[ ! -e "CMakeLists.txt" ]]; then
    git submodule update --init --recursive
fi

echo "Building YCSB..."
mkdir build
cd build
cmake ..
