#!/bin/bash
set -eu -o pipefail

echo "Installing ripgrep..."
sudo apt-get update
sudo apt-get install -y ripgrep

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
CLONE_PATH="$BASE_DIR/.."

echo "Cloning Linux kernel repository..."
cd "$CLONE_PATH"
# We don't need to clone the history for file-search, as ripgrep ignores the
# .git directory.
git clone --depth 1 --branch v6.6 https://github.com/torvalds/linux.git
