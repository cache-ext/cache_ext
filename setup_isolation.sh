#!/bin/bash
set -eu -o pipefail

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
CGROUP_PATH="$BASE_DIR/../cgroup"

echo "Setting up cgroup isolation environment..."
mkdir -p "$CGROUP_PATH"

echo "Cloning Linux kernel repository..."
cd "$CGROUP_PATH"
# We don't need to clone the history for file-search, as ripgrep ignores the
# .git directory.
git clone --depth 1 --branch v6.6 https://github.com/torvalds/linux.git
