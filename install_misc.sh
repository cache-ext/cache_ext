#!/bin/bash
set -eu -o pipefail

# Tools required for running benchmarks

echo "Installing additional tools..."
sudo apt-get update
# Tools:
#   fio: Required for CPU overhead experiments
#   cgroup-tools: Required for all experiments for cgroup management
#   python3-ruamel.yaml: Required for Python benchmarking scripts
#   python3-numpy: Required for Python plotting scripts
#   python3-matplotlib: Required for Python plotting scripts
sudo apt-get install -y fio cgroup-tools python3-ruamel.yaml python3-numpy \
			python3-matplotlib
