# Admit-hook benchmark

This script benchmarks RocksDB performance with admit-hook admission control:

- Baseline
- Admit-hook

It runs the following workloads with the above configurations:

- YCSB-A
- Uniform Read/Write

Outputs:

- `results/admit_hook_results.json` (for baseline and admit-hook)