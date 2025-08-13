# Application-informed admission filter benchmark

This script benchmarks RocksDB performance with application-informed admission filter:

- Baseline
- Application-informed admission filter

It runs YCSB-A and Uniform Read/Write workloads with the above configurations.

It corresponds to Section 6.1.4 in the paper.

Outputs:

- `results/admit_hook_results.json` (for baseline and application-informed admission filter)