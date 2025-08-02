# Isolation benchmark

This script benchmarks the performance of different cache policies in an
isolated environment. It runs an MRU and LFU workload in two different cgroups,
with different cache policies applied to each cgroup.
It corresponds to Figure 10 in the paper.

Outputs:

- `results/per_cgroup_baseline_results.json`
- `results/per_cgroup_both_lfu_results.json`
- `results/per_cgroup_both_mru_results.json`
- `results/per_cgroup_split_results.json`
