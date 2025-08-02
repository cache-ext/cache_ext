# YCSB benchmark

This script benchmarks YCSB performance with LevelDB using 8 different policies:

- Baseline
- Baseline MGLRU
- cache_ext LHD
- cache_ext S3-FIFO
- cache_ext LFU
- cache_ext FIFO
- cache_ext MRU
- cache_ext MGLRU

It also runs Uniform and Uniform R/W workloads with the above policies.

It corresponds to Figure 9 and Table 5 in the paper.

Outputs:

- `results/ycsb_results.json` (for baseline and cache_ext)
- `results/ycsb_results_mglru.json` (for MGLRU)
