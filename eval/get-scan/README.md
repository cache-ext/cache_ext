# GET-SCAN benchmark

This script benchmarks a GET-SCAN workload with LevelDB using a custom policy
and `fadvise()` options.

It corresponds to Figure 8 in the paper.

Outputs:

- `results/get_scan_results.json` (for baseline and cache_ext)
- `results/get_scan_results_mglru.json` (for MGLRU)
