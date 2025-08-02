# File search benchmark

This script benchmarks file search performance with ripgrep using a MRU policy.
It corresponds to Figure 6 in the paper.

Outputs:

- `results/filesearch_results.json` (for baseline and cache_ext)
- `results/filesearch_results_mglru.json` (for MGLRU)
