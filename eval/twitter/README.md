# Twitter traces benchmark

This script benchmarks Twitter traces performance with LevelDB using 5 different
policies:

- Baseline
- Baseline MGLRU
- cache_ext LHD
- cache_ext S3-FIFO
- cache_ext LFU

It corresponds to Figure 7 in the paper.

Outputs, where CLUSTER is one of (17 18 24 34 52):
- `results/twitter_traces_${CLUSTER}_results.json` (for baseline and cache_ext)
- `results/twitter_traces_${CLUSTER}_results_mglru.json` (for MGLRU)
