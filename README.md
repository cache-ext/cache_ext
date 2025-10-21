# cache_ext: Custom Page Cache Eviction Policies with eBPF

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.16915471.svg)](https://doi.org/10.5281/zenodo.16915471)

This repository contains source code and scripts for reproducing key results
from the [cache_ext paper](https://dl.acm.org/doi/10.1145/3731569.3764820) (SOSP 2025) for the purposes of artifact
evaluation.

If using cache_ext, please cite the reference [below](#citation).

We use a Cloudlab instance of type c6525-25g running Ubuntu 22.04, with a
maxed out temporary disk.

There are four major components:

- A modified Linux kernel based on Linux v6.6.8 that supports cache_ext. This
  also includes supporting changes to libbpf and bpftool.
- Policies: A set of custom page cache eviction policies implemented in eBPF.
- LevelDB with minor changes to support cache_ext experiments.
- My-YCSB: an efficient C++ YCSB benchmarking framework.

Additionally, there are several other experiments that make use of pre-existing
tools with no modifications, such as fio and ripgrep.

## Repository Structure

```text
cache_ext
|-- policies/                   : eBPF page cache eviction policies
|-- bench/                      : Benchmarking framework
|-- eval/                       : Evaluation scripts and result analysis
|   |-- cpu-overhead/           : CPU overhead experiment
|   |-- filesearch/             : File search experiment
|   |-- get-scan/               : GET-SCAN experiment
|   |-- isolation/              : Isolation (per-cgroup) experiment
|   |-- twitter/                : Twitter trace experiment
|   \-- ycsb/                   : YCSB experiment
|-- utils/                      : Helper scripts
\-- *.sh                        : Component installation and build scripts
```

## Getting Started

First, clone the repo into Cloudlab's temporary disk (i.e., `/mydata`) and
initialize the submodules:

```sh
cd /mydata
git clone https://github.com/cache-ext/cache_ext.git
cd cache_ext
git submodule update --init --recursive
```

Next, you must compile and install the custom Linux kernel:

```sh
./install_kernel.sh
```

This will also set up libbpf and bpftool.

After the kernel is compiled and installed, you will be prompted to reboot into
cache_ext kernel:

```sh
sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux 6.6.8-cache-ext+"
sudo reboot now
```

Some of the remaining components can only be compiled on the cache_ext kernel,
so you must wait for the system to reboot and then log back in.

Then, run the following command to download the various databases used.
You may be prompted to enter a B2 account ID and B2 account key. These will be
set up on Cloudlab. The download step may take a while, as the datasets are
hundreds of gigabytes in size.

```sh
cd /mydata/cache_ext
./download_dbs.sh
```

Then, you can build and install the other components:

```sh
./install_filesearch.sh
./install_leveldb.sh
./install_misc.sh
./install_ycsb.sh
./setup_isolation.sh
./build_policies.sh
```

Note that this will require approximately 500GB of disk space.

## Running experiments

You can run the experiments in the `eval` directory. Each subdirectory contains
a `run.sh` script that sets up the environment and runs the experiment.
For example, to run the file search benchmark, you can execute:

```sh
cd /mydata/cache_ext/eval/filesearch
./run.sh
```

Note that by default, the `run.sh` scripts are set to run each experiment
three times to get an average result. You can change the number of iterations
by modifying the `ITERATIONS` variable in each `run.sh` script.

The results will be saved in a top-level `results` directory as JSON files.

Many of the experiments will take several hours to run due to the number of
configurations, policies, and iterations. For example, by default, the YCSB
benchmark will take **approximately 20 hours** to run. We recommend using the
`screen` command to start a persistent session that can run the command in the
background and avoid losing progress if the SSH connection is interrupted.

To exit a `screen` session, you can press <kbd>Ctrl</kbd> + <kbd>A</kbd>
followed by <kbd>Ctrl</kbd> + <kbd>D</kbd>.

## Plotting results

We include a Jupyter notebook `bench/bench_plot.ipynb` that can be used to plot
the results of the experiments. You can run this notebook in a Jupyter
environment (i.e., Jupyter Notebook or VSCode).

For example, to start up a Jupyter server, you can run:

```sh
cd /mydata/cache_ext/bench
jupyter notebook
```

This will start a Jupyter server and open a web interface in your browser.
You can then open the `bench_plot.ipynb` notebook and run the cells to generate
the plots.

The figures will be saved as PDFs in a created `figures/` directory.

## Citation

If using cache_ext, please include the following citation:

```bibtex
@inproceedings{cacheext,
author = {Zussman, Tal and Zarkadas, Ioannis and Carin, Jeremy and Cheng, Andrew and Franke, Hubertus and Pfefferle, Jonas and Cidon, Asaf},
title = {cache_ext: Customizing the Page Cache with eBPF},
year = {2025},
isbn = {9798400718700},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3731569.3764820},
doi = {10.1145/3731569.3764820},
pages = {462–478},
numpages = {17},
keywords = {operating systems, eBPF, page cache},
location = {Lotte Hotel World, Seoul, Republic of Korea},
series = {SOSP '25}
}
```
