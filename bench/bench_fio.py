import argparse
import json
import logging
from typing import Dict, List

import psutil
from yanniszark_common.cmdutils import check_output

from bench_lib import *

log = logging.getLogger(__name__)

CLEANUP_TASKS = []


def approx_equal(val1, val2, threshold=0.1):
    """Check if two values are approximately equal within a threshold.

    Args:
        val1: First value to compare
        val2: Second value to compare
        threshold: Maximum allowed difference between values as a percentage (0-1)

    Returns:
        bool: True if values are within threshold of each other, False otherwise
    """
    if val1 == val2:
        return True

    # Calculate percentage difference
    diff = abs(val1 - val2)
    avg = (val1 + val2) / 2
    pct_diff = diff / avg

    return pct_diff <= threshold


def ensure_random_file(path: str, size_in_bytes=10 * GiB):
    """Create a file filled with random data at the specified path and size.

    Args:
        path: Path where the file should be created
        size_in_bytes: Size of the file to create in bytes
    """
    # Check if file already exists and has correct size
    if os.path.exists(path):
        actual_size = os.path.getsize(path)
        if approx_equal(actual_size, size_in_bytes):
            log.info(
                f"File {path} already exists with correct size {size_in_bytes} bytes"
            )
            return
        else:
            raise ValueError(
                f"File {path} exists but has wrong size {actual_size} bytes (expected {size_in_bytes})"
            )
    # Use dd to create a file of random data with 1MB batch size
    bs = 1024 * 1024  # 1MB
    count = size_in_bytes // bs

    cmd = [
        "dd",
        "if=/dev/urandom",
        f"of={path}",
        f"bs={bs}",
        f"count={count}",
        "status=progress",
    ]

    check_output(cmd)


class FioBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("fio_benchmark", benchresults_cls, cli_args)
        target_dir = self.args.target_dir
        if not os.path.exists(target_dir):
            os.mkdir(target_dir)
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, target_dir
        )
        CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())
        target_file = os.path.join(target_dir, "fio_benchfile")
        ensure_random_file(target_file)

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--target-dir", type=str, required=True, help="File to benchmark against."
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            default="./cache_ext_mglru.out",
            help="Specify the path to the policy loader binary",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("iteration", list(range(1, self.args.iterations + 1)), configs)
        configs = add_config_option("workload", ["randread"], configs)
        configs = add_config_option("runtime_seconds", [60], configs)
        configs = add_config_option("nr_threads", [4], configs)
        configs = add_config_option("cgroup_size", [5 * GiB], configs)
        if self.args.default_only:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP], configs
            )
        else:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP], configs
            )

        for config in configs:
            if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
                policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
                config["policy_loader"] = policy_loader_name

        return configs

    def benchmark_prepare(self, config):
        log.info("Dropping page cache")
        drop_page_cache()
        log.info(
            "Setting up cgroup %s with size %s",
            config["cgroup_name"],
            format_bytes_str(config["cgroup_size"]),
        )
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=config["cgroup_size"])
            policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
            if policy_loader_name == "cache_ext_s3fifo.out":
                self.cache_ext_policy.start(cgroup_size=config["cgroup_size"])
            else:
                self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])

    def before_benchmark(self, config):
        log.info("Startin to measure CPU usage")
        # Get the cpu usage of the the first n cpus used by the benchmark
        psutil.cpu_percent(percpu=True)

    def benchmark_cmd(self, config):
        target_dir = self.args.target_dir
        target_file = os.path.join(target_dir, "fio_benchfile")
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            f"memory:{config['cgroup_name']}",
            "fio",
            "--direct=0",
            "--name=test",
            f"--filename={target_file}",
            f"--rw={config['workload']}",
            "--time_based",
            f"--runtime={config['runtime_seconds']}",
            f"--numjobs={config['nr_threads']}",
            "--bs=4k",
            "--group_reporting",
            "--output-format=json",
        ]
        return cmd

    def after_benchmark(self, config):
        log.info("Stopping CPU usage measurement")
        self.cpu_usage = sum(psutil.cpu_percent(percpu=True)[: config["cpus"]])
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            self.cache_ext_policy.stop()
        log.info("Deleting cgroup %s", config["cgroup_name"])
        delete_cgroup(config["cgroup_name"])

    def parse_results(self, stdout: str) -> BenchResults:
        # parse fio output
        fio_results = json.loads(stdout)
        fio_results["cpu_usage"] = self.cpu_usage
        return BenchResults(fio_results)


def main():
    disable_swap()
    disable_smt()

    fio_bench = FioBenchmark()
    fio_bench.benchmark()


if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.INFO)
        main()
    except Exception as e:
        log.error("Error in main: %s", e)
        log.info("Cleaning up")
        for task in CLEANUP_TASKS:
            task()
        log.error("Re-raising exception")
        raise e
