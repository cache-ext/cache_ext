import logging
import os
from time import time
from typing import List, Dict

from bench_lib import *

log = logging.getLogger(__name__)

CLEANUP_TASKS = []


class FileSearchBenchmark(BenchmarkFramework):

    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("filesearch_benchmark", benchresults_cls, cli_args)
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.data_dir
        )
        CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--data-dir",
            type=str,
            default="/mydata/filesearch_data",
            help="Data directory",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            default="./cache_ext_mru.out",
            help="Specify the path to the policy loader binary",
        )

    def benchmark_cmd(self):
        # Start the cache extension policy
        self.cache_ext_policy.start()
        # Run the benchmark
        self.run_benchmark()
        # Stop the cache extension policy
        self.cache_ext_policy.stop()

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("passes", [10], configs)
        configs = add_config_option(
            "cgroup_size", [1 * GiB], configs
        )
        if self.args.default_only:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP], configs
            )

        else:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP], configs
            )

        configs = add_config_option("benchmark", ["filesearch"], configs)
        configs = add_config_option("iteration", list(range(1, self.args.iterations + 1)), configs)
        return configs

    def before_benchmark(self, config):
        drop_page_cache()
        disable_swap()
        disable_smt()
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=config["cgroup_size"])
            self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])
        self.start_time = time()

    def benchmark_cmd(self, config):
        pattern = "write"
        data_dir = self.args.data_dir
        rg_cmd = f"rg {pattern} {data_dir}"
        repeated_rg_cmd = f"for i in $(seq 1 {config['passes']}); do {rg_cmd} > /dev/null; done"
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % config["cgroup_name"],
            "/bin/sh",
            "-c",
            repeated_rg_cmd,
        ]
        return cmd

    def after_benchmark(self, config):
        self.end_time = time()
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            self.cache_ext_policy.stop()
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = {"runtime_sec": self.end_time - self.start_time}
        return BenchResults(results)


def main():
    global log
    logging.basicConfig(level=logging.DEBUG)
    global log
    # To ensure that writeback keeps up with the benchmark
    filesearch_bench = FileSearchBenchmark()
    # Check that trace data dir exists
    if not os.path.exists(filesearch_bench.args.data_dir):
        raise Exception(
            "Filesearch data directory not found: %s" % filesearch_bench.args.data_dir
        )
    log.info("Filesearch data directory: %s", filesearch_bench.args.data_dir)
    filesearch_bench.benchmark()


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
