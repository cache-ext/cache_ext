import argparse
import logging
import os
import re
from time import sleep
from typing import Dict, List

from bench_lib import *


log = logging.getLogger(__name__)
GiB = 2**30

# These only run on error
CLEANUP_TASKS = []


def reset_database(db_dir: str, temp_db_dir: str):
    # rsync -avpl --delete /mydata/leveldb_db_orig/ /mydata/leveldb_db/
    if not db_dir.endswith("/"):
        db_dir += "/"
    run(["rsync", "-avpl", "--delete", db_dir, temp_db_dir])


def parse_leveldb_bench_results(stdout: str) -> Dict:
    # Uniform: calculating overall performance metrics... (might take a while)
    # Uniform overall: UPDATE throughput 0.00 ops/sec, INSERT throughput 0.00 ops/sec, READ throughput 9038.24 ops/sec, SCAN throughput 0.00 ops/sec, READ_MODIFY_WRITE throughput 0.00 ops/sec, total throughput 9038.24 ops/sec
    # Uniform overall: UPDATE average latency 0.00 ns, UPDATE p99 latency 0.00 ns, INSERT average latency 0.00 ns, INSERT p99 latency 0.00 ns, READ average latency 109658.84 ns, READ p99 latency 145190.65 ns, SCAN average latency 0.00 ns, SCAN p99 latency 0.00 ns, READ_MODIFY_WRITE average latency 0.00 ns, READ_MODIFY_WRITE p99 latency 0.00 ns
    results = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "Warm-Up" in line:
            continue
        elif "overall: UPDATE throughput" in line:
            # Parse throughput
            pattern = r"(\w+ throughput) (\d+\.\d+) ops/sec"
            matches = re.findall(pattern, line)
            # Matches look like this:
            # [('UPDATE throughput', '0.00'),
            #  ('INSERT throughput', '12337.23'),
            #  ('READ throughput', '12369.98'),
            #  ('SCAN throughput', '0.00'),
            #  ('READ_MODIFY_WRITE throughput', '0.00'),
            #  ('total throughput', '24707.21')]
            assert len(matches) == 6, "Unexpected line pattern: %s" % line
            assert "total throughput" in matches[-1][0]
            for match in matches:
                if "READ throughput" in match[0]:
                    results["read_throughput_avg"] = float(match[1])
                elif "INSERT throughput" in match[0]:
                    results["insert_throughput_avg"] = float(match[1])
                elif "UPDATE throughput" in match[0]:
                    results["update_throughput_avg"] = float(match[1])
                elif "SCAN throughput" in match[0]:
                    results["scan_throughput_avg"] = float(match[1])
                elif "READ_MODIFY_WRITE throughput" in match[0]:
                    results["read_modify_write_throughput_avg"] = float(match[1])
                elif "total throughput" in match[0]:
                    results["throughput_avg"] = float(match[1])
                else:
                    raise Exception("Unknown throughput type: " + match[0])
            results["throughput_avg"] = float(matches[-1][1])
        elif "overall: UPDATE average latency" in line:
            # Parse latency
            pattern = r"(\w+ \w+ latency) (\d+\.\d+) ns"
            matches = re.findall(pattern, line)
            # Matches look like this:
            # [('UPDATE average latency', '0.00'),
            #  ('UPDATE p99 latency', '0.00'),
            #  ('INSERT average latency', '80992.84'),
            #  ('INSERT p99 latency', '887726.24'),
            #  ('READ average latency', '1850251.43'),
            #  ('READ p99 latency', '6888407.68'),
            #  ('SCAN average latency', '0.00'),
            #  ('SCAN p99 latency', '0.00'),
            #  ('READ_MODIFY_WRITE average latency', '0.00'),
            #  ('READ_MODIFY_WRITE p99 latency', '0.00')]
            for match in matches:
                if "READ average latency" in match[0]:
                    results["read_latency_avg"] = float(match[1])
                    results["latency_avg"] = float(match[1])
                elif "INSERT average latency" in match[0]:
                    results["insert_latency_avg"] = float(match[1])
                elif "UPDATE average latency" in match[0]:
                    results["update_latency_avg"] = float(match[1])
                elif "SCAN average latency" in match[0]:
                    results["scan_latency_avg"] = float(match[1])
                elif "READ_MODIFY_WRITE average latency" in match[0]:
                    results["read_modify_write_latency_avg"] = float(match[1])
                elif "READ p99 latency" in match[0]:
                    results["read_latency_p99"] = float(match[1])
                    results["latency_p99"] = float(match[1])
                elif "INSERT p99 latency" in match[0]:
                    results["insert_latency_p99"] = float(match[1])
                elif "UPDATE p99 latency" in match[0]:
                    results["update_latency_p99"] = float(match[1])
                elif "SCAN p99 latency" in match[0]:
                    results["scan_latency_p99"] = float(match[1])
                elif "READ_MODIFY_WRITE p99 latency" in match[0]:
                    results["read_modify_write_latency_p99"] = float(match[1])
                else:
                    raise Exception("Unknown latency metric: " + match[0])
    if not all(
        key in results for key in ["throughput_avg", "latency_avg", "latency_p99"]
    ):
        raise Exception("Could not parse results from stdout: \n" + stdout)
    return results


class CgroupConfig(dict):
    def __init__(
        self, name, cache_ext, policy1_size, policy2_size, split_cgroups, which_policy=1
    ):
        self.name = name
        self.cache_ext = cache_ext
        self.policy1_size = policy1_size
        self.policy2_size = policy2_size
        self.split_cgroups = split_cgroups
        self.which_policy = which_policy
        dict.__init__(
            self,
            name=name,
            cache_ext=cache_ext,
            policy1_size=policy1_size,
            policy2_size=policy2_size,
            split_cgroups=split_cgroups,
            which_policy=which_policy,
        )


# Policy 1 is LFU, Policy 2 is MRU
baseline_cgroup_configs: List[CgroupConfig] = [
    # CgroupConfig(
    #     name="baseline_one_cgroup",
    #     cache_ext=False,
    #     policy1_size=10 * GiB,
    #     policy2_size=1 * GiB,
    #     split_cgroups=False,
    # ),
    CgroupConfig(
        name="baseline_two_cgroups",
        cache_ext=False,
        policy1_size=10 * GiB,
        policy2_size=1 * GiB,
        split_cgroups=True,
    ),
]

cache_ext_cgroup_configs: List[CgroupConfig] = [
    # CgroupConfig(
    #     name="cache_ext_policy1_one_cgroup",
    #     cache_ext=True,
    #     policy1_size=10 * GiB,
    #     policy2_size=1 * GiB,
    #     split_cgroups=False,
    #     which_policy=1
    # ),
    # CgroupConfig(
    #     name="cache_ext_policy2_one_cgroup",
    #     cache_ext=True,
    #     policy1_size=10 * GiB,
    #     policy2_size=1 * GiB,
    #     split_cgroups=False,
    #     which_policy=2
    # ),
    CgroupConfig(
        name="cache_ext_split_cgroups",
        cache_ext=True,
        policy1_size=10 * GiB,
        policy2_size=1 * GiB,
        split_cgroups=True,
    ),
]


def cgroup_name_from_config(config: CgroupConfig, which: int) -> str:
    if config.cache_ext:
        if config.split_cgroups:
            return f"{DEFAULT_CACHE_EXT_CGROUP}_{which}"
        else:
            if config.which_policy == 1:
                return f"{DEFAULT_CACHE_EXT_CGROUP}_1"
            else:
                return f"{DEFAULT_CACHE_EXT_CGROUP}_2"
    else:
        if config.split_cgroups:
            return f"{DEFAULT_BASELINE_CGROUP}_{which}"
        else:
            return f"{DEFAULT_BASELINE_CGROUP}_1"


class PerCgroupBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("percgroup_benchmark", benchresults_cls, cli_args)
        if self.args.leveldb_temp_db is None:
            self.args.leveldb_temp_db = self.args.leveldb_db + "_temp"

        # Validate arguments based on cache_ext mode
        if not self.args.default:
            if not self.args.policy_loader:
                raise ValueError("--policy-loader is required when not using --default")
            if not self.args.second_policy_loader:
                raise ValueError(
                    "--second-policy-loader is required when not using --default"
                )

        self.second_command = True

        # Only initialize cache_ext policies if not using default mode
        if not self.args.default:
            self.cache_ext_policy = CacheExtPolicy(
                DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.search_path
            )

            self.second_cache_ext_policy = CacheExtPolicy(
                DEFAULT_CACHE_EXT_CGROUP,
                self.args.second_policy_loader,
                self.args.search_path,
            )
            CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())
            CLEANUP_TASKS.append(lambda: self.second_cache_ext_policy.stop())
        else:
            self.cache_ext_policy = None
            self.second_cache_ext_policy = None

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--default",
            action="store_true",
            help="Use baseline configuration instead of cache_ext (default: use cache_ext)",
        )
        parser.add_argument(
            "--search-path",
            type=str,
            required=True,
            help="Watch directory",
        )
        parser.add_argument(
            "--data-dir",
            type=str,
            required=True,
            help="Search data directory",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            help="Specify the path to the policy loader binary (YCSB). Required when not using --default",
        )
        parser.add_argument(
            "--second-policy-loader",
            type=str,
            help="Specify the path to the second policy loader binary (Search). Required when not using --default",
        )
        parser.add_argument(
            "--leveldb-db",
            type=str,
            required=True,
            help="Specify the original LevelDB database directory",
        )
        parser.add_argument(
            "--leveldb-temp-db",
            type=str,
            default=None,
            help="Specify the temporary directory for LevelDB benchmarking. Default is <leveldb-db>_temp",
        )
        parser.add_argument(
            "--bench-binary-dir",
            type=str,
            required=True,
            help="Specify the directory containing the benchmark binary",
        )
        parser.add_argument(
            "--benchmark",
            type=str,
            default="ycsb_c",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("runtime_seconds", [180], configs)
        configs = add_config_option("warmup_runtime_seconds", [240], configs)
        configs = add_config_option(
            "benchmark", parse_strings_string(self.args.benchmark), configs
        )
        # Choose configuration based on command line argument
        cgroup_configs = (
            baseline_cgroup_configs if self.args.default else cache_ext_cgroup_configs
        )
        configs = add_config_option("cgroup_config", cgroup_configs, configs)
        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        return configs

    def before_benchmark(self, config):
        reset_database(self.args.leveldb_db, self.args.leveldb_temp_db)
        drop_page_cache()
        disable_swap()
        disable_smt()

        if config["cgroup_config"].cache_ext:
            if config["cgroup_config"].split_cgroups:
                recreate_cache_ext_cgroup(
                    cgroup=f"{DEFAULT_CACHE_EXT_CGROUP}_1",
                    limit_in_bytes=config["cgroup_config"].policy1_size,
                )
                recreate_cache_ext_cgroup(
                    cgroup=f"{DEFAULT_CACHE_EXT_CGROUP}_2",
                    limit_in_bytes=config["cgroup_config"].policy2_size,
                )
                self.cache_ext_policy.set_cgroup(f"{DEFAULT_CACHE_EXT_CGROUP}_1")
                self.second_cache_ext_policy.set_cgroup(f"{DEFAULT_CACHE_EXT_CGROUP}_2")

                self.cache_ext_policy.start()
                self.second_cache_ext_policy.start()
            else:
                size = (
                    config["cgroup_config"].policy1_size
                    + config["cgroup_config"].policy2_size
                )
                if config["cgroup_config"].which_policy == 1:
                    recreate_cache_ext_cgroup(
                        cgroup=f"{DEFAULT_CACHE_EXT_CGROUP}_1", limit_in_bytes=size
                    )
                    self.cache_ext_policy.set_cgroup(f"{DEFAULT_CACHE_EXT_CGROUP}_1")
                    self.cache_ext_policy.start()
                else:
                    recreate_cache_ext_cgroup(
                        cgroup=f"{DEFAULT_CACHE_EXT_CGROUP}_2", limit_in_bytes=size
                    )
                    self.second_cache_ext_policy.set_cgroup(f"{DEFAULT_CACHE_EXT_CGROUP}_2")
                    self.second_cache_ext_policy.start()
        else:
            if config["cgroup_config"].split_cgroups:
                recreate_baseline_cgroup(
                    cgroup=f"{DEFAULT_BASELINE_CGROUP}_1",
                    limit_in_bytes=config["cgroup_config"].policy1_size,
                )
                recreate_baseline_cgroup(
                    cgroup=f"{DEFAULT_BASELINE_CGROUP}_2",
                    limit_in_bytes=config["cgroup_config"].policy2_size,
                )
            else:
                size = (
                    config["cgroup_config"].policy1_size
                    + config["cgroup_config"].policy2_size
                )
                recreate_baseline_cgroup(
                    cgroup=f"{DEFAULT_BASELINE_CGROUP}_1", limit_in_bytes=size
                )

    def benchmark_cmd(self, config):
        bench_binary_dir = self.args.bench_binary_dir
        leveldb_temp_db_dir = self.args.leveldb_temp_db
        bench_binary = os.path.join(bench_binary_dir, "run_leveldb")
        bench_file = "../leveldb/config/%s.yaml" % config["benchmark"]
        bench_file = os.path.abspath(os.path.join(bench_binary_dir, bench_file))
        if not os.path.exists(bench_file):
            raise Exception("Benchmark file not found: %s" % bench_file)
        with edit_yaml_file(bench_file) as bench_config:
            bench_config["leveldb"]["data_dir"] = leveldb_temp_db_dir
            bench_config["workload"]["runtime_seconds"] = config["runtime_seconds"]
            bench_config["workload"]["warmup_runtime_seconds"] = config[
                "warmup_runtime_seconds"
            ]

        cgroup_name = cgroup_name_from_config(config["cgroup_config"], 1)

        cmd = [
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % cgroup_name,
            bench_binary,
            bench_file,
        ]
        return cmd

    def second_benchmark_cmd(self, config):
        pattern = "write"
        data_dir = self.args.data_dir
        rg_cmd = f"rg {pattern} {data_dir}"
        seconds = config["runtime_seconds"] + config["warmup_runtime_seconds"] + 25
        repeated_rg_cmd = f"end=$(( $(date +%s) + {seconds})); count=0; while [[ $(date +%s) < $end ]]; do {rg_cmd} &>/dev/null; ((count++)); done; echo $count"
        cgroup_name = cgroup_name_from_config(config["cgroup_config"], 2)
        cmd = [
            "taskset",
            "-c",
            "8-15",
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % cgroup_name,
            "/bin/bash",
            "-c",
            repeated_rg_cmd,
        ]
        return cmd

    def after_benchmark(self, config):
        if config["cgroup_config"].cache_ext:
            if config["cgroup_config"].split_cgroups:
                self.cache_ext_policy.stop()
                self.second_cache_ext_policy.stop()
            else:
                if config["cgroup_config"].which_policy == 1:
                    self.cache_ext_policy.stop()
                else:
                    self.second_cache_ext_policy.stop()
        sleep(2)
        enable_smt()

    def parse_results(self, stdout: str, second_output: str = None) -> BenchResults:
        results = parse_leveldb_bench_results(stdout)
        results.update({"rg_iters": int(second_output)})
        return BenchResults(results)


def main():
    global log
    logging.basicConfig(level=logging.DEBUG)
    global log
    # To ensure that writeback keeps up with the benchmark
    percgroup_benchmark = PerCgroupBenchmark()
    # Check that trace data dir exists
    if not os.path.exists(percgroup_benchmark.args.data_dir):
        raise Exception(
            "Filesearch data directory not found: %s"
            % percgroup_benchmark.args.data_dir
        )
    log.info("Filesearch data directory: %s", percgroup_benchmark.args.data_dir)

    if not os.path.exists(percgroup_benchmark.args.leveldb_db):
        raise Exception(
            "LevelDB DB directory not found: %s" % percgroup_benchmark.args.leveldb_db
        )
    # Check that bench_binary_dir exists
    if not os.path.exists(percgroup_benchmark.args.bench_binary_dir):
        raise Exception(
            "Benchmark binary directory not found: %s"
            % percgroup_benchmark.args.bench_binary_dir
        )
    log.info("LevelDB DB directory: %s", percgroup_benchmark.args.leveldb_db)
    log.info("LevelDB temp DB directory: %s", percgroup_benchmark.args.leveldb_temp_db)

    percgroup_benchmark.benchmark()


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
