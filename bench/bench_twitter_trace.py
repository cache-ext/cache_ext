import argparse
import logging
import os
import re
import subprocess
from time import sleep
from typing import Dict, List

from ruamel.yaml import YAML

from bench_lib import (
    CacheExtPolicy,
    BenchmarkFramework,
    BenchResults,
    DEFAULT_BASELINE_CGROUP,
    DEFAULT_CACHE_EXT_CGROUP,
    drop_page_cache,
    disable_swap,
    disable_smt,
    recreate_cache_ext_cgroup,
    recreate_baseline_cgroup,
    run,
    check_output,
    add_config_option,
    parse_strings_string,
    edit_yaml_file,
    format_bytes_str,
    set_sysctl,
)

yaml = YAML()
log = logging.getLogger(__name__)
GiB = 2**30
MiB = 2**20
CLEANUP_TASKS = []


def reset_database(db_dir: str, temp_db_dir: str):
    # rsync -avpl --delete /mydata/leveldb_db_orig/ /mydata/leveldb_db/
    if not db_dir.endswith("/"):
        db_dir += "/"
    run(["rsync", "-avpl", "--delete", db_dir, temp_db_dir])


def dir_size(path: str) -> int:
    # Check that path exists and is a directory
    if not os.path.exists(path):
        raise Exception("Directory not found: %s" % path)
    if not os.path.isdir(path):
        raise Exception("Not a directory: %s" % path)
    cmd = ["du", "-sb", path]
    result = check_output(cmd)
    return int(result.split()[0])


def file_size(path: str) -> int:
    # Check that path exists and is a file
    if not os.path.exists(path):
        raise Exception("File not found: %s" % path)
    if not os.path.isfile(path):
        raise Exception("Not a file: %s" % path)
    return os.path.getsize(path)


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


class LevelDBTwitterTraceBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("leveldb_twitter_trace_benchmark", benchresults_cls, cli_args)
        if self.args.leveldb_temp_db is None:
            self.args.leveldb_temp_db = self.args.leveldb_db + "_temp"
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.leveldb_temp_db
        )
        CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--leveldb-db",
            type=str,
            default="/mydata/leveldb_db",
            help="Specify the directory to watch for cache_ext",
        )
        parser.add_argument(
            "--leveldb-temp-db",
            type=str,
            default=None,
            help="Specify the temporary directory for LevelDB benchmarking. Default is <leveldb-db>_temp",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            default="./cache_ext_sampling.out",
            help="Specify the path to the policy loader binary",
        )
        parser.add_argument(
            "--bench-binary-dir",
            type=str,
            default="/mydata/My-YCSB/build",
            help="Specify the directory containing the benchmark binary",
        )
        parser.add_argument(
            "--benchmark",
            type=str,
            default="twitter_cluster_17_bench",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("enable_mmap", [False], configs)
        configs = add_config_option("runtime_seconds", [240], configs)
        configs = add_config_option("warmup_runtime_seconds", [45], configs)
        configs = add_config_option(
            "benchmark", parse_strings_string(self.args.benchmark), configs
        )
        configs = add_config_option("cgroup_size_pct", [10], configs)
        if self.args.default_only:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP], configs
            )
        else:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP], configs
            )

        policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
        for config in configs:
            if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
                config["policy_loader"] = policy_loader_name

        configs = add_config_option("iteration", list(range(1, self.args.iterations + 1)), configs)
        return configs

    def benchmark_prepare(self, config):
        reset_database(self.args.leveldb_db, self.args.leveldb_temp_db)
        drop_page_cache()
        disable_swap()
        disable_smt()
        db_size = dir_size(self.args.leveldb_temp_db)
        cgroup_size = int(db_size * config["cgroup_size_pct"] / 100)
        # Add enough memory to load trace file into memory
        bench_binary_dir = self.args.bench_binary_dir
        bench_file = "../leveldb/config/%s.yaml" % config["benchmark"]
        bench_file = os.path.abspath(os.path.join(bench_binary_dir, bench_file))
        with open(bench_file, "r") as f:
            bench_config = yaml.load(f)
        trace_file = bench_config["workload"]["trace_file"]
        trace_file_size = file_size(trace_file)
        # Load the trace file in memory to charge it to another cgroup
        cmd = ["cat", trace_file]
        run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # cgroup_size += int(trace_file_size * 1.5)
        # cgroup_size *= 3
        cgroup_size += 20 * MiB
        cgroup_size = max(cgroup_size, 70 * MiB)

        log.info(
            "DB size: %s, trace file size: %s, cgroup size: %s",
            format_bytes_str(db_size),
            format_bytes_str(trace_file_size),
            format_bytes_str(cgroup_size),
        )

        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=cgroup_size)
            if self.cache_ext_policy.loader_path == "./cache_ext_s3fifo.out":
                self.cache_ext_policy.start(cgroup_size=cgroup_size)
            else:
                self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=cgroup_size)

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
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % config["cgroup_name"],
            bench_binary,
            bench_file,
        ]
        return cmd

    def cmd_extra_envs(self, config):
        extra_envs = {}
        if (
            config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP
            and "mixed_get_scan" in config["benchmark"]
        ):
            extra_envs["ENABLE_BPF_SCAN_MAP"] = "1"
        if config["enable_mmap"]:
            extra_envs["LEVELDB_MAX_MMAPS"] = "10000"
        return extra_envs

    def after_benchmark(self, config):
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            self.cache_ext_policy.stop()
        sleep(2)

    def parse_results(self, stdout: str) -> BenchResults:
        results = parse_leveldb_bench_results(stdout)
        return BenchResults(results)


def main():
    global log
    leveldb_bench = LevelDBTwitterTraceBenchmark()
    set_sysctl("vm.dirty_background_ratio", 1)
    set_sysctl("vm.dirty_ratio", 30)
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_background_ratio", 10))
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_ratio", 20))
    # Check that leveldb path exists
    if not os.path.exists(leveldb_bench.args.leveldb_db):
        raise Exception(
            "LevelDB DB directory not found: %s" % leveldb_bench.args.leveldb_db
        )
    # Check that bench_binary_dir exists
    if not os.path.exists(leveldb_bench.args.bench_binary_dir):
        raise Exception(
            "Benchmark binary directory not found: %s"
            % leveldb_bench.args.bench_binary_dir
        )
    log.info("LevelDB DB directory: %s", leveldb_bench.args.leveldb_db)
    log.info("LevelDB temp DB directory: %s", leveldb_bench.args.leveldb_temp_db)
    leveldb_bench.benchmark()


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
