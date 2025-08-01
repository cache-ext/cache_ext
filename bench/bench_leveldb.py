import argparse
import logging
import os
import re
from time import sleep
from typing import Dict, List

from bench_lib import *


log = logging.getLogger(__name__)
GiB = 2**30
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


class LevelDBBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("leveldb_benchmark", benchresults_cls, cli_args)
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
            default="ycsb_a,ycsb_c",
        )
        parser.add_argument(
            "--fadvise-hints",
            type=str,
            default=",SEQUENTIAL,NOREUSE,DONTNEED",
            help="Specify the fadvise hints to use for the baseline cgroup",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("enable_mmap", [False], configs)
        configs = add_config_option("runtime_seconds", [240], configs)
        configs = add_config_option("warmup_runtime_seconds", [45], configs)
        configs = add_config_option(
            "benchmark", parse_strings_string(self.args.benchmark), configs
        )
        configs = add_config_option("cgroup_size", [10 * GiB], configs)
        if self.args.default_only:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP], configs
            )
        else:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP], configs
            )

        # For baseline cgroup only, add fadvise options
        fadvise_hints = parse_strings_string(self.args.fadvise_hints)
        new_configs = []
        for config in configs:
            if config["cgroup_name"] == DEFAULT_BASELINE_CGROUP:
                for fadvise in fadvise_hints:
                    new_config = config.copy()
                    new_config["fadvise"] = fadvise
                    new_configs.append(new_config)
            elif config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
                policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
                config["policy_loader"] = policy_loader_name
                new_configs.append(config)
            else:
                new_configs.append(config)
        configs = new_configs
        configs = add_config_option("iteration", list(range(1, self.args.iterations + 1)), configs)
        return configs

    def benchmark_prepare(self, config):
        reset_database(self.args.leveldb_db, self.args.leveldb_temp_db)
        drop_page_cache()
        disable_swap()
        disable_smt()
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=config["cgroup_size"])

            policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
            if policy_loader_name == "cache_ext_s3fifo.out":
                self.cache_ext_policy.start(cgroup_size=config["cgroup_size"])
            else:
                self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])

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
        if config["cgroup_name"] == DEFAULT_BASELINE_CGROUP and config["fadvise"] != "":
            extra_envs["ENABLE_SCAN_FADVISE"] = config["fadvise"]
        return extra_envs

    def after_benchmark(self, config):
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            self.cache_ext_policy.stop()
        sleep(2)
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = parse_leveldb_bench_results(stdout)
        return BenchResults(results)


def main():
    global log
    leveldb_bench = LevelDBBenchmark()
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
