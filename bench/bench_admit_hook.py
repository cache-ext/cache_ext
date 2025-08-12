import argparse
import logging
import os
import re
import subprocess
from time import sleep
from typing import Dict, List

from bench_lib import *


log = logging.getLogger(__name__)
GiB = 2**30
CLEANUP_TASKS = []


def reset_database(db_dir: str, backup_dir: str):
    # rsync -avpl --delete /mydata/rocksdb-backup/ /mydata/rocksdb-data/
    if not backup_dir.endswith("/"):
        backup_dir += "/"
    run(["sudo", "rsync", "-avpl", "--delete", backup_dir, db_dir])


def parse_rocksdb_bench_results(stdout: str) -> Dict:
    """Parse RocksDB benchmark output - same format as leveldb"""
    results = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "Warm-Up" in line:
            continue
        elif "overall: UPDATE throughput" in line or "overall: INSERT throughput" in line:
            # Parse throughput
            pattern = r"(\w+ throughput) (\d+\.\d+) ops/sec"
            matches = re.findall(pattern, line)
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
        elif "overall: UPDATE average latency" in line or "overall: INSERT average latency" in line:
            # Parse latency
            pattern = r"(\w+ \w+ latency) (\d+\.\d+) ns"
            matches = re.findall(pattern, line)
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
    
    # Parse cachestream bypass rate if present
    bypass_match = re.search(r'Bypass percentage: ([\d.]+)%', stdout)
    if bypass_match:
        results["bypass_percentage"] = float(bypass_match.group(1))
    
    return results


class AdmitHookBenchmark(BenchmarkFramework):
    def __init__(self):
        # Call parent constructor with name
        super().__init__("admit_hook_benchmark")
        self.use_admit_hook = False

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--rocksdb-db",
            type=str,
            default="/mydata/rocksdb-data",
            help="Path to RocksDB database directory",
        )
        parser.add_argument(
            "--rocksdb-backup",
            type=str,
            default="/mydata/rocksdb-backup",
            help="Path to RocksDB backup directory",
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
            required=True,
            help="Specify the benchmark to run, e.g., 'ycsb_a,uniform_read_write'",
        )
        parser.add_argument(
            "--use-admit-hook",
            action="store_true",
            help="Enable admit-hook for this run",
        )
        parser.add_argument(
            "--cgroup-memory-gb",
            type=int,
            default=10,
            help="Memory limit for cgroup in GB (default: 10)",
        )
        parser.add_argument(
            "--cpu-range",
            type=str,
            default="1-3",
            help="CPU cores to use (default: 1-3)",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("runtime_seconds", [240], configs)
        configs = add_config_option("warmup_runtime_seconds", [45], configs)
        benchmarks = self.args.benchmark.split(",")
        configs = add_config_option("benchmark", benchmarks, configs)
        
        # Add cgroup configurations
        configs = add_config_option("cgroup_name", ["cache_ext_test"], configs)
        configs = add_config_option("cgroup_size", [self.args.cgroup_memory_gb * GiB], configs)
        configs = add_config_option("use_admit_hook", [self.args.use_admit_hook], configs)
        
        # Add policy name for results grouping
        policy_name = "admit_hook" if self.args.use_admit_hook else "baseline"
        configs = add_config_option("policy", [policy_name], configs)
        
        # Add iterations
        configs = add_config_option("iteration", list(range(1, self.args.iterations + 1)), configs)
        
        return configs

    def benchmark_prepare(self, config):
        # Setup cgroup
        cgroup_name = config["cgroup_name"]
        cgroup_size = config["cgroup_size"]
        
        # Delete existing cgroup if it exists (ignore errors)
        subprocess.run(["sudo", "cgdelete", f"memory:{cgroup_name}"], stderr=subprocess.DEVNULL, check=False)
        
        # Create new cgroup
        run(["sudo", "cgcreate", "-g", f"memory:{cgroup_name}"])
        run(["sudo", "sh", "-c", f"echo {cgroup_size} > /sys/fs/cgroup/{cgroup_name}/memory.max"])
        
        # Reset database from backup
        reset_database(self.args.rocksdb_db, self.args.rocksdb_backup)
        
        # Drop all caches
        run(["sync"])
        run(["sudo", "sh", "-c", "echo 3 > /proc/sys/vm/drop_caches"])
        
        log.info(f"Prepared cgroup {cgroup_name} with {format_bytes_str(cgroup_size)} memory")

    def benchmark_cmd(self, config):
        bench_binary_dir = self.args.bench_binary_dir
        rocksdb_db = self.args.rocksdb_db
        bench_binary = os.path.join(bench_binary_dir, "run_rocksdb")
        bench_file = "../rocksdb/config/%s.yaml" % config["benchmark"]
        bench_file = os.path.abspath(os.path.join(bench_binary_dir, bench_file))
        
        if not os.path.exists(bench_file):
            raise Exception("Benchmark file not found: %s" % bench_file)
        
        # Build command
        cmd = [
            "sudo", "-E",
            "taskset", "-c", self.args.cpu_range,
            "cgexec", "-g", "memory:%s" % config["cgroup_name"],
            bench_binary, bench_file
        ]
        return cmd

    def cmd_extra_envs(self, config):
        extra_envs = {}
        if config.get("use_admit_hook", False):
            # Export CGROUP_PATH for admit-hook to attach
            extra_envs["CGROUP_PATH"] = f"/sys/fs/cgroup/{config['cgroup_name']}"
            log.info("Admit-hook enabled - setting CGROUP_PATH")
        return extra_envs

    def after_benchmark(self, config):
        # Cleanup cgroup
        cgroup_name = config["cgroup_name"]
        subprocess.run(["sudo", "cgdelete", f"memory:{cgroup_name}"], stderr=subprocess.DEVNULL, check=False)
        sleep(2)

    def parse_results(self, stdout: str) -> BenchResults:
        results = parse_rocksdb_bench_results(stdout)
        return BenchResults(results)


def main():
    global log
    admit_hook_bench = AdmitHookBenchmark()
    
    # Set dirty page settings for better performance
    set_sysctl("vm.dirty_background_ratio", 1)
    set_sysctl("vm.dirty_ratio", 30)
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_background_ratio", 10))
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_ratio", 20))
    
    # Check that rocksdb paths exist
    if not os.path.exists(admit_hook_bench.args.rocksdb_db):
        raise Exception(
            "RocksDB DB directory not found: %s" % admit_hook_bench.args.rocksdb_db
        )
    if not os.path.exists(admit_hook_bench.args.rocksdb_backup):
        raise Exception(
            "RocksDB backup directory not found: %s" % admit_hook_bench.args.rocksdb_backup
        )
    # Check that backup directory actually contains a RocksDB database
    backup_contents = os.listdir(admit_hook_bench.args.rocksdb_backup)
    if not backup_contents or not any(f for f in backup_contents if f.endswith('.sst') or f == 'CURRENT'):
        raise Exception(
            "RocksDB backup directory appears to be empty or invalid: %s" % admit_hook_bench.args.rocksdb_backup
        )
    if not os.path.exists(admit_hook_bench.args.bench_binary_dir):
        raise Exception(
            "Benchmark binary directory not found: %s"
            % admit_hook_bench.args.bench_binary_dir
        )
    
    log.info("RocksDB DB directory: %s", admit_hook_bench.args.rocksdb_db)
    log.info("RocksDB backup directory: %s", admit_hook_bench.args.rocksdb_backup)
    log.info("Admit-hook enabled: %s", admit_hook_bench.args.use_admit_hook)
    
    admit_hook_bench.benchmark()
    
    # Reset to default
    set_sysctl("vm.dirty_background_ratio", 10)
    set_sysctl("vm.dirty_ratio", 20)


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