import argparse
import json
import logging
import os
import resource
import select
import subprocess
import sys
from abc import ABC, abstractmethod
from contextlib import contextmanager, suppress
from subprocess import CalledProcessError
from time import sleep
from typing import Dict, List, Union

from ruamel.yaml import YAML

GiB = 2**30
log = logging.getLogger(__name__)

DEFAULT_CACHE_EXT_CGROUP = "cache_ext_test"
DEFAULT_BASELINE_CGROUP = "baseline_test"


class CacheExtPolicy:
    def __init__(self, cgroup: str, loader_path: str, watch_dir: str):
        self.cgroup_path = "/sys/fs/cgroup/%s" % cgroup
        self.loader_path = loader_path
        self.watch_dir = watch_dir
        self.has_started = False
        self._policy_thread = None

    def start(self, cgroup_size: int=0):
        if self.has_started:
            raise Exception("Policy already started")
        self.has_started = True
        cmd = [
            "sudo",
            self.loader_path,
            "--watch_dir",
            self.watch_dir,
            "--cgroup_path",
            self.cgroup_path,
        ]

        if cgroup_size:
            cmd += ["--cgroup_size", str(cgroup_size)]

        log.info("Starting policy thread: %s", cmd)
        self._policy_thread = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        sleep(10)

        # For some reason, running a command with `sudo` messes up the terminal.
        # This is a workaround to fix it.
        # run(["stty", "sane"])
        if self._policy_thread.poll() is not None:
            raise Exception(
                "Policy thread exited unexpectedly: %s"
                % self._policy_thread.stderr.read().decode("utf-8")
            )

    def stop(self):
        if not self.has_started:
            raise Exception("Policy not started")
        cmd = ["sudo", "kill", "-2", str(self._policy_thread.pid)]
        run(cmd)
        out, err = self._policy_thread.communicate()
        with suppress(subprocess.CalledProcessError):
            run(["sudo", "rm", "/sys/fs/bpf/cache_ext/scan_pids"])
        log.info("Policy thread stdout: %s", out.decode("utf-8"))
        log.info("Policy thread stderr: %s", err.decode("utf-8"))
        self.has_started = False
        self._policy_thread = None


def ulimit(num_open_files: int):
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (num_open_files, num_open_files))
    except ValueError as e:
        log.warning(f"Failed to set ulimit to {num_open_files}: {e}")
        log.warning("Current ulimit: %s", resource.getrlimit(resource.RLIMIT_NOFILE))
        raise e
    except Exception as e:
        log.error(f"Unexpected error while setting ulimit: {e}")
        raise e

def format_bytes_str(bytes: int):
    if bytes < 1024:
        return f"{bytes} B"
    elif bytes < 1024**2:
        return f"{bytes / 1024:.1f} KiB"
    elif bytes < 1024**3:
        return f"{bytes / 1024**2:.1f} MiB"
    else:
        return f"{bytes / 1024**3:.1f} GiB"


@contextmanager
def edit_yaml_file(file_path):
    """
    Context manager for editing YAML files while preserving formatting.

    Usage:
    with edit_yaml_file('path/to/file.yaml') as data:
        data['key'] = 'new_value'
    """
    yaml = YAML()
    yaml.preserve_quotes = True

    try:
        with open(file_path, 'r') as file:
            data = yaml.load(file)
    except FileNotFoundError:
        data = {}

    yield data

    with open(file_path, 'w') as file:
        yaml.dump(data, file)


def run_command_with_live_output(command, **kwargs):
    # Default kwargs for Popen
    popen_kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "bufsize": 1,
        "universal_newlines": True
    }

    # Update with any user-provided kwargs
    popen_kwargs.update(kwargs)

    process = subprocess.Popen(command, **popen_kwargs)

    stdout_output = []
    stderr_output = []

    # Set stdout and stderr to non-blocking mode
    for pipe in [process.stdout, process.stderr]:
        if pipe:
            os.set_blocking(pipe.fileno(), False)

    while True:
        ready_to_read, _, _ = select.select([process.stdout, process.stderr], [], [], 0.1)

        for pipe in ready_to_read:
            if pipe == process.stdout:
                line = process.stdout.readline()
                if line:
                    print(line.strip())
                    stdout_output.append(line)
            elif pipe == process.stderr:
                line = process.stderr.readline()
                if line:
                    print(line.strip(), file=sys.stderr)
                    stderr_output.append(line)

        if process.poll() is not None:
            break

    # Read any remaining output
    for pipe in [process.stdout, process.stderr]:
        if pipe:
            remaining_output = pipe.read()
            if remaining_output:
                print(remaining_output.strip(), file=sys.stderr if pipe == process.stderr else sys.stdout)
                (stderr_output if pipe == process.stderr else stdout_output).append(remaining_output)

    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, command, ''.join(stdout_output), ''.join(stderr_output))

    return ''.join(stdout_output)


def run(cmd, *args, **kwargs):
    # Set check=True
    kwargs['check'] = True
    log.info("Running command: %s" % cmd)
    return subprocess.run(cmd, *args, **kwargs)


def check_output(cmd, *args, **kwargs):
    log.info("Running command: %s" % cmd)
    return subprocess.check_output(cmd, *args, **kwargs)


def read_file(path: str):
    with open(path, "r") as f:
        return f.read().strip()


def write_file(path: str, data: str):
    with open(path, "w") as f:
        f.write(data)


def enable_cache_ext_for_cgroup(cgroup=DEFAULT_CACHE_EXT_CGROUP):
    # Note: With the new per-cgroup interface, cache_ext policies are now
    # attached directly to specific cgroups via the BPF programs,
    # so we no longer need to enable it globally via /proc/cache_ext_enabled_cgroup
    pass


def delete_cgroup(cgroup):
    with suppress(subprocess.CalledProcessError):
        run(["sudo", "cgdelete", f"memory:{cgroup}"])


def recreate_cache_ext_cgroup(cgroup=DEFAULT_CACHE_EXT_CGROUP,
                              limit_in_bytes=2*GiB):
    delete_cgroup(cgroup)
    # Create cache_ext cgroup
    run(["sudo", "cgcreate", "-g", f"memory:{cgroup}"])

    # Set memory limit for cache_ext cgroup
    run(["sudo", "sh", "-c",
         "echo %d > /sys/fs/cgroup/%s/memory.max"
         % (limit_in_bytes, cgroup)])

    log.info(
        "cache_ext cgroup %s created with limit %s",
        cgroup,
        format_bytes_str(limit_in_bytes),
    )


def recreate_baseline_cgroup(cgroup=DEFAULT_BASELINE_CGROUP,
                             limit_in_bytes=2*GiB):
    delete_cgroup(cgroup)
    # Create baseline cgroup
    run(["sudo", "cgcreate", "-g", f"memory:{cgroup}"])

    # Set memory limit for baseline cgroup
    run(["sudo", "sh", "-c",
         "echo %d > /sys/fs/cgroup/%s/memory.max" % (limit_in_bytes, cgroup)])


def drop_page_cache():
    run(["sudo", "sync"])
    run(["sudo", "sh", "-c", "echo 1 > /proc/sys/vm/drop_caches"])


def set_sysctl(key: str, value: Union[int, str]):
    run(["sudo", "sysctl", "-w", f"{key}={value}"])


def disable_swap():
    run(["sudo", "swapoff", "-a"])


def disable_smt():
    run(["sudo", "sh", "-c", "echo off > /sys/devices/system/cpu/smt/control"])


def enable_smt():
    run(["sudo", "sh", "-c", "echo on > /sys/devices/system/cpu/smt/control"])


def rsync_folder(source_dir: str, dest_dir: str):
    # rsync -avpl --delete /mydata/leveldb_db_orig/ /mydata/leveldb_db/
    if not source_dir.endswith("/"):
        source_dir += "/"
    run(["rsync", "-avpl", "--delete", source_dir, dest_dir])


def load_json(path: str):
    with open(path, "r") as f:
        return json.load(f)


def save_json(path: str, data):
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=4)
    os.rename(tmp_path, path)

# Helerp

##########################
# Benchmarking framework #
##########################


class ToJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, "to_json"):
            return obj.to_json()
        return json.JSONEncoder.default(self, obj)


class BenchResults:
    def __init__(self, results: Dict) -> None:
        self.__dict__.update(results)

    def __getitem__(self, key):
        return self.__dict__[key]

    def __setitem__(self, key, value):
        self.__dict__[key] = value

    def to_json(self):
        return self.__dict__

    @classmethod
    def from_json(cls, json_dict: Dict):
        return cls(json_dict)


class BenchRun:
    def __init__(self, config: Dict, results: BenchResults):
        self.config = config
        self.results = results

    def __eq__(self, other: object) -> bool:
        return self.config == other.config

    def to_json(self):
        return self.__dict__


def parse_results_file(results_file: str, benchresults_cls) -> BenchRun:
    with open(results_file, "r") as f:
        results = json.load(f)
    return [BenchRun(r["config"], benchresults_cls.from_json(r["results"])) for r in results]


def exists_config_in_results(results: List[BenchRun], config: Dict) -> bool:
    for r in results:
        if r.config == config:
            return True
    return False


def results_select(results: List[BenchRun], config_match: Dict) -> List[BenchRun]:
    # Select results based on partial config match
    return [r for r in results
            if config_match.items() <= r.config.items()]

def single_result_select(results: List[BenchRun], config_match: Dict) -> BenchRun:
    # Select results based on partial config match
    matches = [r for r in results
               if config_match.items() <= r.config.items()]
    if len(matches) != 1:
        raise Exception("Expected exactly one match, got %s for config_match"
                        " %s" % (len(matches), config_match))
    return matches[0]


def add_config_option(name: str, values: List, configs: List[Dict]) -> List[Dict]:
    new_configs = []
    for config in configs:
        for value in values:
            new_config = config.copy()
            new_config[name] = value
            new_configs.append(new_config)
    return new_configs


def unique_configs_for_keys(configs: List[Dict], keys: List[str]) -> List[Dict]:
    # Return the unique configs for the given keys
    unique_configs = []
    for config in configs:
        unique_config = {}
        for key in keys:
            unique_config[key] = config[key]
        if unique_config not in unique_configs:
            unique_configs.append(unique_config)
    return unique_configs


def checkpoint_results(results_file: str, results: BenchRun):
    temp_results_file = results_file + ".tmp"
    with open(temp_results_file, "w") as f:
        f.write(json.dumps(results, cls=ToJSONEncoder, indent=4))
    os.rename(temp_results_file, results_file)


class BenchmarkFramework(ABC):
    """Simple benchmarking framework.

    Subclass it to implement a benchmark. You need to implement the abstract
    methods."""

    def __init__(self, name: str, benchresults_cls=BenchResults,
                 cli_args=None):
        self.name = name
        self.benchresults_cls = benchresults_cls
        if cli_args:
            self.args = cli_args
        else:
            self.args = self.parse_args()

    def benchmark_prepare(self, config):
        pass

    @abstractmethod
    def benchmark_cmd(self, config):
        raise NotImplementedError

    def cmd_extra_envs(self, config):
        return {}

    def before_benchmark(self, config):
        pass

    def after_benchmark(self, config):
        pass

    @abstractmethod
    def parse_results(self, stdout: str) -> BenchResults:
        raise NotImplementedError

    @abstractmethod
    def add_arguments(self, parser: argparse.ArgumentParser):
        raise NotImplementedError

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        return configs

    def parse_args(self):
        parser = argparse.ArgumentParser("Benchmark %s" % self.name,
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument("--cpu", type=str, default="1",
                            help="Number of CPUs to use. Can be a value, a"
                                 " range, or a list of comma-separated values"
                                 " and ranges")
        parser.add_argument("--results-file", type=str, default="results.json",
                            help="Path to results file (JSON format)")
        # parser.add_argument("--runtime", type=int, default=60,
        #                     help="Runtime in seconds for each benchmark")
        parser.add_argument("--no-reuse-results", action="store_true",
                            default=False,
                            help="Reuse existing results and only calculate"
                            " missing results")
        parser.add_argument("--debug-segfault", action="store_true",
                            default=False, help="Debug segfaults")
        parser.add_argument("--default-only", action="store_true",
                            default=False, help="Run only the default config. Helpful for running MGLRU.")
        parser.add_argument("--iterations", type=int, default=1,
                            help="Number of iterations to run for each config")
        self.add_arguments(parser)
        return parser.parse_args()

    def benchmark(self):
        results_file = self.args.results_file
        reuse_results = not self.args.no_reuse_results
        cpu_str = self.args.cpu

        # Parse CPU string
        cpu_amounts = parse_numbers_string(cpu_str)
        log.info("Will benchmark with each of the following amounts of CPU %s"
                 % cpu_amounts)

        i = 1
        results = []
        while os.path.exists(results_file):
            if reuse_results:
                log.info("Will reuse existing results file %s" % results_file)
                results = parse_results_file(
                    results_file, self.benchresults_cls)
                break
            log.info("Not reusing results file %s" % results_file)
            if "." in results_file:
                filename, ext = results_file.rsplit(".", 1)
                results_file = filename + "_%s." % i + ext
            else:
                results_file = results_file + "_%s" % i
        log.info("Will write results to %s" % results_file)

        all_configs = []
        for cpus in cpu_amounts:
            new_configs = [
                {
                    "name": self.name,
                    "cpus": cpus,
                }
            ]
            new_configs = self.generate_configs(new_configs)
            all_configs.extend(new_configs)

        configs_to_run = []
        for config in all_configs:
            if reuse_results and exists_config_in_results(results, config):
                log.info("Skipping config %s" % config)
            else:
                configs_to_run.append(config)

        for idx, config in enumerate(configs_to_run):
            log.info("Progress: %.1f%% (%s/%s)" %
                     ((idx+1) / len(configs_to_run)*100, idx+1,
                      len(configs_to_run)))
            log.info("Running benchmark for %s with config %s" %
                     (config["name"], config))

            # Prepare environment for benchmarking
            self.benchmark_prepare(config)

            # Run benchmark
            cmd = self.benchmark_cmd(config)

            # Limit CPUs
            cmd = ["taskset", "-c", "0-%s" % str(config["cpus"]-1)] + cmd

            env = os.environ
            if self.args.debug_segfault:
                env["SEGFAULT_SIGNALS"] = "abrt segv"
                env["LD_PRELOAD"] = "/usr/lib/x86_64-linux-gnu/libSegFault.so"
            extra_envs = self.cmd_extra_envs(config)
            if extra_envs:
                log.info("Adding extra envs: %s" % extra_envs)
            env.update(extra_envs)
            self.before_benchmark(config)
            log.info("Running command: %s" % cmd)
            try:
                stdout = run_command_with_live_output(cmd, env=env)
                # stdout = check_output(cmd, encoding="utf-8", env=env)
            except CalledProcessError as e:
                log.error("Benchmark failed with error code %s" % e.returncode)
                log.error("Output was: %s" % e.output)
                raise e

            self.after_benchmark(config)
            # Save results
            log.info("Parsing results...")
            bench_run_results = self.parse_results(stdout)
            bench_run = BenchRun(config, bench_run_results)
            results.append(bench_run)
            checkpoint_results(results_file, results)
            sleep(5)
        all_results = []
        for config in all_configs:
            all_results.append(single_result_select(results, config))
        return all_results


def parse_strings_string(s: str) -> List[str]:
    parts = s.split(",")
    res = []
    for part in parts:
        part = part.strip()
        res.append(part)
    return res


def parse_numbers_string(num_string: str) -> List[int]:
    """Parse a string of comma-separated numbers and ranges into an int list."""
    parts = num_string.split(",")
    num_list = []
    for part in parts:
        if "-" in part:
            start, end = part.split("-")
            num_list.extend(list(range(int(start), int(end) + 1)))
        else:
            num_list.append(int(part))
    return sorted(list(set(num_list)))


def parse_cpu_string(cpu_string: str):
    return parse_numbers_string(cpu_string)


prev_cpu_stats = {
    "idle": 0.0,
    "iowait": 0.0,
    "total": 0.0
}
