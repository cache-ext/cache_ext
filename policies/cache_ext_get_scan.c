#include <argp.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cache_ext_get_scan.skel.h"
#include "dir_watcher.h"

char *USAGE = "Usage: ./cache_ext_get_scan --watch_dir <dir> --cgroup_path <path>\n";
struct cmdline_args {
	char *watch_dir;
	char *cgroup_path;
};

static struct argp_option options[] = { { "watch_dir", 'w', "DIR", 0, "Directory to watch" },
					{ "cgroup_path", 'c', "PATH", 0,
					  "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)" },
					{ 0 } };

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'w':
		args->watch_dir = arg;
		break;
	case 'c':
		args->cgroup_path = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int ret = 1;
	struct cache_ext_get_scan_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// Parse command line arguments
	struct cmdline_args args = { 0 };
	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, &args);

	// Validate arguments
	if (args.watch_dir == NULL) {
		fprintf(stderr, "Missing required argument: watch_dir\n");
		return 1;
	}

	if (args.cgroup_path == NULL) {
		fprintf(stderr, "Missing required argument: cgroup_path\n");
		return 1;
	}

	// Does watch_dir exist?
	if (access(args.watch_dir, F_OK) == -1) {
		fprintf(stderr, "Directory does not exist: %s\n",
			args.watch_dir);
		return 1;
	}

	// Get full path of watch_dir
	char watch_dir_full_path[PATH_MAX];
	if (realpath(args.watch_dir, watch_dir_full_path) == NULL) {
		perror("realpath");
		return 1;
	}

	// TODO: Enable longer length
	if (strlen(watch_dir_full_path) > 128) {
		fprintf(stderr, "watch_dir path too long\n");
		return 1;
	}

	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	// Open skel
	skel = cache_ext_get_scan_bpf__open();
	if (skel == NULL) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	// Set watch_dir
	skel->rodata->watch_dir_path_len = strlen(watch_dir_full_path);
	strcpy(skel->rodata->watch_dir_path, watch_dir_full_path);

	// Load programs
	ret = cache_ext_get_scan_bpf__load(skel);
	if (ret) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	// Initialize inode_watchlist map
	ret = initialize_watch_dir_map(args.watch_dir,
				       bpf_map__fd(skel->maps.inode_watchlist), false);

	// Pin scan_pids map
	ret = bpf_map__pin(skel->maps.scan_pids, "/sys/fs/bpf/cache_ext/scan_pids");
	if (ret < 0) {
		perror("Failed to pin scan_pids map");
		goto cleanup;
	}

	// Attach cache_ext_ops to the specific cgroup
	link = bpf_map__attach_cache_ext_ops(skel->maps.sampling_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach cache_ext_ops to cgroup");
		goto cleanup_unpin;
	}

	// Attach probes
	ret = cache_ext_get_scan_bpf__attach(skel);
	if (ret) {
		perror("Failed to attach BPF programs");
		goto cleanup_unpin;
	}

	// Wait for keyboard input
	printf("Press any key to exit...\n");
	getchar();
	ret = 0;

cleanup_unpin:
	// Unpin scan_pids map
	if (bpf_map__unpin(skel->maps.scan_pids, "/sys/fs/bpf/cache_ext/scan_pids") < 0)
		perror("Failed to unpin scan_pids map");

cleanup:
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_get_scan_bpf__destroy(skel);
	return ret;
}
