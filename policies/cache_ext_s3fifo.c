#include <argp.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "dir_watcher.h"
#include "cache_ext_s3fifo.skel.h"

char *USAGE = "Usage: ./cache_ext_s3fifo --watch_dir <dir> --cgroup_size <size> --cgroup_path <path>\n";
struct cmdline_args {
	char *watch_dir;
        uint64_t cgroup_size;
        char *cgroup_path;
};

static struct argp_option options[] = {
	{ "watch_dir", 'w', "DIR", 0, "Directory to watch" },
        {"cgroup_size", 's', "SIZE", 0, "Size of the cgroup"},
        {"cgroup_path", 'c', "PATH", 0, "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)"},
	{ 0 },
};

static const uint64_t page_size = 4096;

static volatile sig_atomic_t exiting;

static void sig_handler(int signo) {
	exiting = 1;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'w':
		args->watch_dir = arg;
		break;
        case 's':
                // TODO: move this to parse_args()
                errno = 0;
                args->cgroup_size = strtoull(arg, NULL, 10);
                if (errno)
                        args->cgroup_size = 0;

                break;
        case 'c':
                args->cgroup_path = arg;
                break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int parse_args(int argc, char **argv, struct cmdline_args *args) {
	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, args);

	if (args->watch_dir == NULL) {
		fprintf(stderr, "Missing required argument: watch_dir\n");
		return 1;
	}

	if (args->cgroup_size == 0) {
	        fprintf(stderr, "Invalid cgroup size\n");
	        return 1;
	}

	if (args->cgroup_path == NULL) {
		fprintf(stderr, "Missing required argument: cgroup_path\n");
		return 1;
	}

	return 0;
}

/*
 * Validate watch_dir
 *
 * watch_dir_full_path must be able to hold PATH_MAX bytes.
 */
static int validate_watch_dir(const char *watch_dir, char *watch_dir_full_path) {
	// Does watch_dir exist?
	if (access(watch_dir, F_OK) == -1) {
		fprintf(stderr, "Directory does not exist: %s\n", watch_dir);
		return 1;
	}

	// Get full path of watch_dir
	if (realpath(watch_dir, watch_dir_full_path) == NULL) {
		perror("realpath");
		return 1;
	}

	// BPF policy restriction
	if (strlen(watch_dir_full_path) > 128) {
		fprintf(stderr, "watch_dir path too long\n");
		return 1;
	}

	return 0;
}

int main(int argc, char **argv) {
	struct cmdline_args args = { 0 };
	struct cache_ext_s3fifo_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	struct sigaction sa;
	char watch_dir_path[PATH_MAX];
	int cgroup_fd = -1;
	int ret = 1;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	if (parse_args(argc, argv, &args))
		return 1;

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = sig_handler;

	// Install signal handler
	if (sigaction(SIGINT, &sa, NULL)) {
		perror("Failed to set up signal handling");
		return 1;
	}

	if (validate_watch_dir(args.watch_dir, watch_dir_path))
		return 1;

	// Open cgroup directory early
	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	skel = cache_ext_s3fifo_bpf__open();
	if (!skel) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	// Set cache size in terms of number of pages. Assumes uniform page size.
	skel->rodata->cache_size = args.cgroup_size / page_size;
	fprintf(stderr, "Cgroup size: %lu bytes\n", args.cgroup_size);
	fprintf(stderr, "Cache size: %lu pages\n", skel->rodata->cache_size);

	// Resize ghost_map
	if (bpf_map__set_max_entries(skel->maps.ghost_map, skel->rodata->cache_size)) {
		perror("Failed to resize ghost_map");
		ret = 1;
		goto cleanup;
	}

	// Set watch_dir
	watch_dir_path_len_map(skel) = strlen(watch_dir_path);
	strcpy(watch_dir_path_map(skel), watch_dir_path);

	if (cache_ext_s3fifo_bpf__load(skel)) {
		perror("Failed to load BPF skeleton");
		ret = 1;
		goto cleanup;
	}

	if (initialize_watch_dir_map(watch_dir_path, bpf_map__fd(inode_watchlist_map(skel)), true)) {
		perror("Failed to initialize watch_dir map");
		ret = 1;
		goto cleanup;
	}

	link = bpf_map__attach_cache_ext_ops(skel->maps.s3fifo_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach cache_ext_ops to cgroup");
		ret = 1;
		goto cleanup;
	}

	// This is necessary for the dir_watcher functionality
	if (cache_ext_s3fifo_bpf__attach(skel)) {
		perror("Failed to attach BPF skeleton");
		ret = 1;
		goto cleanup;
	}

	// Wait for keyboard input
	printf("Press any key to exit...\n");
	getchar();
	ret = 0;

cleanup:
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_s3fifo_bpf__destroy(skel);
	return ret;
}
