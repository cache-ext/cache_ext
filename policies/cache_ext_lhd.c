#include <argp.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "dir_watcher.h"
#include "cache_ext_lhd.bpf.h"
#include "cache_ext_lhd.skel.h"

char *USAGE = "Usage: ./cache_ext_lhd --watch_dir <dir> --cgroup_path <path>\n";
struct cmdline_args {
	char *watch_dir;
	char *cgroup_path;
};

static struct argp_option options[] = {
	{ "watch_dir", 'w', "DIR", 0, "Directory to watch" },
	{ "cgroup_path", 'c', "PATH", 0, "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)" },
	{ 0 },
};

static long num_reconfigurations;

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

static int handle_event(void *ctx, void *data, size_t data_sz) {
	// Run BPF reconfigure program using BPF_PROG_RUN
	int ret = 0;
	int reconfigure_prog_fd = *(int *)ctx;

	struct bpf_test_run_opts opts = {
		.sz = sizeof(opts),
	};
	
	++num_reconfigurations;

	ret = bpf_prog_test_run_opts(reconfigure_prog_fd, &opts);
	if (ret)
		perror("Failed to run reconfigure program");

	return ret;
}

int main(int argc, char **argv) {
	struct cmdline_args args = { 0 };
	struct cache_ext_lhd_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	struct ring_buffer *events = NULL;
	struct sigaction sa;
	char watch_dir_path[PATH_MAX];
	int reconfigure_prog_fd;
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

	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		fprintf(stderr, "Failed to open cgroup path %s: %s\n",
			args.cgroup_path, strerror(errno));
		return 1;
	}

	skel = cache_ext_lhd_bpf__open();
	if (!skel) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	watch_dir_path_len_map(skel) = strlen(watch_dir_path);
	strcpy(watch_dir_path_map(skel), watch_dir_path);

	if (cache_ext_lhd_bpf__load(skel)) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	if (initialize_watch_dir_map(watch_dir_path, bpf_map__fd(inode_watchlist_map(skel)), false)) {
		perror("Failed to initialize watch_dir map");
		goto cleanup;
	}

	// Get fd of reconfigure program
	reconfigure_prog_fd = bpf_program__fd(skel->progs.reconfigure);

	events = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, &reconfigure_prog_fd, NULL);
	if (!events) {
		perror("Failed to create ring buffer");
		goto cleanup;
	}

	link = bpf_map__attach_cache_ext_ops(skel->maps.lhd_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach cache_ext_ops to cgroup");
		goto cleanup;
	}

	// This is necessary for the dir_watcher functionality
	if (cache_ext_lhd_bpf__attach(skel)) {
		perror("Failed to attach BPF skeleton");
		goto cleanup;
	}

	while (!exiting) {
		ret = ring_buffer__poll(events, -1); // infinite timeout
		
		if (ret == -EINTR) {
			ret = 0;
			break;
		} else if (ret < 0) {
			fprintf(stderr, "error polling ring buffer: %d\n", ret);
			ret = 1;
			goto cleanup;
		} else {
			ret = 0;
		}
	}

	printf("Number of reconfigurations: %ld\n", num_reconfigurations);

cleanup:
	close(cgroup_fd);
	ring_buffer__free(events);
	bpf_link__destroy(link);
	cache_ext_lhd_bpf__destroy(skel);
	return ret;
}
