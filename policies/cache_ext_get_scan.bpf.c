#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define INT64_MAX  (9223372036854775807LL)

// #define DEBUG
#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif

enum ListType {
    LIST_GENERAL,
    LIST_FOR_SCANS,
    NUM_LISTS,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, bool);
    __uint(max_entries, 100);
} scan_pids SEC(".maps");

static inline bool is_scanning_pid() {
	// Get thread id
	__u64 pid = bpf_get_current_pid_tgid();
	pid = pid & 0xFFFFFFFF;
	// Check if pid is in scan_pids map
	u8 *ret = bpf_map_lookup_elem(&scan_pids, &pid);
	if (ret != NULL) {
		return true;
	}
	return false;
}

/*
 * Maps
 */

#define MAX_PAGES (1 << 20)

struct folio_metadata {
	u64 accesses;
	u64 last_access_time;
	bool touched_by_scan;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct folio_metadata);
	__uint(max_entries, 4000000);
} folio_metadata_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, NUM_LISTS);
} sampling_list_map SEC(".maps");

#define MAX_STAT_NAME_LEN 256

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[MAX_STAT_NAME_LEN]);
	__type(value, s64);
	__uint(max_entries, 256);
} stats SEC(".maps");

// Keys for stats
char STAT_SCAN_PAGES[MAX_STAT_NAME_LEN] = "scan_pages";
char STAT_TOTAL_PAGES[MAX_STAT_NAME_LEN] = "total_pages";
char STAT_EVICTED_SCAN_PAGES[MAX_STAT_NAME_LEN] = "evicted_scan_pages";
char STAT_EVICTED_TOTAL_PAGES[MAX_STAT_NAME_LEN] = "evicted_total_pages";
char STAT_INSERTED_SCAN_PAGES[MAX_STAT_NAME_LEN] = "inserted_scan_pages";
char STAT_INSERTED_TOTAL_PAGES[MAX_STAT_NAME_LEN] = "inserted_total_pages";
char STAT_ACCESSED_SCAN_PAGES[MAX_STAT_NAME_LEN] = "accessed_scan_pages";
char STAT_ACCESSED_TOTAL_PAGES[MAX_STAT_NAME_LEN] = "accessed_total_pages";

static s64 scan_pages = 0;

inline void update_stat(char (*stat_name)[MAX_STAT_NAME_LEN], s64 delta) {
#ifdef DEBUG
	u64 *counter = bpf_map_lookup_elem(&stats, stat_name);
	if (!counter) {
		u64 zero = 0;
		bpf_map_update_elem(&stats, stat_name, &zero, BPF_NOEXIST);
		counter = bpf_map_lookup_elem(&stats, stat_name);
	}
	if (counter) {
		__sync_fetch_and_add(counter, delta);
	}
#endif
}

inline s64 get_stat(char (*stat_name)[MAX_STAT_NAME_LEN]) {
#ifdef DEBUG
	u64 *counter = bpf_map_lookup_elem(&stats, stat_name);
	if (!counter) {
		bpf_printk("cache_ext: Failed to get stat: %s\n", *stat_name);
		return 0;
	}
	return *counter;
#endif
	return 0;
}

inline u64 get_sampling_list(enum ListType list_type)
{
	int map_key = (int) list_type;
	u64 *sampling_list;
	sampling_list = bpf_map_lookup_elem(&sampling_list_map, &map_key);
	if (!sampling_list) {
		return 0;
	}
			dbg_printk("cache_ext: List type %d, got sampling_list: %llu\n", map_key, *sampling_list);
	return *sampling_list;
}

inline bool is_folio_relevant(struct folio *folio)
{
	if (!folio) {
		// bpf_printk("folio not relevant because it's null\n");
		return false;
	}
	if (folio->mapping == NULL) {
		// bpf_printk("folio not relevant because it's mapping is null\n");
		return false;
	}
	if (folio->mapping->host == NULL) {
		// bpf_printk("folio not relevant because it's host is null\n");
		return false;
	}
	bool res = inode_in_watchlist(folio->mapping->host->i_ino);
	// if (!res) {
	// 	bpf_printk("folio not relevant because it's inode is not in watchlist, inode %llu\n",
	// 		   folio->mapping->host->i_ino);

	// }
	return res;
}

// SEC("struct_ops.s/mixed_init")
s32 BPF_STRUCT_OPS_SLEEPABLE(mixed_init, struct mem_cgroup *memcg)
{
	int ret;
	dbg_printk("cache_ext: Hi from the mixed_init hook! :D\n");
	for (enum ListType list_type = 0; list_type < NUM_LISTS; list_type++) {
		u64 sampling_list = bpf_cache_ext_ds_registry_new_list(memcg);
		if (sampling_list == 0) {
			bpf_printk(
				"cache_ext: Failed to create sampling_list\n");
			return -1;
		}
		bpf_printk("cache_ext: Created sampling_list: %llu\n",
			   sampling_list);
		int map_key = list_type;
		ret = bpf_map_update_elem(&sampling_list_map, &map_key,
				    &sampling_list, BPF_ANY);
		if (ret != 0) {
			bpf_printk(
				"cache_ext: Failed to update sampling_list_map\n");
			return -1;
		}
	}
	return 0;
}

void BPF_STRUCT_OPS(mixed_folio_added, struct folio *folio)
{
	dbg_printk(
		"cache_ext: Hi from the mixed_folio_added hook! :D\n");
	if (!is_folio_relevant(folio)) {
		return;
	}
    enum ListType list_type = LIST_GENERAL;
	bool touched_by_scan = is_scanning_pid();
    if (touched_by_scan) {
        list_type = LIST_FOR_SCANS;
    }
    u64 sampling_list = get_sampling_list(list_type);
	if (sampling_list == 0) {
		bpf_printk("cache_ext: Failed to get sampling_list\n");
		return;
	}
	int ret = 0;
    ret = bpf_cache_ext_list_add_tail(sampling_list, folio);
	if (ret != 0) {
		bpf_printk(
			"cache_ext: Failed to add folio to sampling_list\n");
		return;
	}
	dbg_printk("cache_ext: Added folio to sampling_list\n");

    // Stats
	update_stat(&STAT_TOTAL_PAGES, 1);
	update_stat(&STAT_INSERTED_TOTAL_PAGES, 1);
	if (touched_by_scan) {
		__sync_fetch_and_add(&scan_pages, 1);
		//update_stat(&STAT_SCAN_PAGES, 1);
		update_stat(&STAT_INSERTED_SCAN_PAGES, 1);
	}

	// Create folio metadata
	u64 key = (u64)folio;
	struct folio_metadata new_meta = {
		.accesses = 1,
		.touched_by_scan = touched_by_scan,
		.last_access_time = bpf_ktime_get_ns(),
	};
	bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
}

void BPF_STRUCT_OPS(mixed_folio_accessed, struct folio *folio)
{
	if (!is_folio_relevant(folio)) {
		return;
	}
	// TODO: Update folio metadata with other values we want to track
	struct folio_metadata *meta;
	u64 key = (u64)folio;
	meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!meta) {
        // If metadata does not exist, try to add it
		struct folio_metadata new_meta = { 0 };
		int ret = bpf_map_update_elem(&folio_metadata_map, &key,
					      &new_meta, BPF_ANY);
		if (ret != 0) {
			bpf_printk(
				"cache_ext: Failed to create folio metadata in accessed. Return value: %d\n",
				ret);
			return;
		}
		meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
		if (meta == NULL) {
			bpf_printk("cache_ext: Failed to get created folio metadata in accessed\n");
			return;
		}
	}
    // bool touched_by_scan = is_scanning_pid();
	// If the page was inserted by a scan but then accessed by a non-scan,
	// move it to the general list.
    // if (meta->touched_by_scan && !touched_by_scan){
    //     // Update stat
    //     update_stat(&STAT_SCAN_PAGES, -1);
	//     meta->touched_by_nonscan = !touched_by_scan;
    //     // Change list
    //     u64 sampling_list = get_sampling_list(LIST_GENERAL);
    //     if (sampling_list == 0) {
    //         bpf_printk("cache_ext: Failed to get sampling_list\n");
    //         return;
    //     }
    //     bpf_cache_ext_list_del(folio);
    //     bpf_cache_ext_list_add(sampling_list, folio);
    // }

	update_stat(&STAT_ACCESSED_TOTAL_PAGES, 1);
	if (meta->touched_by_scan) {
		update_stat(&STAT_ACCESSED_SCAN_PAGES, 1);
	}
	__sync_fetch_and_add(&meta->accesses, 1);
	meta->last_access_time = bpf_ktime_get_ns();
	// meta->touched_by_scan = touched_by_scan;
}

void BPF_STRUCT_OPS(mixed_folio_evicted, struct folio *folio)
{
	dbg_printk(
		"cache_ext: Hi from the mixed_folio_evicted hook! :D\n");
	int ret = bpf_cache_ext_list_del(folio);
	if (ret != 0) {
		bpf_printk("cache_ext: Failed to delete folio from list: %d\n",
			   ret);
	}

	u64 key = (u64)folio;
	bool touched_by_scan = false;
	struct folio_metadata *meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (meta) {
		touched_by_scan = meta->touched_by_scan;
	} else {
		bpf_printk("cache_ext: Failed to get metadata for evicted folio\n");
	}
	bpf_map_delete_elem(&folio_metadata_map, &key);
	// Update stats
	if (touched_by_scan) {
		__sync_fetch_and_sub(&scan_pages, 1);
		//update_stat(&STAT_SCAN_PAGES, -1);
		update_stat(&STAT_EVICTED_SCAN_PAGES, 1);
	}
	update_stat(&STAT_TOTAL_PAGES, -1);
	update_stat(&STAT_EVICTED_TOTAL_PAGES, 1);

}

static inline bool is_last_page_in_file(struct folio *folio)
{
	struct address_space *mapping = folio->mapping;
	if (!mapping) {
		return false;
	}
	struct inode *inode = mapping->host;
	if (!inode) {
		return false;
	}
	// TODO: Handle hugepages
	if (folio_test_large(folio) ||  folio_test_hugetlb(folio)) {
		bpf_printk("cache_ext: Hugepages not supported\n");
		return false;
	}
	unsigned long long file_size = i_size_read(inode);
	unsigned long long page_index = folio_index(folio);
	unsigned long long page_size = 4096;
	unsigned long long last_page_index = (file_size + page_size - 1) / page_size - 1;
	return page_index == last_page_index;
}

static s64 bpf_lfu_score_fn(struct cache_ext_list_node *a)
{
	s64 score = 0;
	struct folio_metadata *meta_a;
	u64 key_a = (u64)a->folio;
	meta_a = bpf_map_lookup_elem(&folio_metadata_map, &key_a);
	if (!meta_a) {
		bpf_printk("cache_ext: Failed to get metadata\n");
		return INT64_MAX;
	}
	// if (!meta_a->touched_by_scan) {
	// 	bpf_printk("cache_ext: Found page not in scan in score_fn\n");
	// }
	score = meta_a->accesses;
	// In leveldb, the index block is at the end of the file.
	bool is_last_page = is_last_page_in_file(a->folio);
	if (is_last_page) {
		// bpf_printk("cache_ext: Found last page in file\n");
		score += 100000;
	}
	return score;
}

void BPF_STRUCT_OPS(mixed_evict_folios,
		    struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	int sampling_rate = 5;
	dbg_printk(
		"cache_ext: Hi from the mixed_evict_folios hook! :D\n");
    // When evicting, use the scan list first always
	s64 num_scan_pages = scan_pages;
	if (num_scan_pages == 0) {
		bpf_printk("cache_ext: No pages to evict\n");
		return;
	}
	enum ListType list_type = LIST_FOR_SCANS;
	if (num_scan_pages < 1000 * sampling_rate) {
		list_type = LIST_GENERAL;
	}
	u64 sampling_list = get_sampling_list(list_type);
	if (sampling_list == 0) {
		bpf_printk(
			"cache_ext: Failed to get sampling_list on eviction path\n");
		return;
	}
	// TODO: What does the eviction interface look like for sampling?
	struct sampling_options sampling_opts = {
		.sample_size = sampling_rate,
	};
	bpf_cache_ext_list_sample(memcg, sampling_list, bpf_lfu_score_fn,
				  &sampling_opts, eviction_ctx);
	if (eviction_ctx->nr_folios_to_evict != eviction_ctx->request_nr_folios_to_evict) {
		bpf_printk("cache_ext: Failed to evict enough pages: %d/%d\n",
			   eviction_ctx->nr_folios_to_evict,
			   eviction_ctx->request_nr_folios_to_evict);
	}
	dbg_printk("cache_ext: Evicting %d pages (%d requested)\n",
			   eviction_ctx->nr_folios_to_evict,
			   eviction_ctx->request_nr_folios_to_evict);
	dbg_printk("cache_ext: Printing first two and last two folios: %p %p %p %p\n",
			   eviction_ctx->folios_to_evict[0],
			   eviction_ctx->folios_to_evict[1],
			   eviction_ctx->folios_to_evict[32 - 2],
			   eviction_ctx->folios_to_evict[32 - 1]);
}

SEC(".struct_ops.link")
struct cache_ext_ops sampling_ops = {
	.init = (void *)mixed_init,
	.evict_folios = (void *)mixed_evict_folios,
	.folio_accessed = (void *)mixed_folio_accessed,
	.folio_evicted = (void *)mixed_folio_evicted,
	.folio_added = (void *)mixed_folio_added,
};
