#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

#define ENOENT		2  /* include/uapi/asm-generic/errno-base.h */
#define INT64_MAX	(9223372036854775807LL)

// Set from userspace. In terms of number of pages.
// TODO: change

//#define CACHE_SIZE (((1ull << 30) * 2) / 4096)
#define CACHE_SIZE (((1ull << 20) * 200) / 4096)
const volatile size_t cache_size = 0;

struct folio_metadata {
	s64 freq;
	bool in_main;
};

struct ghost_entry {
	u64 address_space;
	u64 offset;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct folio_metadata);
	__uint(max_entries, 4000000);
} folio_metadata_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ghost_entry);
	__type(value, u8);
	//__uint(max_entries, CACHE_SIZE); // TODO: change
	__uint(map_flags, BPF_F_NO_COMMON_LRU);  // Per-CPU LRU eviction logic
} ghost_map SEC(".maps");

static u64 main_list;
static u64 small_list;

/*
 * This is an approximate value based on what we choose to evict, not what is
 * actually evicted.
 */
static s64 small_list_size = 0;
static s64 main_list_size = 0;

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

static inline struct folio_metadata *get_folio_metadata(struct folio *folio) {
	u64 key = (u64)folio;
	return bpf_map_lookup_elem(&folio_metadata_map, &key);
}

/*
 * Check if a folio is in the ghost map and delete the ghost entry.
 * We only check if an element is in the ghost map on inserting into the cache.
 * Relies on bpf_map_delete_elem() returning -ENOENT if the element is not found.
 */
static inline bool folio_in_ghost(struct folio *folio) {
	struct ghost_entry key = {
		.address_space = (u64)folio->mapping->host,
		.offset = folio->index,
	};
	// TODO: handle non-ENOENT errors
	return bpf_map_delete_elem(&ghost_map, &key) != -ENOENT;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(s3fifo_init, struct mem_cgroup *memcg)
{
	main_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (main_list == 0) {
		bpf_printk("cache_ext: init: Failed to create main_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created main_list: %llu\n", main_list);

	small_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (small_list == 0) {
		bpf_printk("cache_ext: init: Failed to create small_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created small_list: %llu\n", small_list);

	return 0;
}

static s64 bpf_s3fifo_score_main_fn(struct cache_ext_list_node *a) {
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return INT64_MAX;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return INT64_MAX;

	struct folio_metadata *data = get_folio_metadata(a->folio);
	if (!data) {
		bpf_printk("cache_ext: score_fn: Failed to get metadata\n");
		return INT64_MAX;
	}

	s64 freq = __sync_sub_and_fetch(&data->freq, 1);
	if (freq < 0)
		data->freq = 0;

	return freq;
}

static int bpf_s3fifo_score_small_fn(int idx, struct cache_ext_list_node *a)
{
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	struct folio_metadata *data = get_folio_metadata(a->folio);
	if (!data) {
		bpf_printk("cache_ext: score_fn: Failed to get metadata\n");
		return CACHE_EXT_CONTINUE_ITER;
	}

	// Move to main list if freq > 1
	if (data->freq > 1) {
		data->in_main = true;
		return CACHE_EXT_CONTINUE_ITER;
	}

	// Else, evict
	return CACHE_EXT_EVICT_NODE;
}

static void evict_main(struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
	/*
	 * Iterate from head. If freq > 0, move to tail, freq--.
	 * Otherwise, evict. (When evicting, move to tail in the meantime).
	 */

	struct sampling_options opts = {
		.sample_size = 10,
	};

	if (bpf_cache_ext_list_sample(memcg, main_list, bpf_s3fifo_score_main_fn, &opts,
				      eviction_ctx)) {
		bpf_printk("cache_ext: evict: Failed to sample main_list\n");
		return;
	}

	// if (__sync_sub_and_fetch(&main_list_size, eviction_ctx->nr_folios_to_evict) < 0)
	// 	main_list_size = 0;
}

#define MAIN_ITER_FN(id) 								\
static int bpf_s3fifo_score_main_iter_fn_##id(int idx, struct cache_ext_list_node *a) 	\
{ 											\
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) 		\
		return CACHE_EXT_CONTINUE_ITER; 					\
 											\
	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) 		\
		return CACHE_EXT_CONTINUE_ITER; 					\
 											\
	struct folio_metadata *data = get_folio_metadata(a->folio); 			\
	if (!data) { 									\
		bpf_printk("cache_ext: score_fn: Failed to get metadata\n"); 		\
		return CACHE_EXT_CONTINUE_ITER; 					\
	} 										\
 											\
	s64 freq = __sync_sub_and_fetch(&data->freq, 1); 				\
	if (freq < id) { 								\
		/*data->freq = 0;*/ 							\
		return CACHE_EXT_EVICT_NODE; 						\
	} 										\
 											\
	return CACHE_EXT_CONTINUE_ITER; 						\
}

MAIN_ITER_FN(0)
MAIN_ITER_FN(1)
MAIN_ITER_FN(2)
MAIN_ITER_FN(3)

static void evict_main_iter(struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
	/*
	 * Iterate from head. If freq > 0, move to tail, freq--.
	 * Otherwise, evict. (When evicting, move to tail in the meantime).
	 */

	struct cache_ext_iterate_opts opts = {
		.continue_list = CACHE_EXT_ITERATE_SELF,
		.continue_mode = CACHE_EXT_ITERATE_TAIL,
		.evict_list = CACHE_EXT_ITERATE_SELF,
		.evict_mode = CACHE_EXT_ITERATE_TAIL,
	};

	if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s3fifo_score_main_iter_fn_0, &opts,
						eviction_ctx) < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
		return;
	}

	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
		if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s3fifo_score_main_iter_fn_1, &opts,
							eviction_ctx) < 0) {
			bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
			return;
		}
	} else {
		return;
	}

	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
		if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s3fifo_score_main_iter_fn_2, &opts,
							eviction_ctx) < 0) {
			bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
			return;
		}
	} else {
		return;
	}

	if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
		if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s3fifo_score_main_iter_fn_3, &opts,
							eviction_ctx) < 0) {
			bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
			return;
		}
	}
}

static void evict_small(struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg)
{
	/*
	 * Iterate from head. If freq > 1, move to main list, otherwise evict.
	 * (When evicting, move to tail in the meantime).
	 *
	 * Use the iterate interface.
	 */

	struct cache_ext_iterate_opts opts = {
		.continue_list = main_list,
		.continue_mode = CACHE_EXT_ITERATE_TAIL,
		.evict_list = CACHE_EXT_ITERATE_SELF,
		.evict_mode = CACHE_EXT_ITERATE_TAIL,
	};

	if (bpf_cache_ext_list_iterate_extended(memcg, small_list, bpf_s3fifo_score_small_fn, &opts,
						eviction_ctx) < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate small_list\n");
		return;
	}

	if (__sync_fetch_and_sub(&small_list_size, opts.nr_folios_continue) < 0)
		small_list_size = 0;

	if (__sync_fetch_and_add(&main_list_size, opts.nr_folios_continue) < 0)
		main_list_size = opts.nr_folios_continue;
}

void BPF_STRUCT_OPS(s3fifo_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	// bpf_printk("cache_ext: evict_folios: main_list_size: %lld, small_list_size: %lld, cache_size: %lld\n",
	// 	   main_list_size, small_list_size, cache_size);
	if (small_list_size >= cache_size / 15 || main_list_size <= 2 * small_list_size)
		evict_small(eviction_ctx, memcg);
	else
		evict_main_iter(eviction_ctx, memcg);
}

void BPF_STRUCT_OPS(s3fifo_folio_accessed, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	struct folio_metadata *data = get_folio_metadata(folio);
	if (!data) {
		bpf_printk("cache_ext: accessed: Failed to get metadata\n");
		return;
	}

	// Cap frequency at 3
	if (__sync_add_and_fetch(&data->freq, 1) > 3)
		data->freq = 3;
}

void BPF_STRUCT_OPS(s3fifo_folio_evicted, struct folio *folio) {
	u64 key = (u64)folio;
	u8 ghost_val = 0;

	// if (bpf_cache_ext_list_del(folio)) {
	// 	bpf_printk("cache_ext: Failed to delete folio from sampling_list\n");
	// 	return;
	// }

	struct ghost_entry ghost_key = {
		.address_space = (u64)folio->mapping->host,
		.offset = folio->index,
	};

	// Don't return early, we want to delete the folio metadata regardless
	if (bpf_map_update_elem(&ghost_map, &ghost_key, &ghost_val, BPF_ANY))
		bpf_printk("cache_ext: evicted: Failed to add to ghost_map\n");

	struct folio_metadata *data = get_folio_metadata(folio);
	if (!data) {
		//bpf_printk("cache_ext: evicted: Failed to get metadata\n");
		return;
	}

	if (data->in_main)
		__sync_fetch_and_sub(&main_list_size, 1);
	else
		__sync_fetch_and_sub(&small_list_size, 1);

	bpf_map_delete_elem(&folio_metadata_map, &key);

	// if (bpf_map_delete_elem(&folio_metadata_map, &key))
	// 	bpf_printk("cache_ext: evicted: Failed to delete metadata\n");
}

/*
 * If folio is in the ghost map, add to tail of main list, otherwise add to tail
 * of small list.
 */
void BPF_STRUCT_OPS(s3fifo_folio_added, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	u64 key = (u64)folio;
	struct folio_metadata new_meta = {
		.freq = 0,
	};

	u64 list_to_add;
	if (folio_in_ghost(folio)) {
		list_to_add = main_list;
		new_meta.in_main = true;
		__sync_fetch_and_add(&main_list_size, 1);
	} else {
		list_to_add = small_list;
		new_meta.in_main = false;
		__sync_fetch_and_add(&small_list_size, 1);
	}

	if (bpf_cache_ext_list_add_tail(list_to_add, folio)) {
		// TODO: add back to ghost_map?
		bpf_printk("cache_ext: added: Failed to add folio to main_list\n");
		return;
	}

	if (bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY)) {
		// TODO: add back to ghost_map? + error check delete call?
		bpf_cache_ext_list_del(folio);
		bpf_printk("cache_ext: added: Failed to create folio metadata\n");
		return;
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops s3fifo_ops = {
	.init = (void *)s3fifo_init,
	.evict_folios = (void *)s3fifo_evict_folios,
	.folio_accessed = (void *)s3fifo_folio_accessed,
	.folio_evicted = (void *)s3fifo_folio_evicted,
	.folio_added = (void *)s3fifo_folio_added,
};
