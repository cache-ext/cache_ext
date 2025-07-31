#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";


#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// #define DEBUG
#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif


inline bool is_folio_relevant(struct folio *folio)
{
	if (!folio) {
		return false;
	}
	if (folio->mapping == NULL) {
		return false;
	}
	if (folio->mapping->host == NULL) {
		return false;
	}
	bool res = inode_in_watchlist(folio->mapping->host->i_ino);
	return res;
}

__u64 mru_list;

s32 BPF_STRUCT_OPS_SLEEPABLE(mru_init, struct mem_cgroup *memcg)
{
	dbg_printk("cache_ext: Hi from the mru_init hook! :D\n");
	mru_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (mru_list == 0) {
		bpf_printk("cache_ext: Failed to create mru_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created mru_list: %llu\n", mru_list);
	return 0;
}

void BPF_STRUCT_OPS(mru_folio_added, struct folio *folio)
{
	dbg_printk("cache_ext: Hi from the mru_folio_added hook! :D\n");
	if (!is_folio_relevant(folio)) {
		return;
	}

	int ret = bpf_cache_ext_list_add(mru_list, folio);
	if (ret != 0) {
		bpf_printk("cache_ext: Failed to add folio to mru_list\n");
		return;
	}
	dbg_printk("cache_ext: Added folio to mru_list\n");
}

void BPF_STRUCT_OPS(mru_folio_accessed, struct folio *folio)
{
	int ret;
	dbg_printk("cache_ext: Hi from the mru_folio_accessed hook! :D\n");

	if (!is_folio_relevant(folio)) {
		return;
	}

	ret = bpf_cache_ext_list_move(mru_list, folio, false);
	if (ret != 0) {
		bpf_printk("cache_ext: Failed to move folio to mru_list head\n");
		return;
	}

	dbg_printk("cache_ext: Moved folio to mru_list tail\n");
}

void BPF_STRUCT_OPS(mru_folio_evicted, struct folio *folio)
{
	dbg_printk("cache_ext: Hi from the mru_folio_evicted hook! :D\n");
	bpf_cache_ext_list_del(folio);
}

static int iterate_mru(int idx, struct cache_ext_list_node *node)
{
	if ((idx < 200) && (!folio_test_uptodate(node->folio) || !folio_test_lru(node->folio))) {
		return CACHE_EXT_CONTINUE_ITER;
	}
	return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(mru_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
	       struct mem_cgroup *memcg)
{
	dbg_printk("cache_ext: Hi from the mru_evict_folios hook! :D\n");
	int ret = bpf_cache_ext_list_iterate(memcg, mru_list, iterate_mru,
					     eviction_ctx);
	// Check that the right amount of folios were evicted
	if (ret < 0) {
		bpf_printk("cache_ext: Failed to evict folios\n");
	}
	if (eviction_ctx->request_nr_folios_to_evict > eviction_ctx->nr_folios_to_evict) {
		bpf_printk("cache_ext: Didn't evict enough folios. Requested: %d, Evicted: %d\n",
			   eviction_ctx->request_nr_folios_to_evict,
			   eviction_ctx->nr_folios_to_evict);
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops mru_ops = {
	.init = (void *)mru_init,
	.evict_folios = (void *)mru_evict_folios,
	.folio_accessed = (void *)mru_folio_accessed,
	.folio_evicted = (void *)mru_folio_evicted,
	.folio_added = (void *)mru_folio_added,
};
