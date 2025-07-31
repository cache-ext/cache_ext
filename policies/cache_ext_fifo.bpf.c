#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

static u64 main_list;

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(fifo_init, struct mem_cgroup *memcg)
{
	main_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (main_list == 0) {
		bpf_printk("cache_ext: init: Failed to create main_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created main_list: %llu\n", main_list);

	return 0;
}

static int bpf_fifo_evict_cb(int idx, struct cache_ext_list_node *a)
{
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return CACHE_EXT_CONTINUE_ITER;

	return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(fifo_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	if (bpf_cache_ext_list_iterate(memcg, main_list, bpf_fifo_evict_cb, eviction_ctx) < 0) {
		bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
		return;
	}
}

void BPF_STRUCT_OPS(fifo_folio_evicted, struct folio *folio) {
	// if (bpf_cache_ext_list_del(folio)) {
	// 	bpf_printk("cache_ext: Failed to delete folio from list\n");
	// 	return;
	// }
}

void BPF_STRUCT_OPS(fifo_folio_added, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	if (bpf_cache_ext_list_add_tail(main_list, folio)) {
		bpf_printk("cache_ext: added: Failed to add folio to main_list\n");
		return;
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops fifo_ops = {
	.init = (void *)fifo_init,
	.evict_folios = (void *)fifo_evict_folios,
	.folio_evicted = (void *)fifo_folio_evicted,
	.folio_added = (void *)fifo_folio_added,
};
