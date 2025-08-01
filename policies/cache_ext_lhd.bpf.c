#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"
#include "cache_ext_lhd.bpf.h"

char _license[] SEC("license") = "GPL";

static u64 next_reconfiguration = REQS_PER_RECONFIG;
static u32 num_reconfigurations = 0;

static u64 age_coarsening_shift = INITIAL_AGE_COARSENING_SHIFT;
static u64 ewma_num_objects = 0;
static u64 ewma_num_objects_mass = 0;

static u64 ewma_victim_hit_density = 0;

/*
static u64 recently_admitted_head = 0;
static u64 recently_admitted[RECENTLY_ADMITTED_SIZE];
*/

// Current number of requests
static u64 timestamp = 0;

// For debugging purposes
static u64 overflows = 0;

static u64 lhd_list;

static u64 num_objects = 0;

#define INT64_MAX  (9223372036854775807LL)

// We omit size, assume all folios are same size for now
struct folio_metadata {
	u64 last_access_time;
	u64 last_hit_age;
	u64 last_last_hit_age;
	u32 app;
};

struct lhd_class {
	u64 total_hits;
	u64 total_evictions;

	u64 hits[MAX_AGE];
	u64 evictions[MAX_AGE];
	u64 hit_densities[MAX_AGE];
};

static struct lhd_class classes[NUM_CLASSES];

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct folio_metadata);
	__uint(max_entries, 4000000);
} folio_metadata_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

static inline long ewma_decay(u64 val) {
	return (val * 9) / 10;
}

static inline long rem_ewma_decay(u64 val) {
	return val / 10;
}

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

static inline struct folio_metadata *get_folio_metadata(struct folio *folio) {
	u64 key = (u64)folio;
	return bpf_map_lookup_elem(&folio_metadata_map, &key);
}

static inline u32 hit_age_to_class(u64 hit_age) {
	u32 class = 0;

	if (hit_age == 0)
		return 0;

	// Approximates log(MAX_AGE - hit_age)
	while (hit_age < MAX_AGE && class < HIT_AGE_CLASSES - 1) {
		hit_age <<= 1;
		class++;
	}

	return class;
}

static inline u32 get_class_id(struct folio_metadata *data) {
	u32 hit_age_id = hit_age_to_class(data->last_hit_age + data->last_last_hit_age);
	return data->app * HIT_AGE_CLASSES + hit_age_id;
}

static inline struct lhd_class *get_class(struct folio_metadata *data) {
	u32 class_id = get_class_id(data);
	return &classes[class_id & NUM_CLASSES_MASK];
}

static inline u64 get_age(struct folio_metadata *data) {
	u64 age = (timestamp - data->last_access_time) >> age_coarsening_shift;

	if (age >= MAX_AGE) {
		overflows++;
		return MAX_AGE - 1;
	} 

	return age;
}

static inline u64 get_hit_density(struct folio_metadata *data) {
	u64 age = get_age(data);
	if (age == MAX_AGE - 1)
		return 0;

	struct lhd_class *cls = get_class(data);
	if (!cls)
		return -1;

	return cls->hit_densities[age & MAX_AGE_MASK];
}

static inline void update_class(struct lhd_class *class) {
	int i;

	class->total_hits = 0;
	class->total_evictions = 0;

	bpf_for(i, 0, MAX_AGE) {
		class->hits[i] = ewma_decay(class->hits[i]);
		class->evictions[i] = ewma_decay(class->evictions[i]);

		class->total_hits += class->hits[i];
		class->total_evictions += class->evictions[i];
	}
}

static inline void stretch_distribution(s32 delta) {
	int i;
	bpf_for(i, 0, NUM_CLASSES) {
		struct lhd_class *cls = &classes[i];
		int init_age = MAX_AGE >> (-delta);
		u32 j;

		bpf_for(j, init_age, MAX_AGE - 1) {
			cls->hits[MAX_AGE - 1] += cls->hits[j];
			cls->evictions[MAX_AGE - 1] = cls->evictions[j];
		}
		bpf_for(j, 2, MAX_AGE + 1) { // MAX_AGE -2 -> 0
			u32 index = MAX_AGE - j;
			cls->hits[index & MAX_AGE_MASK] =
				cls->hits[(j >> (-delta)) & MAX_AGE_MASK] /
				(1 << (-delta));
			cls->evictions[index & MAX_AGE_MASK] =
				cls->evictions[(j >> (-delta)) & MAX_AGE_MASK] /
				(1 << (-delta));
		}
	}
}

static inline void compress_distribution(s32 delta) {
	int i;
	bpf_for(i, 0, NUM_CLASSES) {
		struct lhd_class *cls = &classes[i];
		u32 j;

		bpf_for(j, 0, MAX_AGE >> delta) {
			cls->hits[j & MAX_AGE_MASK] =
				cls->hits[(j << delta) & MAX_AGE_MASK];
			cls->evictions[j & MAX_AGE_MASK] =
				cls->evictions[(j << delta) & MAX_AGE_MASK];
			int k;
			bpf_for(k, 1, (1 << delta)) {
				cls->hits[j & MAX_AGE_MASK] +=
					cls->hits[((j << delta) + k) &
						  MAX_AGE_MASK];
				cls->evictions[j & MAX_AGE_MASK] +=
					cls->evictions[((j << delta) + k) &
						       MAX_AGE_MASK];
			}
		}

		bpf_for(j, MAX_AGE >> delta, MAX_AGE - 1) {
			cls->hits[j & MAX_AGE_MASK] = 0;
			cls->evictions[j & MAX_AGE_MASK] = 0;
		}
	}
}

static inline void adapt_age_coarsening(void) {
	ewma_num_objects = ewma_decay(ewma_num_objects);
	ewma_num_objects_mass = ewma_decay(ewma_num_objects_mass);

	ewma_num_objects += num_objects * NUM_OBJECTS_SCALING_FACTOR;
	ewma_num_objects_mass += 1;

	u64 num_objects_coarsening = ewma_num_objects / ewma_num_objects_mass;

	u64 optimal_age_coarsening =
		1 * num_objects_coarsening * AGE_COARSENING_ERROR_TOLERANCE / MAX_AGE;

	if (num_reconfigurations == 5 || num_reconfigurations == 25) {
		u32 optimal_age_coarsening_log2 = 1;

		while ((1 << optimal_age_coarsening_log2) * NUM_OBJECTS_SCALING_FACTOR <
		       optimal_age_coarsening)
			optimal_age_coarsening_log2++;

		s32 delta = optimal_age_coarsening_log2 - age_coarsening_shift;
		age_coarsening_shift = optimal_age_coarsening_log2;

		ewma_num_objects *= 8;
		ewma_num_objects_mass *= 8;

		if (delta < 0)
			stretch_distribution(delta);
		else if (delta > 0)
			compress_distribution(delta);
	}
}

static inline void model_hit_density(void) {
	int i;

	bpf_for(i, 0, NUM_CLASSES) {
		struct lhd_class *cls = &classes[i];
		u64 total_hits = cls->hits[MAX_AGE - 1];
		u64 total_events = total_hits + cls->evictions[MAX_AGE - 1];
		u64 lifetime_unconditoned = total_events;

		int j;
		bpf_for(j, 2, MAX_AGE + 1) {
			u32 index = MAX_AGE - j;

			total_hits += cls->hits[index & MAX_AGE_MASK];
			total_events += cls->evictions[index & MAX_AGE_MASK];
			lifetime_unconditoned += total_events;

			if (total_events > TOTAL_EVENTS_THRESH)
				cls->hit_densities[index & MAX_AGE_MASK] =
					total_hits * HIT_DENSITY_SCALING_FACTOR /
					lifetime_unconditoned;
			else
				cls->hit_densities[index & MAX_AGE_MASK] = 0;
		}
	}
}

SEC("syscall")
int reconfigure(void) {
	int i;

	bpf_for(i, 0, NUM_CLASSES) {
		update_class(&classes[i]);
	}

	adapt_age_coarsening();

	model_hit_density();

	overflows = 0;

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(lhd_init, struct mem_cgroup *memcg) {
	uint32_t i;

	lhd_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (lhd_list == 0) {
		bpf_printk("cache_ext: init: Failed to create lhd_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created lhd_list: %llu\n", lhd_list);

	/*
	 * BPF global variables are zero-initialized, so we only need to
	 * initialize the hit densities.
	 */
	bpf_for(i, 0, NUM_CLASSES) {
		uint32_t j;

		// Initialize hit densities to GDSF
		struct lhd_class *cls = &classes[i];
		bpf_for(j, 0, MAX_AGE) {
			cls->hit_densities[j] = 1 * HIT_DENSITY_SCALING_FACTOR * (i + 1) / (j + 1);
		}
	}

	return 0;
}

static s64 bpf_lhd_score_fn(struct cache_ext_list_node *a) {
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return INT64_MAX;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return INT64_MAX;

	struct folio_metadata *data = get_folio_metadata(a->folio);
	if (!data) {
		bpf_printk("cache_ext: score_fn: Failed to get metadata\n");
		return INT64_MAX;
	}

	return get_hit_density(data);
}

void BPF_STRUCT_OPS(lhd_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
	       struct mem_cgroup *memcg)
{
	struct sampling_options opts = {
		.sample_size = 16,
	};

	if (bpf_cache_ext_list_sample(memcg, lhd_list, bpf_lhd_score_fn, &opts, eviction_ctx)) {
		bpf_printk("cache_ext: evict: Failed to sample\n");
		return;
	}

	/*
	 * Yields the following verifier error:
	 * 	R2 is ptr_cache_ext_eviction_ctx invalid variable offset: off=272, var_off=(0x0; 0xf8)
	 */
	// Deal with recently_admitted folios
	/*for (int i = 0; i < RECENTLY_ADMITTED_SIZE; i++) {
		size_t index = (recently_admitted_head + i) % RECENTLY_ADMITTED_SIZE;
		struct folio *folio = (struct folio *)recently_admitted[index];
		if (!folio)
			break;

		struct folio_metadata *data = get_folio_metadata(folio);
		if (!data) {
			bpf_printk("cache_ext: Failed to get metadata\n");
			continue;
		}

		u64 hit_density = get_hit_density(data);
		if (hit_density == -1) {
			bpf_printk("cache_ext: Failed to get hit density\n");
			continue;
		}

		// TODO: improve this?
		int j;
		bpf_for(j, 0, eviction_ctx->nr_folios_to_evict) {
			if (hit_density < eviction_ctx->scores[j & 31]) {
				eviction_ctx->folios_to_evict[j & 31] = folio;
				eviction_ctx->scores[j & 31] = hit_density;
				break;
			}
		}
	}*/
}

void BPF_STRUCT_OPS(lhd_folio_accessed, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	struct folio_metadata *data = get_folio_metadata(folio);
	if (!data) {
		bpf_printk("cache_ext: accessed: Failed to get metadata\n");
		return;
	}

	u64 age = get_age(data);
	struct lhd_class *cls = get_class(data);
	if (!cls) {
		bpf_printk("cache_ext: Failed to get class\n");
		return;
	}

	data->last_last_hit_age = data->last_hit_age;
	data->last_hit_age = age;
	data->last_access_time = timestamp;
	// data->app = DEFAULT_APP_ID % APP_CLASSES;

	u64 *hits = cls->hits + age;

	__sync_fetch_and_add(hits, 1 * HIT_SCALING_FACTOR);

	__sync_fetch_and_add(&timestamp, 1);

	if (__sync_sub_and_fetch(&next_reconfiguration, 1) == 0) {
		next_reconfiguration = REQS_PER_RECONFIG;
		num_reconfigurations++;

		// Submit reconfigure event to ring buffer
		if (bpf_ringbuf_output(&events, &num_reconfigurations, sizeof(num_reconfigurations), 0))
			bpf_printk("cache_ext: Failed to submit reconfigure event\n");
	}
}

void BPF_STRUCT_OPS(lhd_folio_evicted, struct folio *folio) {
	u64 key = (u64)folio;
	u64 age, hit_density, *evictions;
	struct lhd_class *cls;

	// if (bpf_cache_ext_list_del(folio)) {
	// 	bpf_printk("cache_ext: Failed to delete folio from sampling_list\n");
	// 	return;
	// }

	struct folio_metadata *data = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!data) {
		//bpf_printk("cache_ext: evicted: Failed to get metadata\n");
		return;
	}

	age = get_age(data);
	cls = get_class(data);
	if (!cls) {
		bpf_printk("cache_ext: evicted: Failed to get class\n");
		return;
	}

	evictions = cls->evictions + age;

	__sync_fetch_and_add(evictions, 1 * HIT_SCALING_FACTOR);

	__sync_fetch_and_sub(&num_objects, 1);

	// Open-coded get_hit_density()
	hit_density = cls->hit_densities[age];
	ewma_victim_hit_density = ewma_decay(ewma_victim_hit_density) + rem_ewma_decay(hit_density);

	// Remove folio metadata
	if (bpf_map_delete_elem(&folio_metadata_map, &key))
		bpf_printk("cache_ext: evicted: Failed to delete metadata\n");
}

void BPF_STRUCT_OPS(lhd_folio_added, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	if (bpf_cache_ext_list_add_tail(lhd_list, folio)) {
		bpf_printk("cache_ext: added: Failed to add folio to lhd_list\n");
		return;
	}

	u64 key = (u64)folio;
	struct folio_metadata new_meta = {
		.last_access_time = timestamp,
		.last_hit_age = 0,
		.last_last_hit_age = MAX_AGE,
		.app = DEFAULT_APP_ID % APP_CLASSES,
	};

	if (bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY)) {
		bpf_cache_ext_list_del(folio);
		bpf_printk("cache_ext: added: Failed to create folio metadata\n");
		return;
	}

	// Track likely eviction candidates
	// u64 hit_density = get_hit_density(&new_meta);
	// if (hit_density == -1) {
	// 	bpf_printk("cache_ext: added: Failed to get hit density\n");
	// 	return;
	// }

	/*
	if (hit_density < ewma_victim_hit_density)
		recently_admitted[recently_admitted_head++ % RECENTLY_ADMITTED_SIZE] = (u64)folio;
	*/

	__sync_fetch_and_add(&timestamp, 1);

	__sync_fetch_and_add(&num_objects, 1);

	if (__sync_sub_and_fetch(&next_reconfiguration, 1) == 0) {
		next_reconfiguration = REQS_PER_RECONFIG;
		num_reconfigurations++;

		// Submit reconfigure event to ring buffer
		if (bpf_ringbuf_output(&events, &num_reconfigurations, sizeof(num_reconfigurations), 0))
			bpf_printk("cache_ext: added: Failed to submit reconfigure event\n");
	}
}

SEC(".struct_ops.link")
struct cache_ext_ops lhd_ops = {
	.init = (void *)lhd_init,
	.evict_folios = (void *)lhd_evict_folios,
	.folio_accessed = (void *)lhd_folio_accessed,
	.folio_evicted = (void *)lhd_folio_evicted,
	.folio_added = (void *)lhd_folio_added,
};
