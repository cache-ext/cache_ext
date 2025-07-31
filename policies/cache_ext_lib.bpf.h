#ifndef _CACHE_EXT_LIB_BPF_H
#define _CACHE_EXT_LIB_BPF_H 1

#define U32_MAX		((u32)~0U)
#define U64_MAX		((u64)~0ULL)
#define S64_MAX		((s64)(U64_MAX >> 1))

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Generic

#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name)      \
	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
	SEC("struct_ops.s/" #name)              \
	BPF_PROG(name, ##args)

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

#define barrier() asm volatile("" ::: "memory")

typedef __u8  __attribute__((__may_alias__))  __u8_alias_t;
typedef __u16 __attribute__((__may_alias__)) __u16_alias_t;
typedef __u32 __attribute__((__may_alias__)) __u32_alias_t;
typedef __u64 __attribute__((__may_alias__)) __u64_alias_t;

static __always_inline void __read_once_size(const volatile void *p, void *res, int size)
{
    switch (size) {
    case 1: *(__u8_alias_t  *) res = *(volatile __u8_alias_t  *) p; break;
    case 2: *(__u16_alias_t *) res = *(volatile __u16_alias_t *) p; break;
    case 4: *(__u32_alias_t *) res = *(volatile __u32_alias_t *) p; break;
    case 8: *(__u64_alias_t *) res = *(volatile __u64_alias_t *) p; break;
    default:
        barrier();
        __builtin_memcpy((void *)res, (const void *)p, size);
        barrier();
    }
}

#define READ_ONCE(x)                                \
({                                                  \
    union { typeof(x) __val; char __c[1]; } __u =   \
        { .__c = { 0 } };                           \
    __read_once_size(&(x), __u.__c, sizeof(x));     \
    __u.__val;                                      \
})


static __always_inline void __write_once_size(volatile void *p, void *res, int size)
{
    switch (size) {
    case 1: *(volatile  __u8_alias_t *) p = *(__u8_alias_t  *) res; break;
    case 2: *(volatile __u16_alias_t *) p = *(__u16_alias_t *) res; break;
    case 4: *(volatile __u32_alias_t *) p = *(__u32_alias_t *) res; break;
    case 8: *(volatile __u64_alias_t *) p = *(__u64_alias_t *) res; break;
    default:
        barrier();
        __builtin_memcpy((void *)p, (const void *)res, size);
        barrier();
    }
}

#define WRITE_ONCE(x, val)                          \
({                                                  \
    union { typeof(x) __val; char __c[1]; } __u =   \
        { .__val = (val) };                         \
    __write_once_size(&(x), __u.__c, sizeof(x));    \
    __u.__val;                                      \
})

// cache_ext BPF API

int bpf_cache_ext_list_add(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_add_tail(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_del(struct folio *folio) __ksym;
int bpf_cache_ext_list_move(u64 list, struct folio *folio, bool tail) __ksym;
int bpf_cache_ext_list_iterate(struct mem_cgroup *memcg, u64 list,
			       int(iter_fn)(int idx, struct cache_ext_list_node *node),
			       struct cache_ext_eviction_ctx *ctx) __ksym;
int bpf_cache_ext_list_iterate_extended(struct mem_cgroup *memcg, u64 list,
					int(iter_fn)(int idx, struct cache_ext_list_node *node),
					struct cache_ext_iterate_opts *opts,
					struct cache_ext_eviction_ctx *ctx) __ksym;
int bpf_cache_ext_list_sample(struct mem_cgroup *memcg, u64 list,
			      s64(score_fn)(struct cache_ext_list_node *a),
			      struct sampling_options *opts,
			      struct cache_ext_eviction_ctx *ctx) __ksym;
u64 bpf_cache_ext_ds_registry_new_list(struct mem_cgroup *memcg) __ksym;

#define BITS_PER_LONG 64
#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)

#define bitop(op, nr, addr)						\
	((__builtin_constant_p(nr) &&					\
	  __builtin_constant_p((uintptr_t)(addr) != (uintptr_t)NULL) &&	\
	  (uintptr_t)(addr) != (uintptr_t)NULL &&			\
	  __builtin_constant_p(*(const unsigned long *)(addr))) ?	\
	 const##op(nr, addr) : op(nr, addr))

#define test_bit(nr, addr)		bitop(_test_bit, nr, addr)
#define _test_bit

#define FOLIO_PF_ANY		0
#define pgoff_t unsigned long


static __always_inline bool
generic_test_bit(unsigned long nr, const volatile unsigned long *addr)
{
	/*
	 * Unlike the bitops with the '__' prefix above, this one *is* atomic,
	 * so `volatile` must always stay here with no cast-aways. See
	 * `Documentation/atomic_bitops.txt` for the details.
	 */
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

static inline unsigned long *folio_flags(struct folio *folio, unsigned n)
{
	struct page *page = &folio->page;
	return &page[n].flags;
}


static inline bool folio_test_uptodate(struct folio *folio)
{
	bool ret = generic_test_bit(PG_uptodate, folio_flags(folio, 0));

	return ret;
}

static inline bool folio_test_lru(struct folio *folio)
{
	bool ret = generic_test_bit(PG_lru, folio_flags(folio, 0));

	return ret;
}

static inline bool folio_test_dirty(struct folio *folio)
{
	bool ret = generic_test_bit(PG_dirty, folio_flags(folio, 0));

	return ret;
}

static inline bool folio_test_reclaim(struct folio *folio)
{
	bool ret = generic_test_bit(PG_reclaim, folio_flags(folio, 0));

	return ret;
}


static inline bool folio_test_writeback(struct folio *folio)
{
	bool ret = generic_test_bit(PG_writeback, folio_flags(folio, 0));

	return ret;
}


static __always_inline bool folio_test_head(struct folio *folio)
{
	return generic_test_bit(PG_head, folio_flags(folio, FOLIO_PF_ANY));
}

static inline bool folio_test_large(struct folio *folio)
{
	return folio_test_head(folio);
}

static inline bool folio_test_locked(struct folio *folio)
{
	bool ret = generic_test_bit(PG_locked, folio_flags(folio, 0));

	return ret;
}


static inline bool folio_test_hugetlb(struct folio *folio)
{
	return folio_test_large(folio) &&
		generic_test_bit(PG_hugetlb, folio_flags(folio, 1));
}

static inline bool folio_test_unevictable(struct folio *folio)
{
	bool ret = generic_test_bit(PG_unevictable, folio_flags(folio, 0));

	return ret;
}

static inline long folio_nr_pages(struct folio *folio)
{
	return 1;
	// if (!folio_test_large(folio))
	// 	return 1;
	// return folio->_folio_nr_pages;
}

static inline loff_t i_size_read(const struct inode *inode)
{
	// IMPORTANT: This assumes a 64-bit kernel.
	// TODO: Don't compile if that's not the case.
	return inode->i_size;
}


/* from pagemap.h */
static inline pgoff_t folio_index(struct folio *folio)
{
	// TODO: Handle swapcache
	// if (unlikely(folio_test_swapcache(folio)))
	//         return swapcache_index(folio);
	return folio->index;
}


///////////////////////////////////////////////////////////////////////////////
// Generic Utils //////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// Generate a random number in [0, max).
static inline u32 bpf_get_random_unbiased(u32 max) {
	// XXX: Address modulo bias.
	if (max == 0) {
		return 0;
	}
	u32 max_divisible = U32_MAX - (U32_MAX % max);
	u32 max_retries = 10;
	u32 res;
	for (int i = 0; i < max_retries; i++) {
		res = bpf_get_prandom_u32();
		if (res < max_divisible) {
			return res % max;
		}
	}
	bpf_printk("bpf_get_random: max_retries reached\n");
	return res % max;
}

// Generate a random number in [0, max).
static inline u32 bpf_get_random_biased(u32 max) {
	// XXX: Address modulo bias.
	if (max == 0) {
		return 0;
	}
	return bpf_get_prandom_u32() % max;
}

#endif /* _CACHE_EXT_LIB_BPF_H */
