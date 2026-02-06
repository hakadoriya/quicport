/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * bpf_helpers.h - BPF helper definitions for libbpf-based programs
 *
 * This header provides macros and helper function declarations needed
 * for SK_REUSEPORT BPF programs.
 */

#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

#include "vmlinux.h"

/* BPF program section definition */
#define SEC(name) \
    __attribute__((section(name), used))

/* Prevent inlining */
#define __noinline __attribute__((noinline))

/* Force inlining */
#define __always_inline inline __attribute__((always_inline))

/* License declaration - required for all BPF programs */
#define BPF_LICENSE(license) \
    char _license[] SEC("license") = license

/* Map definition helpers */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/*
 * BPF map types used in this project
 */
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
    BPF_MAP_TYPE_XSKMAP = 17,
    BPF_MAP_TYPE_SOCKHASH = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    /* ... more types exist but not needed here */
};

/*
 * BPF SK_REUSEPORT return values
 */
#define SK_DROP  0
#define SK_PASS  1

/*
 * Map update flags
 */
#define BPF_ANY       0 /* create or update element */
#define BPF_NOEXIST   1 /* create element if it doesn't exist */
#define BPF_EXIST     2 /* update existing element */

/*
 * BPF helper functions - declarations for the compiler
 *
 * These are kernel functions callable from BPF programs.
 * The actual implementation is in the kernel.
 */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

/*
 * bpf_sk_select_reuseport - Select socket from reuseport group
 *
 * @ctx:    Pointer to sk_reuseport_md context
 * @map:    Pointer to BPF_MAP_TYPE_REUSEPORT_SOCKARRAY map
 * @key:    Pointer to key for socket selection
 * @flags:  Reserved (must be 0)
 *
 * Returns: SK_PASS (1) on success, SK_DROP (0) on failure
 *
 * This helper is used in SK_REUSEPORT programs to select which socket
 * from a reuseport group should receive the packet. The map must be
 * of type BPF_MAP_TYPE_REUSEPORT_SOCKARRAY.
 */
static long (*bpf_sk_select_reuseport)(
    struct sk_reuseport_md *ctx,
    void *map,
    void *key,
    __u64 flags
) = (void *) 82;

/*
 * bpf_skb_load_bytes - Load bytes from packet
 *
 * @ctx:    Pointer to sk_reuseport_md context
 * @offset: Offset from the start of packet data
 * @to:     Pointer to buffer to store data
 * @len:    Length of data to load
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Use this to safely load packet data that may be beyond the
 * directly accessible range (data to data_end).
 */
static long (*bpf_skb_load_bytes)(
    const void *ctx,
    __u32 offset,
    void *to,
    __u32 len
) = (void *) 26;

/*
 * bpf_trace_printk - BPF helper #6 (Linux 4.1+)
 *
 * デバッグ用。CAP_SYS_ADMIN が必要。
 * 出力先: /sys/kernel/debug/tracing/trace_pipe
 *
 * 【フォーマット引数の制限: 最大 3 個】
 *
 * BPF ヘルパーの呼び出し規約上、レジスタは R1〜R5 の 5 個に制限される。
 * bpf_trace_printk は R1 (fmt), R2 (fmt_size) で 2 枠消費するため、
 * 残りの R3〜R5 の 3 枠分、フォーマット引数は最大 3 個までしか渡せない。
 *
 *   NG: bpf_printk("a=%d b=%d c=%d d=%d", a, b, c, d);  // 4 個 → エラー
 *   OK: bpf_printk("a=%d b=%d c=%d", a, b, c);           // 3 個 → OK
 *
 * 【bpf_trace_vprintk (helper #177, Linux 5.16+) との違い】
 *
 * Linux 5.16 以降では bpf_trace_vprintk が利用可能で、引数をスタック上の
 * u64 配列にパックして渡すことでフォーマット引数の個数制限を回避できる。
 * libbpf の bpf_printk マクロは引数数に応じて自動的に使い分ける:
 *   - 3 個以下 → bpf_trace_printk
 *   - 4 個以上 → bpf_trace_vprintk
 *
 * 本プロジェクトでは古いカーネル (Linux 4.1+) との互換性を維持するため、
 * bpf_trace_vprintk は使用せず、常に bpf_trace_printk を直接呼び出す。
 * そのためフォーマット引数は最大 3 個に制限される点に注意すること。
 */
static long (*bpf_trace_printk)(
    const char *fmt,
    __u32 fmt_size,
    ...
) = (void *) 6;

/* Debug print macro - compile out in release */
#ifdef DEBUG
#define bpf_printk(fmt, ...)                                    \
    ({                                                          \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#else
#define bpf_printk(fmt, ...) ((void)0)
#endif

#endif /* __BPF_HELPERS_H__ */
