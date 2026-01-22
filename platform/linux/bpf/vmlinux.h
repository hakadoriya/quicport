/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * vmlinux.h - Minimal kernel type definitions for quicport eBPF
 *
 * This file contains only the types needed for SK_REUSEPORT programs.
 * Generated types would normally come from: bpftool btf dump file /sys/kernel/btf/vmlinux format c
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/* Prevent including system headers */
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

/* Basic types */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;

/* Boolean type */
typedef _Bool bool;
#define true 1
#define false 0

/* NULL definition */
#define NULL ((void *)0)

/*
 * sk_reuseport_md - BPF context for SK_REUSEPORT programs
 *
 * This structure is passed to SK_REUSEPORT programs when a packet arrives
 * on a socket group. The program can inspect packet data and select which
 * socket should receive the packet.
 */
struct sk_reuseport_md {
    /*
     * Start of directly accessible data. It points to the byte
     * following UDP header (or IPv4/IPv6 header for TCP syn packets)
     */
    __u32 data;

    /* End of directly accessible data */
    __u32 data_end;

    /*
     * Total length of packet (starting from the MAC header).
     * Note that the directly accessible bytes (data_end - data)
     * could be less than this "len". Those bytes could be
     * indirectly read by bpf_skb_load_bytes().
     */
    __u32 len;

    /*
     * Eth protocol in network order. Since mac header is not yet
     * validated, only eth->h_proto is available.
     */
    __u32 eth_protocol;

    /* IP protocol (IPPROTO_TCP, IPPROTO_UDP, etc.) */
    __u32 ip_protocol;

    /* Is header checksum bound to the packet (i.e. not from CHECKSUM_PARTIAL) */
    __u32 bind_inany;

    /* Hash value for the packet */
    __u32 hash;

    /* Reserved for future use */
    __u32 :32; /* padding */
    __u32 :32; /* padding */
    __u32 :32; /* padding */
    __u32 :32; /* padding */

    /* Migration type */
    __u32 migration;
};

/*
 * bpf_sock - Socket representation in BPF
 */
struct bpf_sock {
    __u32 bound_dev_if;
    __u32 family;
    __u32 type;
    __u32 protocol;
    __u32 mark;
    __u32 priority;
    /* IP addresses in network byte order */
    __u32 src_ip4;
    __u32 src_ip6[4];
    __u32 src_port;     /* host byte order */
    __u32 dst_port;     /* network byte order */
    __u32 dst_ip4;
    __u32 dst_ip6[4];
    __u32 state;
    __s32 rx_queue_mapping;
};

#pragma clang attribute pop

#endif /* __VMLINUX_H__ */
