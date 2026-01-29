// SPDX-License-Identifier: Apache-2.0
/*
 * quicport_reuseport.bpf.c - QUIC Connection ID based packet routing
 *
 * This BPF_PROG_TYPE_SK_REUSEPORT program routes incoming QUIC packets
 * to the correct Data Plane process based on the Connection ID embedded
 * in the packet header.
 *
 * # How It Works
 *
 * 1. Multiple Data Plane processes bind to the same UDP port with SO_REUSEPORT
 * 2. Each Data Plane registers its socket in the REUSEPORT_SOCKARRAY map
 *    using its assigned server_id as the key
 * 3. When a QUIC packet arrives, this program:
 *    a. Extracts the Destination Connection ID from the QUIC header
 *    b. Reads the server_id from the first 4 bytes of the CID
 *    c. Selects the corresponding socket from the map
 * 4. This ensures that packets for existing connections go to the old process
 *    while new connections can be handled by the new process
 *
 * # Graceful Restart Flow
 *
 *   Time    Old DP (server_id=1)    New DP (server_id=2)
 *   ----    -------------------     --------------------
 *   t0      Running, serving        -
 *   t1      Running                 Starts, registers in map
 *   t2      In drain mode           Accepts new connections
 *   t3      Existing conns only     CIDs contain server_id=2
 *   t4      Exits after drain       Full service
 *
 * # Author
 *
 * quicport project - https://github.com/hakadoriya/quicport
 */

#include "bpf_helpers.h"
#include "quicport_reuseport.h"

/*
 * socket_map - REUSEPORT_SOCKARRAY for socket selection
 *
 * Key: server_id (u32)
 * Value: Socket (managed by kernel)
 *
 * Each Data Plane process registers its socket with its server_id.
 * When a packet arrives, we extract server_id from the QUIC CID
 * and use it to select the correct socket.
 */
struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, MAX_SOCKETS);
    __type(key, __u32);
    __type(value, __u64);
} socket_map SEC(".maps");

/*
 * Check if data points to UDP header instead of UDP payload
 *
 * SK_REUSEPORT の ctx->data は、カーネルバージョンによって:
 * - UDP ペイロード（QUIC データ）を指す場合
 * - UDP ヘッダーを指す場合
 * がある。
 *
 * UDP ヘッダーの length フィールド（オフセット 4-5）と ctx->len を比較して判断する。
 * UDP length = ヘッダー(8バイト) + ペイロードの長さ
 * ctx->len が UDP length と一致する場合、ctx->data は UDP ヘッダーを指している。
 *
 * UDP Header format:
 *   +------------------+------------------+
 *   | Source Port (2B) | Dest Port (2B)   |
 *   +------------------+------------------+
 *   | Length (2B)      | Checksum (2B)    |
 *   +------------------+------------------+
 *    0                 2                 4                 6                 8
 *
 * @param data: データの先頭ポインタ
 * @param data_end: データの終端ポインタ
 * @param ctx_len: ctx->len の値
 * @return: 1 if UDP header, 0 if QUIC data
 */
static __always_inline int
is_udp_header(void *data, void *data_end, __u32 ctx_len)
{
    /* Need at least 6 bytes to read UDP length field */
    if (data + 6 > data_end) {
        return 0;
    }

    __u8 *bytes = (__u8 *)data;

    /*
     * UDP length is at offset 4-5 (big endian)
     * If UDP length matches ctx->len, this is UDP header
     */
    __u16 udp_len = ((__u16)bytes[4] << 8) | bytes[5];

    return udp_len == ctx_len;
}

/*
 * Extract server_id from packet data
 *
 * This function reads the QUIC header and extracts the server_id
 * (first 4 bytes of Destination Connection ID).
 *
 * @param data: Pointer to QUIC packet data (after UDP header if needed)
 * @param data_end: Pointer to end of packet data
 * @param server_id: Output pointer for server_id (in native byte order)
 *
 * @return: 0 on success, negative on error
 */
static __always_inline int
extract_server_id_from_quic(void *data, void *data_end, __u32 *server_id)
{
    __u8 flags;
    __u32 cid_offset;

    /* Need at least 1 byte to read flags */
    if (data + 1 > data_end) {
        return -1;
    }

    flags = *(__u8 *)data;

    /*
     * Determine header type and CID offset
     *
     * QUIC header format detection:
     * - Bit 7 (0x80) = 1: Long Header (Initial, Handshake, 0-RTT, Retry)
     * - Bit 7 (0x80) = 0: Short Header (1-RTT)
     */
    if (flags & QUIC_FLAGS_LONG_HEADER_MASK) {
        /* Long Header: CID at offset 6 (after flags, version, dcid_len) */
        cid_offset = QUIC_LONG_HEADER_DCID_OFFSET;

        /* Verify we have enough data */
        if (data + QUIC_MIN_LONG_HEADER_LEN > data_end) {
            return -1;
        }

        /*
         * Validate DCID Length field
         *
         * For quicport, we expect exactly 8-byte CIDs.
         * If DCID length is 0 or doesn't match our format, skip routing.
         */
        __u8 dcid_len = *(__u8 *)(data + QUIC_LONG_HEADER_DCID_LEN_OFFSET);
        if (dcid_len != QUICPORT_CID_LEN) {
            return -1;
        }
    } else {
        /* Short Header: CID at offset 1 (after flags) */
        cid_offset = QUIC_SHORT_HEADER_CID_OFFSET;

        /* Verify we have enough data */
        if (data + QUIC_MIN_SHORT_HEADER_LEN > data_end) {
            return -1;
        }
    }

    /*
     * Extract server_id from CID (Big Endian -> Native)
     *
     * The CID format is:
     *   [server_id (4 bytes, BE)][counter (4 bytes, BE)]
     *
     * We read the first 4 bytes and convert to native byte order.
     */
    __u8 *cid = (__u8 *)(data + cid_offset);

    /* Bounds check for server_id bytes */
    if ((void *)(cid + QUICPORT_SERVER_ID_LEN) > data_end) {
        return -1;
    }

    /*
     * Reconstruct server_id from Big Endian bytes
     *
     * BE format: [byte0][byte1][byte2][byte3]
     * value = (byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3
     */
    *server_id = ((__u32)cid[0] << 24) |
                 ((__u32)cid[1] << 16) |
                 ((__u32)cid[2] << 8)  |
                 ((__u32)cid[3]);

    return 0;
}

/*
 * Extract server_id from sk_reuseport_md context
 *
 * This function handles the case where ctx->data may point to either:
 * - UDP payload (QUIC data) - most common case
 * - UDP header - happens on some kernel versions
 *
 * @param ctx: sk_reuseport_md context
 * @param server_id: Output pointer for server_id
 *
 * @return: 0 on success, negative on error
 */
static __always_inline int
extract_server_id(struct sk_reuseport_md *ctx, __u32 *server_id)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /*
     * Check if data points to UDP header instead of QUIC payload
     *
     * UDP length フィールド（オフセット 4-5）と ctx->len を比較して判断する。
     * 一致すれば UDP ヘッダーを指しているので、8 バイトスキップする。
     */

    /* Debug: show UDP length field and ctx->len for comparison */
    if (data + 6 <= data_end) {
        __u8 *dbg_bytes = (__u8 *)data;
        __u16 dbg_udp_len = ((__u16)dbg_bytes[4] << 8) | dbg_bytes[5];
        bpf_printk("quicport: UDP len field=%u, ctx->len=%u\n",
                   (unsigned int)dbg_udp_len, ctx->len);
    }

    if (is_udp_header(data, data_end, ctx->len)) {
        /* Skip UDP header (8 bytes) to get to QUIC payload */
        data = data + UDP_HEADER_LEN;

        bpf_printk("quicport: skipping UDP header (8 bytes)\n");

        /* Verify we still have data after skipping */
        if (data + 1 > data_end) {
            return -1;
        }
    } else {
        bpf_printk("quicport: NOT UDP header, treating as QUIC directly\n");
    }

    return extract_server_id_from_quic(data, data_end, server_id);
}

/*
 * Fallback to default active DP (key=0)
 *
 * socket_map の key=0 は「デフォルト ACTIVE DP」として予約されている。
 * server_id の抽出やソケット選択に失敗した場合、key=0 で再ルックアップすることで
 * 新規コネクション（Initial パケット等）を ACTIVE な DP にルーティングする。
 *
 * key=0 にエントリがない場合はカーネルデフォルト（ハッシュベース分散）にフォールスルーする。
 *
 * @param ctx: sk_reuseport_md context
 * @return: SK_PASS
 */
static __always_inline int
fallback_to_default_active(struct sk_reuseport_md *ctx)
{
    __u32 default_key = 0;
    long ret;

    ret = bpf_sk_select_reuseport(ctx, &socket_map, &default_key, 0);
    if (ret < 0) {
        bpf_printk("quicport: no default active DP (key=0), using kernel routing\n");
        return SK_PASS;
    }
    bpf_printk("quicport: routed to default active DP (key=0)\n");
    return SK_PASS;
}

/*
 * SK_REUSEPORT program entry point
 *
 * Called by the kernel when a UDP packet arrives on a SO_REUSEPORT socket group.
 * Selects which socket should receive the packet based on QUIC CID.
 *
 * @param ctx: sk_reuseport_md context with packet data
 *
 * @return: SK_PASS to use selected socket or fallback to kernel default
 *          SK_DROP would drop the packet (we don't use this)
 */
SEC("sk_reuseport")
int quicport_select_socket(struct sk_reuseport_md *ctx)
{
    __u32 server_id;
    long ret;

    /*
     * DEBUG: 無条件でログを出力
     *
     * このログが trace_pipe に出力されない場合、プログラムがソケットに
     * アタッチされていない可能性が高い。
     *
     * 確認方法:
     *   echo 1 | sudo tee /sys/kernel/debug/tracing/events/bpf_trace/bpf_trace_printk/enable
     *   sudo cat /sys/kernel/debug/tracing/trace_pipe | grep quicport
     */
    bpf_printk("quicport: ========== ENTRY ==========\n");
    bpf_printk("quicport: sk_reuseport program invoked, ctx=%p\n", ctx);

    /*
     * DEBUG: Dump first bytes of ctx->data to verify what it points to
     *
     * Expected values:
     * - If UDP payload (QUIC): 0xc0+ (Long Header) or 0x40+ (Short Header)
     * - If IP header: 0x45 (IPv4) or 0x60 (IPv6)
     */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /*
     * DEBUG: ctx の詳細情報を出力
     *
     * sk_reuseport_md の主要フィールド:
     * - len: パケット全体の長さ
     * - eth_protocol: Ethernet プロトコル (ETH_P_IP=0x0800, ETH_P_IPV6=0x86DD)
     * - ip_protocol: IP プロトコル (IPPROTO_UDP=17)
     * - data/data_end: パケットデータへのポインタ
     *
     * 注意: SK_REUSEPORT では ctx->data は **UDP ペイロード** の先頭を指す
     * (IP/UDP ヘッダはスキップ済み)
     */
    bpf_printk("quicport: ctx->len=%u, eth_proto=0x%04x, ip_proto=%u\n",
               ctx->len, ctx->eth_protocol, ctx->ip_protocol);

    if (data + 8 <= data_end) {
        __u8 *bytes = (__u8 *)data;
        /* bpf_trace_printk は最大 3 引数なので分割 */
        bpf_printk("quicport: data[0-2]=%02x %02x %02x\n",
                   bytes[0], bytes[1], bytes[2]);
        bpf_printk("quicport: data[3-5]=%02x %02x %02x\n",
                   bytes[3], bytes[4], bytes[5]);
        /*
         * data[0] の解釈:
         * - 0xc0-0xff: QUIC Long Header (Initial, Handshake, 0-RTT, Retry)
         * - 0x40-0x7f: QUIC Short Header (1-RTT)
         * - 0x45: IPv4 header (もし IP ヘッダが含まれている場合)
         * - 0x60: IPv6 header (もし IP ヘッダが含まれている場合)
         */
        if ((bytes[0] & 0x80) == 0x80) {
            bpf_printk("quicport: detected QUIC Long Header\n");
        } else if ((bytes[0] & 0x40) == 0x40) {
            bpf_printk("quicport: detected QUIC Short Header\n");
        } else if ((bytes[0] >> 4) == 4) {
            bpf_printk("quicport: WARNING: data points to IPv4 header, not UDP payload!\n");
        } else if ((bytes[0] >> 4) == 6) {
            bpf_printk("quicport: WARNING: data points to IPv6 header, not UDP payload!\n");
        } else {
            bpf_printk("quicport: unknown packet format, first_byte=0x%02x\n", bytes[0]);
        }
    } else {
        bpf_printk("quicport: data too short for analysis, data_end-data=%ld\n", (long)(data_end - data));
    }

    /* Extract server_id from QUIC CID */
    if (extract_server_id(ctx, &server_id) < 0) {
        /*
         * Failed to extract server_id - packet might not be QUIC
         * or uses a different CID format (e.g., Initial packet with
         * client-generated random CID).
         *
         * Fallback to default active DP (key=0) to route new connections
         * to the ACTIVE DP instead of relying on kernel hash-based routing
         * which might send to a DRAINING DP.
         */
        bpf_printk("quicport: failed to extract server_id, trying default active DP\n");
        return fallback_to_default_active(ctx);
    }

    bpf_printk("quicport: extracted server_id=%u\n", server_id);

    /*
     * Select socket based on server_id
     *
     * bpf_sk_select_reuseport() looks up the socket in the map
     * and assigns it to handle this packet.
     *
     * If the lookup fails (server_id not registered), we fallback
     * to the default active DP (key=0).
     */
    ret = bpf_sk_select_reuseport(ctx, &socket_map, &server_id, 0);
    if (ret < 0) {
        /*
         * Socket selection failed - server_id not found in map
         *
         * This can happen when:
         * - New connection with CID from a process that has exited
         * - CID was generated before any Data Plane registered
         * - Map was reset/corrupted
         *
         * Fallback to default active DP (key=0).
         */
        bpf_printk("quicport: server_id=%u not found, trying default active DP\n", server_id);
        return fallback_to_default_active(ctx);
    }

    bpf_printk("quicport: routed to server_id=%u\n", server_id);

    return SK_PASS;
}

/*
 * BPF program license
 *
 * This must be GPL-compatible to use certain BPF helpers.
 * The overall project is Apache-2.0 licensed.
 */
BPF_LICENSE("Dual BSD/GPL");
