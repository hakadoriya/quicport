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
 * Extract server_id from packet data
 *
 * This function reads the QUIC header and extracts the server_id
 * (first 4 bytes of Destination Connection ID).
 *
 * @param ctx: sk_reuseport_md context
 * @param server_id: Output pointer for server_id (in native byte order)
 *
 * @return: 0 on success, negative on error
 */
static __always_inline int
extract_server_id(struct sk_reuseport_md *ctx, __u32 *server_id)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
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
     * DEBUG: Dump first bytes of ctx->data to verify what it points to
     *
     * Expected values:
     * - If UDP payload (QUIC): 0xc0+ (Long Header) or 0x40+ (Short Header)
     * - If IP header: 0x45 (IPv4) or 0x60 (IPv6)
     */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 8 <= data_end) {
        __u8 *bytes = (__u8 *)data;
        bpf_printk("quicport: data[0-3]=%02x %02x %02x %02x\n",
                   bytes[0], bytes[1], bytes[2], bytes[3]);
        bpf_printk("quicport: data[4-7]=%02x %02x %02x %02x\n",
                   bytes[4], bytes[5], bytes[6], bytes[7]);
        bpf_printk("quicport: data_len=%u\n", ctx->len);
    } else {
        bpf_printk("quicport: data too short, len=%u\n", ctx->len);
    }

    /* Extract server_id from QUIC CID */
    if (extract_server_id(ctx, &server_id) < 0) {
        /*
         * Failed to extract server_id - packet might not be QUIC
         * or uses a different CID format.
         *
         * Fall through to kernel's default SO_REUSEPORT behavior
         * which typically uses consistent hashing on the 4-tuple.
         */
        bpf_printk("quicport: failed to extract server_id, using default routing\n");
        return SK_PASS;
    }

    bpf_printk("quicport: extracted server_id=%u\n", server_id);

    /*
     * Select socket based on server_id
     *
     * bpf_sk_select_reuseport() looks up the socket in the map
     * and assigns it to handle this packet.
     *
     * If the lookup fails (server_id not registered), the helper
     * returns an error and we fall through to default routing.
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
         * Fall back to kernel default routing.
         */
        bpf_printk("quicport: server_id=%u not found, using default routing\n", server_id);
        return SK_PASS;
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
