/* SPDX-License-Identifier: Apache-2.0 */
/*
 * quicport_reuseport.h - Shared definitions for quicport SK_REUSEPORT
 *
 * This header defines constants and structures shared between
 * the eBPF program and userspace loader.
 */

#ifndef __QUICPORT_REUSEPORT_H__
#define __QUICPORT_REUSEPORT_H__

/*
 * Maximum number of server_id values that can be registered in socket_map
 *
 * REUSEPORT_SOCKARRAY requires keys to be in the range [0, max_entries-1].
 * We use 65536 (16-bit range) to provide sufficient randomization space
 * for server_id collision avoidance during graceful restart.
 *
 * Memory impact: REUSEPORT_SOCKARRAY is sparse, so actual memory usage
 * is proportional to the number of registered entries (typically 1-3),
 * not the max_entries value.
 */
#define MAX_SOCKETS 65536

/*
 * QUIC Connection ID (CID) Configuration
 *
 * quicport uses a custom 8-byte CID format:
 *
 *   +------------------+------------------+
 *   | server_id (4B)   | counter (4B)     |
 *   | Big Endian       | Big Endian       |
 *   +------------------+------------------+
 *    0                4                  8
 *
 * The server_id is assigned by Control Plane when a Data Plane starts.
 * It uniquely identifies which process should handle connections with
 * CIDs containing that server_id.
 */
#define QUICPORT_CID_LEN         8
#define QUICPORT_SERVER_ID_OFFSET 0
#define QUICPORT_SERVER_ID_LEN   4

/*
 * QUIC Packet Header Offsets
 *
 * QUIC Short Header (1-RTT, most common after handshake):
 *   +--------+------------------+------------------+
 *   | Flags  | Dest CID (8B)    | Packet Number... |
 *   | 1 byte | server_id | ctr  |                  |
 *   +--------+------------------+------------------+
 *    0        1                9
 *
 * QUIC Long Header (Initial, Handshake, 0-RTT):
 *   +--------+----------+----------+------------------+
 *   | Flags  | Version  | DCID Len | Dest CID (8B)    | ...
 *   | 1 byte | 4 bytes  | 1 byte   | server_id | ctr  |
 *   +--------+----------+----------+------------------+
 *    0        1          5          6               14
 *
 * Header type detection:
 *   - (flags & 0x80) == 0  -> Short Header
 *   - (flags & 0x80) != 0  -> Long Header
 */
#define QUIC_FLAGS_LONG_HEADER_MASK  0x80
#define QUIC_FLAGS_FIXED_BIT         0x40

/* Short Header: CID starts at offset 1 */
#define QUIC_SHORT_HEADER_CID_OFFSET 1

/* Long Header: DCID Length is at offset 5, DCID starts at offset 6 */
#define QUIC_LONG_HEADER_DCID_LEN_OFFSET 5
#define QUIC_LONG_HEADER_DCID_OFFSET     6

/*
 * Minimum packet sizes for QUIC packets
 *
 * We need at least enough bytes to read the CID to perform routing.
 */
#define QUIC_MIN_SHORT_HEADER_LEN  (1 + QUICPORT_CID_LEN)  /* 9 bytes */
#define QUIC_MIN_LONG_HEADER_LEN   (6 + QUICPORT_CID_LEN)  /* 14 bytes */

/*
 * UDP Header size
 *
 * SK_REUSEPORT の ctx->data は UDP ヘッダーを指している場合がある。
 * その場合、QUIC データにアクセスするには UDP ヘッダーをスキップする必要がある。
 *
 * UDP Header format:
 *   +------------------+------------------+
 *   | Source Port (2B) | Dest Port (2B)   |
 *   +------------------+------------------+
 *   | Length (2B)      | Checksum (2B)    |
 *   +------------------+------------------+
 *    0                 2                 4                 6                 8
 */
#define UDP_HEADER_LEN 8

#endif /* __QUICPORT_REUSEPORT_H__ */
