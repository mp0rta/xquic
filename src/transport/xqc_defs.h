/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_DEFS_H
#define XQC_DEFS_H

#include <stdint.h>
#include <xquic/xquic.h>

#define XQC_MAX_PACKET_LEN 1500

/* default connection timeout(millisecond) */
#define XQC_CONN_DEFAULT_IDLE_TIMEOUT 120000
/* default connection initial timeout(millisecond) */
#define XQC_CONN_INITIAL_IDLE_TIMEOUT 10000


#define XQC_CONN_ADDR_VALIDATION_CID_ENTROPY 8

/* connection PTO packet count */
#define XQC_CONN_PTO_PKT_CNT_MAX 2

/* connection max UDP payload size */
#define XQC_CONN_MAX_UDP_PAYLOAD_SIZE 1500

/* connection active cid limit */
#define XQC_CONN_ACTIVE_CID_LIMIT 8

/* version definitions */
#define XQC_VERSION_V1_VALUE    0x00000001
#define XQC_IDRAFT_VER_29_VALUE 0xFF00001D

#define XQC_PROTO_VERSION_LEN 4

/* the value of max_streams transport parameter or MAX_STREAMS frame must <= 2^60 */
#define XQC_MAX_STREAMS ((uint64_t)1 << 60)

#define XQC_CONN_MAX_CRYPTO_DATA_TOTAL_LEN (10 * 1024 * 1024)

/*
 * CWE-770 mitigation: limit buffered out-of-order CRYPTO frame resources.
 * These caps prevent unbounded memory allocation from sparse CRYPTO fragments
 * that keep next_read_offset pinned (RFC 9001 §5.2 attack surface).
 */
#define XQC_MAX_CRYPTO_FRAME_BUFFERED_COUNT     1024    /* max buffered frame nodes per crypto stream */
#define XQC_MAX_CRYPTO_FRAME_BUFFERED_BYTES     (1*1024*1024)  /* max buffered data bytes per crypto stream (1MB), accommodates large cert chains under reordering */

/*
 * CWE-770 mitigation for buffered STREAM frame nodes (RFC 9000 §21.7).
 *
 * 8192 remains the sparse-fragment threshold: beyond it, a stream must carry
 * enough payload per node to avoid metadata amplification.  A separate hard
 * ceiling still bounds dense packet-sized nodes.  The hard ceiling covers a
 * full 16 MiB receive window even when ordinary QUIC/H3 framing leaves less
 * than one MSS of application payload in each packet.
 *
 * The receive window bounds the hard ceiling only while the buffered ranges
 * are disjoint.  The density budget charges each node its own data_length,
 * but stream flow control charges the highest offset reached, so a peer that
 * resends one range at one-byte offset steps pays the density tier in full
 * with almost no flow-control credit: measured, 1 KB frames stepped by one
 * byte reach the hard ceiling holding ~32 MB behind an unfilled hole for
 * ~33 KB of stream offset.  That is a memory ceiling, not an amplifier --
 * the sender still puts every held byte on the wire -- and the previous flat
 * 8192-node cap had the same shape at ~8 MB.  Raising the ceiling raises that
 * worst case with it; it does not open a path the old cap closed.
 */
#define XQC_MAX_STREAM_FRAME_BUFFERED_COUNT          8192
#define XQC_MAX_STREAM_FRAME_BUFFERED_COUNT_HARD     32768
#define XQC_MIN_STREAM_BUFFERED_BYTES_PER_FRAME      256


/* xquic will not send stateless reset to packets which are smaller than
   XQC_STATELESS_RESET_PKT_MIN_LEN */
#define XQC_STATELESS_RESET_PKT_MIN_LEN 21
#define XQC_STATELESS_RESET_PKT_MAX_LEN 43

/* xquic will  */
#define XQC_STATELESS_RESET_PKT_SUBTRAHEND 2

/* max token length supported by xquic */
#define XQC_MAX_TOKEN_LEN 256
#define XQC_TOKEN_IV_LEN  12
#define XQC_TOKEN_TAG_LEN 16
/* EVP_aes_128_gcm secret len */
#define XQC_TOKEN_SECRET_LEN 16

/* length of retry integrity tag */
#define XQC_RETRY_INTEGRITY_TAG_LEN 16


extern const uint32_t xqc_proto_version_value[];
extern const unsigned char xqc_proto_version_field[][XQC_PROTO_VERSION_LEN];


#define xqc_check_proto_version_valid(ver) \
    ((ver) > XQC_IDRAFT_INIT_VER && (ver) < XQC_IDRAFT_VER_NEGOTIATION)


/* max alpn length */
#define XQC_MAX_ALPN_LEN 255

/* limit of anti-amplification (RFC 9000 Section 8.1) */
#define XQC_DEFAULT_ANTI_AMPLIFICATION_LIMIT    3

#define XQC_MAX_MT_ROW 256

#define XQC_RSM_COL 48
#endif
