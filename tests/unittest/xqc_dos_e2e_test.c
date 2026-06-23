/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 * @copyright Copyright (c) 2026, mp0rta
 */

/*
 * Integration ("engine path") tests for the #811 DoS mitigations.
 *
 * Unlike xqc_crypto_frame_test.c (which calls xqc_insert_crypto_frame directly),
 * these drive a flood through the real receive/dispatch path
 * (xqc_process_crypto_frame -> parse -> insert) and assert that the connection
 * enforces the limit (CONN_ERR + error return) and survives (no crash / no
 * unbounded buffering).
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include "xqc_dos_e2e_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_defs.h"

/* Encode a QUIC varint that fits in 2 bytes (14-bit, values 0..16383). */
static size_t
xqc_test_put_varint2(unsigned char *p, uint64_t v)
{
    p[0] = 0x40 | (unsigned char)((v >> 8) & 0x3f);
    p[1] = (unsigned char)(v & 0xff);
    return 2;
}

/*
 * Build one CRYPTO frame on the wire: type(0x06) + offset(2B varint) +
 * length(1B varint=1) + 1 data byte. Returns total length written.
 */
static size_t
xqc_test_build_crypto_frame(unsigned char *buf, uint64_t offset)
{
    size_t off = 0;
    buf[off++] = 0x06; /* CRYPTO frame type */
    off += xqc_test_put_varint2(buf + off, offset);
    buf[off++] = 0x01;                           /* length = 1 (1-byte varint) */
    buf[off++] = (unsigned char)(offset & 0xff); /* 1 byte of crypto data */
    return off;
}

/*
 * #811 CWE-770: a peer that floods sparse CRYPTO frames (gaps that never fill)
 * forces unbounded reassembly buffering. Drive that flood through the real
 * frame receive path and assert the node-count cap fires.
 */
void
xqc_test_dos_crypto_frame_flood_recv_path(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    uint64_t accepted = 0;
    xqc_int_t last_ret = XQC_OK;

    /*
     * Offsets start at 64 and step by 2, so offset 0..63 is never filled:
     * next_read_offset stays pinned at 0 and every frame is buffered. Feed one
     * more than the cap to trip rejection.
     */
    for (uint64_t i = 0; i < XQC_MAX_CRYPTO_FRAME_BUFFERED_COUNT + 50; i++) {
        uint64_t offset = 64 + i * 2;

        unsigned char wire[8];
        size_t wire_len = xqc_test_build_crypto_frame(wire, offset);

        xqc_packet_in_t pi;
        memset(&pi, 0, sizeof(pi));
        pi.pos = wire;
        pi.last = wire + wire_len;
        pi.pi_pkt.pkt_type = XQC_PTYPE_INIT; /* -> XQC_ENC_LEV_INIT crypto stream */

        last_ret = xqc_process_crypto_frame(conn, &pi);
        if (last_ret != XQC_OK) {
            break;
        }
        accepted++;
    }

    /* The cap must have fired: exactly COUNT frames accepted, then rejection. */
    CU_ASSERT(accepted == XQC_MAX_CRYPTO_FRAME_BUFFERED_COUNT);
    CU_ASSERT(last_ret == -XQC_ELIMIT);
    CU_ASSERT(conn->conn_err == TRA_CRYPTO_BUFFER_EXCEEDED);

    /* Buffering is bounded (did not grow past the cap). */
    xqc_stream_t *cs = conn->crypto_stream[XQC_ENC_LEV_INIT];
    CU_ASSERT_FATAL(cs != NULL);
    CU_ASSERT(cs->stream_data_in.buffered_frame_count ==
              XQC_MAX_CRYPTO_FRAME_BUFFERED_COUNT);

    /* Connection survived the flood (still usable / destroyable). */
    xqc_engine_destroy(conn->engine);
}
