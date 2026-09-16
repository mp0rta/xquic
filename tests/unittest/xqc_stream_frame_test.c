/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_stream_frame_test.h"
#include <CUnit/CUnit.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_defs.h"
#include "src/transport/xqc_packet_in.h"
#include <xquic/xqc_errno.h>
#include "xqc_common_test.h"

void
xqc_test_stream_frame()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT(stream != NULL);

    char payload[100];
    xqc_stream_frame_t *frame[10];
    memset(frame, 0, sizeof(frame));

    for (int i = 0; i < 10; i++) {
        frame[i] = xqc_malloc(sizeof(xqc_stream_frame_t));
        memset(frame[i], 0, sizeof(*frame[i]));
        frame[i]->data_length = 10;
        frame[i]->data_offset = i * 10;
        memset(payload + i * 10, i, 10);
        frame[i]->data = xqc_malloc(10);
        memcpy(frame[i]->data, payload + i * 10, 10);
    }

    ret = xqc_insert_stream_frame(conn, stream, frame[1]);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 0);

    ret = xqc_insert_stream_frame(conn, stream, frame[2]);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 0);

    ret = xqc_insert_stream_frame(conn, stream, frame[0]);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 30);

    ret = xqc_insert_stream_frame(conn, stream, frame[3]);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 40);

    xqc_list_head_t *pos;
    xqc_stream_frame_t *pframe;
    uint64_t offset = 0;
    xqc_list_for_each(pos, &stream->stream_data_in.frames_tailq) {
        pframe = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);
        CU_ASSERT(pframe->data_offset == offset);
        offset += 10;
    }

    char recv_buf[16];
    unsigned recv_buf_size = 16;
    unsigned char fin;
    offset = 0;
    do {
        ret = xqc_stream_recv(stream, recv_buf, recv_buf_size, &fin);
        CU_ASSERT(ret >= 0 || ret == -XQC_EAGAIN);
        if (ret > 0) {
            CU_ASSERT(memcmp(payload + offset, recv_buf, ret) == 0);
        }
        offset += ret;
    } while (ret > 0);

    for (int i = 4; i < 10; i++) {
        xqc_destroy_stream_frame(frame[i]);
    }

    xqc_engine_destroy(conn->engine);
}


static xqc_stream_frame_t *
test_mk_frame(uint64_t offset, unsigned length)
{
    xqc_stream_frame_t *f = xqc_calloc(1, sizeof(xqc_stream_frame_t));
    f->data_offset = offset;
    f->data_length = length;
    f->data = xqc_malloc(length);
    memset(f->data, 'x', length);
    return f;
}

/**
 * Test buffered_frame_count limit (CWE-770 mitigation for stream fragmentation attack)
 */
void
xqc_test_stream_frame_buffered_limit()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }

    /* Each attempt uses its own allocation; a frame is freed here only when
     * the insert did NOT take ownership (any non-OK return), so an
     * unexpected accept cannot corrupt the list. */

    /* Simulate count at limit: should reject */
    xqc_stream_frame_t *fa = test_mk_frame(99999, 1);
    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT;
    ret = xqc_insert_stream_frame(conn, stream, fa);
    CU_ASSERT(ret == -XQC_ELIMIT);
    if (ret != XQC_OK) { xqc_free(fa->data); xqc_free(fa); }

    /* Beyond-hole frames stop at (limit - 1): the last slot is reserved for
     * a prefix-extending frame (liveness carve-out), so limit - 1 rejects too */
    xqc_stream_frame_t *fb = test_mk_frame(99999, 1);
    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT - 1;
    ret = xqc_insert_stream_frame(conn, stream, fb);
    CU_ASSERT(ret == -XQC_ELIMIT);
    if (ret != XQC_OK) { xqc_free(fb->data); xqc_free(fb); }

    /* Simulate count at limit - 2: should accept (count -> limit - 1) */
    xqc_stream_frame_t *fc = test_mk_frame(99999, 1);
    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT - 2;
    ret = xqc_insert_stream_frame(conn, stream, fc);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == XQC_MAX_STREAM_FRAME_BUFFERED_COUNT - 1);
    if (ret != XQC_OK) { xqc_free(fc->data); xqc_free(fc); }

    /* Next beyond-hole insert should be rejected (count == limit - 1 now) */
    xqc_stream_frame_t *fd = test_mk_frame(199999, 1);
    ret = xqc_insert_stream_frame(conn, stream, fd);
    CU_ASSERT(ret == -XQC_ELIMIT);
    if (ret != XQC_OK) { xqc_free(fd->data); xqc_free(fd); }

    xqc_engine_destroy(conn->engine);
}


/* Build a minimal 1-frame packet_in and run it through
 * xqc_process_stream_frame. buf must hold exactly one wire-encoded STREAM
 * frame. */
static xqc_int_t
test_process_stream_bytes(xqc_connection_t *conn, const unsigned char *buf,
                          size_t len, xqc_pkt_type_t pkt_type)
{
    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.buf = buf;
    packet_in.buf_size = len;
    packet_in.pos = (unsigned char *)buf;
    packet_in.last = (unsigned char *)buf + len;
    packet_in.pi_pkt.pkt_type = pkt_type;
    return xqc_process_stream_frame(conn, &packet_in);
}

static xqc_stream_t *
test_stream_with_fc(xqc_connection_t *conn, uint64_t stream_fc, uint64_t conn_fc)
{
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    if (stream == NULL) {
        return NULL;
    }
    stream->stream_flow_ctl.fc_max_stream_data_can_recv = stream_fc;
    conn->conn_flow_ctl.fc_max_data_can_recv = conn_fc;
    return stream;
}

/**
 * At the cap, a frame that extends the contiguous prefix (fills the leftmost
 * hole) must still be admitted into the reserved slot — rejecting it would
 * make the hole unfillable and livelock the stream — while the total node
 * count stays hard-bounded at the cap.
 */
void
xqc_test_stream_frame_cap_liveness()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }

    /* one real beyond-hole frame at [20,30) so the list is non-empty.
     * Ownership rule throughout: free a frame here only when the insert
     * did NOT take it (non-OK return), so an unexpected accept under old
     * semantics degrades to an assert failure, not list corruption. */
    xqc_stream_frame_t *seed = test_mk_frame(20, 10);
    ret = xqc_insert_stream_frame(conn, stream, seed);
    CU_ASSERT(ret == XQC_OK);
    if (ret != XQC_OK) { xqc_free(seed->data); xqc_free(seed); }

    /* simulate a buffer full of beyond-hole frames */
    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT - 1;

    /* beyond-hole frame: rejected (reserved slot must not be consumed) */
    xqc_stream_frame_t *bh = test_mk_frame(100, 10);
    ret = xqc_insert_stream_frame(conn, stream, bh);
    CU_ASSERT(ret == -XQC_ELIMIT);
    if (ret != XQC_OK) { xqc_free(bh->data); xqc_free(bh); }

    /* prefix-extending frame [0,10): admitted into the reserved slot */
    xqc_stream_frame_t *pf = test_mk_frame(0, 10);
    ret = xqc_insert_stream_frame(conn, stream, pf);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 10);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count
              == XQC_MAX_STREAM_FRAME_BUFFERED_COUNT);
    if (ret != XQC_OK) { xqc_free(pf->data); xqc_free(pf); }

    /* at the hard bound even a prefix-extender is rejected (wait for drain) */
    xqc_stream_frame_t *pf2 = test_mk_frame(10, 5);
    ret = xqc_insert_stream_frame(conn, stream, pf2);
    CU_ASSERT(ret == -XQC_ELIMIT);
    if (ret != XQC_OK) { xqc_free(pf2->data); xqc_free(pf2); }

    /* after the app drains one node, prefix admission resumes */
    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT - 1;
    xqc_stream_frame_t *pf3 = test_mk_frame(10, 5);
    ret = xqc_insert_stream_frame(conn, stream, pf3);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 15);
    if (ret != XQC_OK) { xqc_free(pf3->data); xqc_free(pf3); }

    xqc_engine_destroy(conn->engine);
}

/**
 * Retransmitted FIN-only frames for an already-determined stream must not
 * accumulate zero-length frame nodes (they consume no flow-control credit,
 * so unbounded accumulation would be a resource-exhaustion vector).
 */
void
xqc_test_stream_frame_fin_only_no_accumulation()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = test_stream_with_fc(conn, 1 << 20, 1 << 20);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }
    CU_ASSERT(stream->stream_id < 64); /* 1-byte varint below */

    /* STREAM frame, LEN|FIN, no OFF: offset 0, length 0, fin */
    unsigned char fin_only[3] = { 0x0b, (unsigned char)stream->stream_id, 0x00 };

    for (int i = 0; i < 5; i++) {
        ret = test_process_stream_bytes(conn, fin_only, sizeof(fin_only),
                                        XQC_PTYPE_SHORT_HEADER);
        CU_ASSERT(ret == XQC_OK);
    }

    CU_ASSERT(stream->stream_data_in.stream_determined == XQC_TRUE);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count <= 1);

    xqc_engine_destroy(conn->engine);
}

/**
 * A beyond-hole STREAM frame rejected by the reassembly cap must surface as
 * a tolerant whole-packet drop (-XQC_EIGNORE_PKT, packet never acked) for
 * short-header packets — not as a connection error. Long-header (0-RTT)
 * packets keep the generic error path because the tolerant handling would
 * skip coalesced follow-up packets (RFC 9000 §12.2).
 */
void
xqc_test_stream_frame_cap_tolerant_drop()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = test_stream_with_fc(conn, 1 << 20, 1 << 20);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }
    CU_ASSERT(stream->stream_id < 64);

    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT;

    /* STREAM frame, OFF|LEN: offset 200 (beyond hole), length 10 */
    unsigned char beyond[15] = { 0x0e, (unsigned char)stream->stream_id,
                                 0x40, 0xc8, 0x0a,
                                 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x' };

    ret = test_process_stream_bytes(conn, beyond, sizeof(beyond),
                                    XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == -XQC_EIGNORE_PKT);
    CU_ASSERT(conn->conn_err == 0);

    ret = test_process_stream_bytes(conn, beyond, sizeof(beyond),
                                    XQC_PTYPE_0RTT);
    CU_ASSERT(ret == -XQC_ELIMIT);
    CU_ASSERT(conn->conn_err == 0);

    xqc_engine_destroy(conn->engine);
}

/**
 * Mandatory flow-control validation must run before the resource-pressure
 * rejection: a frame past the advertised limit is a FLOW_CONTROL_ERROR
 * connection error even while the reassembly buffer is at the cap, and must
 * not be masked by the tolerant packet drop.
 */
void
xqc_test_stream_frame_fc_before_cap()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = test_stream_with_fc(conn, 100, 1 << 20);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }
    CU_ASSERT(stream->stream_id < 64);

    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT;

    /* STREAM frame, OFF|LEN: offset 96, length 10 -> final 106 > limit 100 */
    unsigned char violating[15] = { 0x0e, (unsigned char)stream->stream_id,
                                    0x40, 0x60, 0x0a,
                                    'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x' };

    ret = test_process_stream_bytes(conn, violating, sizeof(violating),
                                    XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_FLOW_CONTROL_ERROR);

    /* connection-level flow control must be enforced the same way: reset the
     * sticky conn error, open the stream limit, shrink the conn limit */
    conn->conn_err = 0;
    stream->stream_flow_ctl.fc_max_stream_data_can_recv = 1 << 20;
    conn->conn_flow_ctl.fc_max_data_can_recv = 100;

    ret = test_process_stream_bytes(conn, violating, sizeof(violating),
                                    XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == -XQC_EPROTO);
    CU_ASSERT(conn->conn_err == TRA_FLOW_CONTROL_ERROR);

    xqc_engine_destroy(conn->engine);
}

/**
 * A FIN whose frame node is rejected by the reassembly cap still records the
 * final size (stream_determined/SIZE_KNOWN) before admission. The rejected
 * packet is unacked, so the peer retransmits the FIN; that retransmission is
 * swallowed by the already-recvd duplicate path — which must then perform
 * the missed SIZE_KNOWN -> DATA_RECVD completion and wake the reader, or the
 * stream stalls forever with the connection alive.
 */
void
xqc_test_stream_frame_fin_rejected_then_retransmitted()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = test_stream_with_fc(conn, 1 << 20, 1 << 20);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }
    CU_ASSERT(stream->stream_id < 64);

    /* deliver [0,10) so merged_offset_end == 10 (STREAM, LEN only) */
    unsigned char data10[13] = { 0x0a, (unsigned char)stream->stream_id, 0x0a,
                                 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd' };
    ret = test_process_stream_bytes(conn, data10, sizeof(data10),
                                    XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.merged_offset_end == 10);

    /* FIN-only frame [10,10) arriving while the buffer is at the cap:
     * node rejected (zero-length never extends the prefix), but the final
     * size was already recorded (STREAM, OFF|LEN|FIN) */
    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT;
    unsigned char fin_at_10[4] = { 0x0f, (unsigned char)stream->stream_id, 0x0a, 0x00 };
    ret = test_process_stream_bytes(conn, fin_at_10, sizeof(fin_at_10),
                                    XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == -XQC_EIGNORE_PKT);
    CU_ASSERT(stream->stream_data_in.stream_determined == XQC_TRUE);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_SIZE_KNOWN);

    /* cap pressure gone; the peer retransmits the FIN (unacked packet).
     * The duplicate path must repair the completion state. */
    stream->stream_data_in.buffered_frame_count = 1;
    ret = test_process_stream_bytes(conn, fin_at_10, sizeof(fin_at_10),
                                    XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_DATA_RECVD);

    /* and the reader actually observes fin */
    char buf[64];
    unsigned char fin = 0;
    ret = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
    CU_ASSERT(ret == 10);
    CU_ASSERT(fin == 1);

    xqc_engine_destroy(conn->engine);
}

/**
 * Reserved-slot liveness with real frame nodes end to end: fill the buffer
 * with beyond-hole frames up to (cap - 1), verify rejection, admit the
 * hole-filling frame through the reserved slot, drain via xqc_stream_recv,
 * and verify admission resumes after the drain.
 */
void
xqc_test_stream_frame_cap_liveness_real()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }

    /* hole at [0,10); contiguous beyond-hole frames from offset 10 */
    uint64_t i;
    for (i = 0; i + 1 < XQC_MAX_STREAM_FRAME_BUFFERED_COUNT; i++) {
        xqc_stream_frame_t *f = test_mk_frame(10 + i * 10, 10);
        ret = xqc_insert_stream_frame(conn, stream, f);
        if (ret != XQC_OK) {
            xqc_free(f->data);
            xqc_free(f);
            break;
        }
    }
    CU_ASSERT(stream->stream_data_in.buffered_frame_count
              == XQC_MAX_STREAM_FRAME_BUFFERED_COUNT - 1);

    /* beyond-hole insert now rejected */
    xqc_stream_frame_t *bh = test_mk_frame(10 + i * 10, 10);
    ret = xqc_insert_stream_frame(conn, stream, bh);
    CU_ASSERT(ret == -XQC_ELIMIT);
    if (ret != XQC_OK) { xqc_free(bh->data); xqc_free(bh); }

    /* hole filler admitted through the reserved slot; merge cascades */
    xqc_stream_frame_t *pf = test_mk_frame(0, 10);
    ret = xqc_insert_stream_frame(conn, stream, pf);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count
              == XQC_MAX_STREAM_FRAME_BUFFERED_COUNT);
    CU_ASSERT(stream->stream_data_in.merged_offset_end
              == 10 * (uint64_t)XQC_MAX_STREAM_FRAME_BUFFERED_COUNT);
    if (ret != XQC_OK) { xqc_free(pf->data); xqc_free(pf); }

    /* application drain frees the nodes */
    char buf[4096];
    unsigned char fin = 0;
    do {
        ret = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
    } while (ret > 0);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == 0);

    /* admission resumes */
    xqc_stream_frame_t *nf =
        test_mk_frame(10 * (uint64_t)XQC_MAX_STREAM_FRAME_BUFFERED_COUNT + 10, 10);
    ret = xqc_insert_stream_frame(conn, stream, nf);
    CU_ASSERT(ret == XQC_OK);
    if (ret != XQC_OK) { xqc_free(nf->data); xqc_free(nf); }

    xqc_engine_destroy(conn->engine);
}

/**
 * The duplicate-path completion repair must never reactivate a DISCARDED
 * stream: stream_create_notify failed, so no user context exists and
 * stream_read_notify must not fire. A retransmitted FIN on a discarded
 * stream stays inert.
 */
void
xqc_test_stream_frame_fin_repair_skips_discarded()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = test_stream_with_fc(conn, 1 << 20, 1 << 20);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }
    CU_ASSERT(stream->stream_id < 64);

    stream->stream_flag |= XQC_STREAM_FLAG_DISCARDED;

    /* first FIN-only [0,0): records SIZE_KNOWN, then hits the discard path */
    unsigned char fin_only[3] = { 0x0b, (unsigned char)stream->stream_id, 0x00 };
    ret = test_process_stream_bytes(conn, fin_only, sizeof(fin_only),
                                    XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.stream_determined == XQC_TRUE);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_SIZE_KNOWN);
    stream->stream_flag &= ~XQC_STREAM_FLAG_READY_TO_READ;

    /* retransmitted FIN: swallowed as duplicate, must NOT repair a
     * discarded stream nor queue it for reading */
    ret = test_process_stream_bytes(conn, fin_only, sizeof(fin_only),
                                    XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_SIZE_KNOWN);
    CU_ASSERT(!(stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ));

    xqc_engine_destroy(conn->engine);
}

/**
 * conn_settings.max_stream_frame_buffered_cnt overrides the built-in cap
 * (0 keeps the default); reserved-slot arithmetic follows the override.
 */
void
xqc_test_stream_frame_cap_setting()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) return;

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) { xqc_engine_destroy(conn->engine); return; }

    conn->conn_settings.max_stream_frame_buffered_cnt = 16;

    /* beyond-hole stops at cap-1 = 15 */
    xqc_stream_frame_t *fa = test_mk_frame(1000, 1);
    stream->stream_data_in.buffered_frame_count = 15;
    ret = xqc_insert_stream_frame(conn, stream, fa);
    CU_ASSERT(ret == -XQC_ELIMIT);
    if (ret != XQC_OK) { xqc_free(fa->data); xqc_free(fa); }

    xqc_stream_frame_t *fb = test_mk_frame(1000, 1);
    stream->stream_data_in.buffered_frame_count = 14;
    ret = xqc_insert_stream_frame(conn, stream, fb);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == 15);
    if (ret != XQC_OK) { xqc_free(fb->data); xqc_free(fb); }

    /* prefix-extender may use the reserved slot up to the override cap */
    xqc_stream_frame_t *pf = test_mk_frame(0, 10);
    ret = xqc_insert_stream_frame(conn, stream, pf);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == 16);
    if (ret != XQC_OK) { xqc_free(pf->data); xqc_free(pf); }

    xqc_stream_frame_t *pf2 = test_mk_frame(10, 5);
    ret = xqc_insert_stream_frame(conn, stream, pf2);
    CU_ASSERT(ret == -XQC_ELIMIT);
    if (ret != XQC_OK) { xqc_free(pf2->data); xqc_free(pf2); }

    xqc_engine_destroy(conn->engine);
}

/**
 * A full-size receive window can legitimately contain more than 8192 packet-sized
 * STREAM frames while the application is backpressured or a multipath gap is being
 * repaired.  The sparse-fragment guard must keep rejecting tiny-frame amplification,
 * but it must not close a healthy connection whose buffered nodes carry substantial
 * payload.
 */
void
xqc_test_stream_frame_dense_buffer_budget()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);

    stream->stream_data_in.buffered_frame_count = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT;
    stream->stream_data_in.buffered_data_bytes =
        XQC_MAX_STREAM_FRAME_BUFFERED_COUNT * 1024;

    xqc_stream_frame_t *frame = xqc_calloc(1, sizeof(*frame));
    CU_ASSERT_PTR_NOT_NULL_FATAL(frame);
    frame->data_length = 1024;
    frame->data_offset = stream->stream_data_in.buffered_data_bytes + 4096;
    frame->data = xqc_malloc(frame->data_length);
    CU_ASSERT_PTR_NOT_NULL_FATAL(frame->data);

    CU_ASSERT_EQUAL(xqc_insert_stream_frame(conn, stream, frame), XQC_OK);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_data_bytes,
                    (XQC_MAX_STREAM_FRAME_BUFFERED_COUNT + 1) * 1024);

    xqc_stream_frame_t *hard_frame = xqc_calloc(1, sizeof(*hard_frame));
    CU_ASSERT_PTR_NOT_NULL_FATAL(hard_frame);
    hard_frame->data_length = 1024;
    hard_frame->data_offset = frame->data_offset + frame->data_length + 4096;
    hard_frame->data = xqc_malloc(hard_frame->data_length);
    CU_ASSERT_PTR_NOT_NULL_FATAL(hard_frame->data);

    stream->stream_data_in.buffered_frame_count =
        XQC_MAX_STREAM_FRAME_BUFFERED_COUNT_HARD;
    stream->stream_data_in.buffered_data_bytes =
        XQC_MAX_STREAM_FRAME_BUFFERED_COUNT_HARD * 1024;
    CU_ASSERT_EQUAL(xqc_insert_stream_frame(conn, stream, hard_frame), -XQC_ELIMIT);
    xqc_destroy_stream_frame(hard_frame);

    xqc_engine_destroy(conn->engine);
}

/**
 * The reserved prefix slot has to survive the sparse-density tier as well as
 * the node-count tier. A stream at the sparse threshold with exactly the
 * minimum density would otherwise reject the one small frame that fills the
 * leftmost hole, because charging the density budget at the real post-insert
 * count makes that node drop the average below the minimum. Nothing about
 * the stream changes on rejection, so the retransmission is refused forever
 * and the stream livelocks.
 *
 * The exemption is reusable but not farmable, and this pins why: admission
 * under the density tier requires B + L >= C*m, so after insertion
 * B' >= (C'-1)*m always holds. The average may sit one reserved node below
 * the minimum and no lower, however many prefix frames arrive, and the
 * application never has to drain for that bound to hold (reclamation happens
 * in xqc_stream_recv, not here).
 */
void
xqc_test_stream_frame_dense_prefix_liveness()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);

    const uint64_t m = XQC_MIN_STREAM_BUFFERED_BYTES_PER_FRAME;
    const uint64_t c0 = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT;

    stream->stream_data_in.merged_offset_end = 0;
    stream->stream_data_in.buffered_frame_count = c0;
    stream->stream_data_in.buffered_data_bytes = c0 * m;

    /* Beyond-hole first, so the state it sees is the pristine one and no
     * accepted node is left in the list behind a reset counter. */
    xqc_stream_frame_t *beyond = xqc_calloc(1, sizeof(*beyond));
    CU_ASSERT_PTR_NOT_NULL_FATAL(beyond);
    beyond->data_offset = 1ULL << 20;
    beyond->data_length = 1;
    beyond->data = xqc_malloc(beyond->data_length);
    CU_ASSERT_PTR_NOT_NULL_FATAL(beyond->data);
    CU_ASSERT_EQUAL(xqc_insert_stream_frame(conn, stream, beyond), -XQC_ELIMIT);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_frame_count, c0);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_data_bytes, c0 * m);
    xqc_destroy_stream_frame(beyond);

    /* The prefix-extender takes the reserved node. */
    xqc_stream_frame_t *prefix = xqc_calloc(1, sizeof(*prefix));
    CU_ASSERT_PTR_NOT_NULL_FATAL(prefix);
    prefix->data_offset = 0;
    prefix->data_length = 1;
    prefix->data = xqc_malloc(prefix->data_length);
    CU_ASSERT_PTR_NOT_NULL_FATAL(prefix->data);
    CU_ASSERT_EQUAL(xqc_insert_stream_frame(conn, stream, prefix), XQC_OK);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_frame_count, c0 + 1);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_data_bytes, c0 * m + 1);
    CU_ASSERT_EQUAL(stream->stream_data_in.merged_offset_end, 1);

    /* Reusing it immediately, with no drain, buys nothing: the credit is
     * spent and a second one-byte prefix cannot pay for its own node. */
    xqc_stream_frame_t *again = xqc_calloc(1, sizeof(*again));
    CU_ASSERT_PTR_NOT_NULL_FATAL(again);
    again->data_offset = 1;
    again->data_length = 1;
    again->data = xqc_malloc(again->data_length);
    CU_ASSERT_PTR_NOT_NULL_FATAL(again->data);
    CU_ASSERT_EQUAL(xqc_insert_stream_frame(conn, stream, again), -XQC_ELIMIT);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_frame_count, c0 + 1);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_data_bytes, c0 * m + 1);
    xqc_destroy_stream_frame(again);

    /* One that does pay for its node is admitted, and the invariant holds. */
    xqc_stream_frame_t *paid = xqc_calloc(1, sizeof(*paid));
    CU_ASSERT_PTR_NOT_NULL_FATAL(paid);
    paid->data_offset = 1;
    paid->data_length = (unsigned)(m - 1);
    paid->data = xqc_malloc(paid->data_length);
    CU_ASSERT_PTR_NOT_NULL_FATAL(paid->data);
    CU_ASSERT_EQUAL(xqc_insert_stream_frame(conn, stream, paid), XQC_OK);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_frame_count, c0 + 2);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_data_bytes, (c0 + 1) * m);
    CU_ASSERT_TRUE(stream->stream_data_in.buffered_data_bytes
                   >= (stream->stream_data_in.buffered_frame_count - 1) * m);

    xqc_engine_destroy(conn->engine);
}

/**
 * The reserved node is exempt from density, never from the hard ceiling: a
 * prefix-extender may reach exactly the hard cap and no frame may pass it.
 */
void
xqc_test_stream_frame_prefix_respects_hard_cap()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);

    const uint64_t m = XQC_MIN_STREAM_BUFFERED_BYTES_PER_FRAME;
    const uint64_t hard = XQC_MAX_STREAM_FRAME_BUFFERED_COUNT_HARD;

    stream->stream_data_in.merged_offset_end = 0;
    stream->stream_data_in.buffered_frame_count = hard - 1;
    stream->stream_data_in.buffered_data_bytes = (hard - 1) * m;

    xqc_stream_frame_t *last = xqc_calloc(1, sizeof(*last));
    CU_ASSERT_PTR_NOT_NULL_FATAL(last);
    last->data_offset = 0;
    last->data_length = (unsigned)m;
    last->data = xqc_malloc(last->data_length);
    CU_ASSERT_PTR_NOT_NULL_FATAL(last->data);
    CU_ASSERT_EQUAL(xqc_insert_stream_frame(conn, stream, last), XQC_OK);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_frame_count, hard);

    xqc_stream_frame_t *over = xqc_calloc(1, sizeof(*over));
    CU_ASSERT_PTR_NOT_NULL_FATAL(over);
    over->data_offset = m;
    over->data_length = (unsigned)m;
    over->data = xqc_malloc(over->data_length);
    CU_ASSERT_PTR_NOT_NULL_FATAL(over->data);
    CU_ASSERT_EQUAL(xqc_insert_stream_frame(conn, stream, over), -XQC_ELIMIT);
    CU_ASSERT_EQUAL(stream->stream_data_in.buffered_frame_count, hard);
    xqc_destroy_stream_frame(over);

    xqc_engine_destroy(conn->engine);
}
