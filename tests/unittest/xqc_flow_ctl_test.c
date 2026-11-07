/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_flow_ctl_test.h"
#include <CUnit/CUnit.h>
#include <stdint.h>
#include <string.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_packet_out.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "xqc_common_test.h"

/*
 * Place the receive limit less than one window below the bound so a single
 * growth step has to cross it.
 */
#define XQC_TEST_FC_NEAR_LIMIT (XQC_MAX_FLOW_CONTROL_WINDOW - 100)


/**
 * Test: xqc_clamp_to_max_flow_ctl bounds every input at the RFC 9000
 * variable-length integer maximum and leaves smaller values untouched.
 */
void
xqc_test_flow_ctl_clamp_boundary(void)
{
    CU_ASSERT_EQUAL(XQC_MAX_FLOW_CONTROL_WINDOW, ((uint64_t)1 << 62) - 1);

    /* below the bound passes through unchanged */
    CU_ASSERT_EQUAL(xqc_clamp_to_max_flow_ctl(0), 0);
    CU_ASSERT_EQUAL(xqc_clamp_to_max_flow_ctl(XQC_MAX_RECV_WINDOW), XQC_MAX_RECV_WINDOW);
    CU_ASSERT_EQUAL(xqc_clamp_to_max_flow_ctl(XQC_MAX_FLOW_CONTROL_WINDOW - 1),
                    XQC_MAX_FLOW_CONTROL_WINDOW - 1);

    /* exactly at the bound passes through unchanged */
    CU_ASSERT_EQUAL(xqc_clamp_to_max_flow_ctl(XQC_MAX_FLOW_CONTROL_WINDOW),
                    XQC_MAX_FLOW_CONTROL_WINDOW);

    /* one above the bound, and far above it, are clamped */
    CU_ASSERT_EQUAL(xqc_clamp_to_max_flow_ctl(XQC_MAX_FLOW_CONTROL_WINDOW + 1),
                    XQC_MAX_FLOW_CONTROL_WINDOW);
    CU_ASSERT_EQUAL(xqc_clamp_to_max_flow_ctl(UINT64_MAX), XQC_MAX_FLOW_CONTROL_WINDOW);
}


/**
 * Test: the stream-level growth path in xqc_stream_do_recv_flow_ctl stops at
 * the variable-length integer maximum instead of advertising a larger
 * MAX_STREAM_DATA value.
 */
void
xqc_test_stream_flow_ctl_clamp(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);

    /* keep the window-sizing branches deterministic */
    stream->recv_rate_bytes_per_sec = 0;
    stream->stream_flow_ctl.fc_last_window_update_time = 0;

    /* the whole window has been consumed, so growth is due */
    stream->stream_flow_ctl.fc_max_stream_data_can_recv = XQC_TEST_FC_NEAR_LIMIT;
    stream->stream_data_in.next_read_offset = XQC_TEST_FC_NEAR_LIMIT;
    stream->stream_flow_ctl.fc_stream_recv_window_size = XQC_MAX_RECV_WINDOW;

    CU_ASSERT_EQUAL(xqc_stream_do_recv_flow_ctl(stream), XQC_OK);

    CU_ASSERT_EQUAL(stream->stream_flow_ctl.fc_max_stream_data_can_recv,
                    XQC_MAX_FLOW_CONTROL_WINDOW);

    xqc_engine_destroy(conn->engine);
}


/**
 * Test: the connection-level growth path in xqc_stream_do_recv_flow_ctl stops
 * at the variable-length integer maximum instead of advertising a larger
 * MAX_DATA value.
 */
void
xqc_test_conn_flow_ctl_clamp(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);

    /* leave the stream window fully free so only the connection level grows */
    stream->recv_rate_bytes_per_sec = 0;
    stream->stream_flow_ctl.fc_stream_recv_window_size = XQC_MAX_RECV_WINDOW;
    stream->stream_flow_ctl.fc_max_stream_data_can_recv = XQC_MAX_RECV_WINDOW;
    stream->stream_data_in.next_read_offset = 0;

    conn->conn_settings.recv_rate_bytes_per_sec = 0;
    conn->conn_flow_ctl.fc_last_window_update_time = 0;
    conn->conn_flow_ctl.fc_max_data_can_recv = XQC_TEST_FC_NEAR_LIMIT;
    conn->conn_flow_ctl.fc_data_read = XQC_TEST_FC_NEAR_LIMIT;
    conn->conn_flow_ctl.fc_data_recved = XQC_TEST_FC_NEAR_LIMIT;
    conn->conn_flow_ctl.fc_recv_windows_size = XQC_MAX_RECV_WINDOW;

    CU_ASSERT_EQUAL(xqc_stream_do_recv_flow_ctl(stream), XQC_OK);

    /* the stream level stayed put, so the assertion below observes the
       connection-level clamp on its own */
    CU_ASSERT_EQUAL(stream->stream_flow_ctl.fc_max_stream_data_can_recv, XQC_MAX_RECV_WINDOW);
    CU_ASSERT_EQUAL(conn->conn_flow_ctl.fc_max_data_can_recv, XQC_MAX_FLOW_CONTROL_WINDOW);

    xqc_engine_destroy(conn->engine);
}


/**
 * Control test: a limit far below the bound still grows by the full window, so
 * the assertions above observe the clamp rather than a saturated no-op.
 */
void
xqc_test_flow_ctl_normal_no_clamp(void)
{
    uint64_t expected;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);

    stream->recv_rate_bytes_per_sec = 0;
    stream->stream_flow_ctl.fc_last_window_update_time = 0;

    stream->stream_flow_ctl.fc_max_stream_data_can_recv = 1024 * 1024;
    stream->stream_data_in.next_read_offset = 1024 * 1024;
    stream->stream_flow_ctl.fc_stream_recv_window_size = XQC_MAX_RECV_WINDOW;

    expected = stream->stream_flow_ctl.fc_max_stream_data_can_recv + XQC_MAX_RECV_WINDOW;

    CU_ASSERT_EQUAL(xqc_stream_do_recv_flow_ctl(stream), XQC_OK);

    CU_ASSERT_EQUAL(stream->stream_flow_ctl.fc_max_stream_data_can_recv, expected);
    CU_ASSERT(stream->stream_flow_ctl.fc_max_stream_data_can_recv < XQC_MAX_FLOW_CONTROL_WINDOW);

    xqc_engine_destroy(conn->engine);
}


/* xqc_test_uni_stream_credit_exhausted and _not_exhausted (upstream #963)
   test the stream-count credit of upstream #555, which this fork reverts
   (48b7fc3). */


/*
 * Set up `unread` received-unread bytes, `avail` credit granted beyond what
 * was received and window w, run the connection-level update only, and report
 * whether MAX_DATA grew (RFC 9000 Section 4.2).
 */
static int
xqc_test_fc_try(xqc_connection_t *conn, xqc_stream_t *stream, uint64_t w,
    uint64_t unread, uint64_t avail, uint64_t *new_max)
{
    xqc_conn_flow_ctl_t *fc = &conn->conn_flow_ctl;
    uint64_t             before;

    fc->fc_recv_windows_size = w;
    fc->fc_last_window_update_time = 0;
    fc->fc_last_window_update_read = 0;
    fc->fc_data_read = 30000;
    fc->fc_data_recved = 30000 + unread;
    fc->fc_max_data_can_recv = fc->fc_data_recved + avail;
    before = fc->fc_max_data_can_recv;

    CU_ASSERT_EQUAL(xqc_stream_do_recv_conn_flow_ctl(stream), XQC_OK);
    if (new_max) {
        *new_max = fc->fc_max_data_can_recv;
    }
    return fc->fc_max_data_can_recv > before;
}

static xqc_stream_t *
xqc_test_fc_stream(xqc_connection_t *conn)
{
    xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);

    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    /* 1.5 x this stays below every window the tests use */
    stream->stream_flow_ctl.fc_stream_recv_window_size = 1000;
    conn->conn_settings.recv_rate_bytes_per_sec = 0;
    return stream;
}

/* Unread bytes held by a paused stream do not block the others. */
void
xqc_test_conn_credit_parked_bytes(void)
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_stream_t     *stream;
    uint64_t          max;
    uint64_t          w = 100000;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_test_fc_stream(conn);

    /* 60000 parked, the peer's credit is used up: extended to read + W
       without any DATA_BLOCKED having been processed */
    CU_ASSERT(xqc_test_fc_try(conn, stream, w, 60000, 0, &max));
    CU_ASSERT_EQUAL(max, 30000 + w);

    /* the whole window is unread: nothing to extend */
    CU_ASSERT(!xqc_test_fc_try(conn, stream, w, w, 0, NULL));
    CU_ASSERT(!xqc_test_fc_try(conn, stream, w, w + 5000, 0, NULL));

    /* E = 1 and E = 2: extended at once */
    CU_ASSERT(xqc_test_fc_try(conn, stream, w, w - 1, 0, &max));
    CU_ASSERT_EQUAL(max, 30000 + w);
    CU_ASSERT(xqc_test_fc_try(conn, stream, w, w - 2, 0, &max));
    CU_ASSERT_EQUAL(max, 30000 + w);
    CU_ASSERT(!xqc_test_fc_try(conn, stream, w, w - 1, 1, NULL));

    /* nothing parked: extended exactly when max_data - fc_data_read < W / 2 */
    CU_ASSERT(!xqc_test_fc_try(conn, stream, w, 0, w / 2, NULL));
    CU_ASSERT(xqc_test_fc_try(conn, stream, w, 0, w / 2 - 1, &max));
    CU_ASSERT_EQUAL(max, 30000 + w);

    xqc_engine_destroy(conn->engine);
}

/* A RESET_STREAM moves fc_data_read and extends the
   credit at once (RFC 9000 Section 4.5) */
void
xqc_test_conn_credit_reset_extends(void)
{
    xqc_connection_t    *conn = test_engine_connect();
    xqc_stream_t        *stream;
    xqc_conn_flow_ctl_t *fc;
    xqc_packet_in_t      pi;
    uint8_t              frame[16];
    size_t               n = 0;
    uint64_t             before;
    uint64_t             w = 63000;
    uint64_t             id;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_test_fc_stream(conn);
    fc = &conn->conn_flow_ctl;
    id = stream->stream_id;

    /* this stream holds 40000 unread bytes; other streams read 20000 */
    stream->stream_max_recv_offset = 40000;
    stream->stream_data_in.next_read_offset = 0;
    stream->stream_flow_ctl.fc_max_stream_data_can_recv = 1000000;
    fc->fc_recv_windows_size = w;
    fc->fc_data_read = 20000;
    fc->fc_data_recved = 60000;
    fc->fc_max_data_can_recv = 63000;
    before = fc->fc_max_data_can_recv;

    /* RESET_STREAM: stream id, error code, final size (4-byte varints) */
    frame[n++] = XQC_FRAME_TYPE_RESET_STREAM;
    frame[n++] = (uint8_t)(0x80 | (id >> 24));
    frame[n++] = (uint8_t)(id >> 16);
    frame[n++] = (uint8_t)(id >> 8);
    frame[n++] = (uint8_t)id;
    frame[n++] = 0x40;
    frame[n++] = 0x01;
    frame[n++] = 0x80;
    frame[n++] = 0x00;
    frame[n++] = 0x9c;
    frame[n++] = 0x40;                  /* 40000 */
    memset(&pi, 0, sizeof(pi));
    pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    pi.pos = frame;
    pi.last = frame + n;

    CU_ASSERT_EQUAL(xqc_process_reset_stream_frame(conn, &pi), XQC_OK);

    CU_ASSERT_EQUAL(fc->fc_data_read, 60000);
    CU_ASSERT_EQUAL(fc->fc_data_recved, 60000);
    CU_ASSERT(fc->fc_max_data_can_recv > before);
    CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, 60000 + w);

    xqc_engine_destroy(conn->engine);
}

/* packets in the send queues that carry a MAX_DATA frame */
static unsigned
xqc_test_fc_max_data_queued(xqc_connection_t *conn)
{
    xqc_list_head_t *heads[] = {
        &conn->conn_send_queue->sndq_send_packets,
        &conn->conn_send_queue->sndq_send_packets_high_pri,
    };
    unsigned         count = 0;
    size_t           k;

    for (k = 0; k < sizeof(heads) / sizeof(heads[0]); k++) {
        xqc_list_head_t *pos;

        xqc_list_for_each(pos, heads[k]) {
            xqc_packet_out_t *po = xqc_list_entry(pos, xqc_packet_out_t,
                                                  po_list);
            count += !!(po->po_frame_types & XQC_FRAME_BIT_MAX_DATA);
        }
    }
    return count;
}

/* A RESET_STREAM_AT whose final size uses credit extends the connection
   credit at once, with unread data held (RFC 9000 Section 4.2 and 4.5) */
void
xqc_test_conn_credit_reset_at_final_size_extends(void)
{
    xqc_connection_t    *conn = test_engine_connect();
    xqc_stream_t        *stream;
    xqc_conn_flow_ctl_t *fc;
    xqc_packet_in_t      pi;
    uint8_t              frame[32];
    size_t               n = 0;
    uint64_t             w = 63000;
    uint64_t             id;
    unsigned             queued;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_test_fc_stream(conn);
    fc = &conn->conn_flow_ctl;
    id = stream->stream_id;
    conn->local_settings.reset_stream_at = XQC_TRUE;
    conn->remote_settings.reset_stream_at = XQC_TRUE;

    /* this stream holds 40000 unread bytes, nothing else is unread */
    stream->stream_max_recv_offset = 40000;
    stream->stream_data_in.next_read_offset = 0;
    stream->stream_flow_ctl.fc_max_stream_data_can_recv = 1000000;
    fc->fc_recv_windows_size = w;
    fc->fc_data_read = 20000;
    fc->fc_data_recved = 60000;
    fc->fc_max_data_can_recv = 62000;

    /* RESET_STREAM_AT: id, error, final size 41000, reliable size 100 */
    frame[n++] = XQC_FRAME_TYPE_RESET_STREAM_AT;
    frame[n++] = (uint8_t)(0x80 | (id >> 24));
    frame[n++] = (uint8_t)(id >> 16);
    frame[n++] = (uint8_t)(id >> 8);
    frame[n++] = (uint8_t)id;
    frame[n++] = 0x40;
    frame[n++] = 0x01;                  /* error 1 */
    frame[n++] = 0x80;
    frame[n++] = 0x00;
    frame[n++] = 0xa0;
    frame[n++] = 0x28;                  /* 41000 */
    frame[n++] = 0x40;
    frame[n++] = 0x64;                  /* 100 */
    memset(&pi, 0, sizeof(pi));
    pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    pi.pos = frame;
    pi.last = frame + n;

    CU_ASSERT_EQUAL(xqc_process_reset_stream_at_frame(conn, &pi), XQC_OK);

    CU_ASSERT_EQUAL(stream->stream_max_recv_offset, 41000);
    CU_ASSERT_EQUAL(fc->fc_data_recved, 61000);
    CU_ASSERT_EQUAL(fc->fc_data_read, 20000);
    CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, 20000 + w);
    queued = xqc_test_fc_max_data_queued(conn);
    CU_ASSERT(queued > 0);

    xqc_engine_destroy(conn->engine);
}

/* A RESET_STREAM that completes the reset checks connection credit once,
   after the discarded bytes count as read; a second check would queue a
   second MAX_DATA, which the count assert catches. Both reliable-reset
   settings run, as they select the handler. */
void
xqc_test_conn_credit_reset_checks_once(void)
{
    int pass;

    for (pass = 0; pass < 2; pass++) {
        xqc_connection_t    *conn = test_engine_connect();
        xqc_stream_t        *stream;
        xqc_conn_flow_ctl_t *fc;
        xqc_packet_in_t      pi;
        uint8_t              frame[32];
        size_t               n = 0;
        uint64_t             w = 63000;
        uint64_t             id;

        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        stream = xqc_test_fc_stream(conn);
        fc = &conn->conn_flow_ctl;
        id = stream->stream_id;
        conn->local_settings.reset_stream_at = pass == 1;
        conn->remote_settings.reset_stream_at = pass == 1;

        stream->stream_max_recv_offset = 40000;
        stream->stream_data_in.next_read_offset = 0;
        stream->stream_flow_ctl.fc_max_stream_data_can_recv = 1000000;
        fc->fc_recv_windows_size = w;
        fc->fc_data_read = 20000;
        fc->fc_data_recved = 60000;
        fc->fc_max_data_can_recv = 62000;

        /* RESET_STREAM: id, error 1, final size 41000 */
        frame[n++] = XQC_FRAME_TYPE_RESET_STREAM;
        frame[n++] = (uint8_t)(0x80 | (id >> 24));
        frame[n++] = (uint8_t)(id >> 16);
        frame[n++] = (uint8_t)(id >> 8);
        frame[n++] = (uint8_t)id;
        frame[n++] = 0x40;
        frame[n++] = 0x01;
        frame[n++] = 0x80;
        frame[n++] = 0x00;
        frame[n++] = 0xa0;
        frame[n++] = 0x28;
        memset(&pi, 0, sizeof(pi));
        pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
        pi.pos = frame;
        pi.last = frame + n;

        CU_ASSERT_EQUAL(xqc_process_frames(conn, &pi), XQC_OK);

        CU_ASSERT_EQUAL(fc->fc_data_read, 61000);
        CU_ASSERT_EQUAL(fc->fc_data_recved, 61000);
        CU_ASSERT_EQUAL(fc->fc_recv_windows_size, w);
        CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, 61000 + w);
        CU_ASSERT_EQUAL(xqc_test_fc_max_data_queued(conn), 1);

        xqc_engine_destroy(conn->engine);
    }
}

/* With a bound on unread data the connection window never shrinks. */
void
xqc_test_conn_window_monotone(void)
{
    xqc_connection_t    *conn = test_engine_connect();
    xqc_stream_t        *stream;
    xqc_conn_flow_ctl_t *fc;
    xqc_path_ctx_t      *path;
    int                  pass;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_test_fc_stream(conn);
    fc = &conn->conn_flow_ctl;
    path = conn->conn_initial_path;
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);

    /* (a) L > 0, receive rate; (c) rate only; (d) stream rate limit */
    for (pass = 0; pass < 3; pass++) {
        conn->conn_settings.max_body_buf_per_stream = pass == 0 ? 1 : 0;
        conn->conn_settings.enable_stream_rate_limit = pass == 2;
        conn->conn_settings.recv_rate_bytes_per_sec = 10 * 1000 * 1000;

        path->path_send_ctl->ctl_srtt = 60000;
        CU_ASSERT_EQUAL(xqc_conn_get_max_srtt(conn), 60000);
        fc->fc_recv_windows_size = 63000;
        xqc_test_fc_try(conn, stream, 63000, 0, 0, NULL);
        CU_ASSERT_EQUAL(fc->fc_recv_windows_size, 600000);

        path->path_send_ctl->ctl_srtt = 5000;
        xqc_test_fc_try(conn, stream, fc->fc_recv_windows_size, 0, 0, NULL);
        CU_ASSERT_EQUAL(fc->fc_recv_windows_size, pass == 1 ? 63000 : 600000);
    }

    /* (b) L > 0, no rate, 32 MiB initial window, two updates within
       2 * min_srtt: the autotune would cut it to 16 MiB */
    conn->conn_settings.max_body_buf_per_stream = 1;
    conn->conn_settings.enable_stream_rate_limit = 0;
    conn->conn_settings.recv_rate_bytes_per_sec = 0;
    path->path_send_ctl->ctl_srtt = 10 * 1000 * 1000;
    /* 20 MiB read: more than half a window since the last resize, so it
       resizes */
    fc->fc_recv_windows_size = 32 * 1024 * 1024;
    fc->fc_last_window_update_time = 0;
    fc->fc_last_window_update_read = 0;
    fc->fc_data_read = fc->fc_data_recved = 20 * 1024 * 1024;
    fc->fc_max_data_can_recv = fc->fc_data_recved;
    CU_ASSERT(xqc_stream_do_recv_conn_flow_ctl(stream) == XQC_OK);
    fc->fc_data_read = fc->fc_data_recved = fc->fc_max_data_can_recv;
    CU_ASSERT(fc->fc_last_window_update_time != 0);
    CU_ASSERT(xqc_stream_do_recv_conn_flow_ctl(stream) == XQC_OK);
    CU_ASSERT(fc->fc_recv_windows_size >= 32 * 1024 * 1024);

    /* without the bound it is cut (today's behaviour) */
    conn->conn_settings.max_body_buf_per_stream = 0;
    fc->fc_data_read = fc->fc_data_recved = fc->fc_max_data_can_recv;
    CU_ASSERT(xqc_stream_do_recv_conn_flow_ctl(stream) == XQC_OK);
    CU_ASSERT_EQUAL(fc->fc_recv_windows_size, XQC_MAX_RECV_WINDOW);

    xqc_engine_destroy(conn->engine);
}

/* The peer sends one STREAM frame of len bytes at off through the parser. */
static int
xqc_test_fc_peer_frame(xqc_connection_t *conn, xqc_stream_t *stream,
    uint64_t off, uint64_t len)
{
    static uint8_t  pkt[1300];
    uint8_t        *p = pkt;
    xqc_packet_in_t pi;

    *p++ = 0x0e;    /* STREAM with OFF, LEN */
    p = xqc_put_varint(p, stream->stream_id);
    p = xqc_put_varint(p, off);
    p = xqc_put_varint(p, len);
    CU_ASSERT_FATAL(len <= sizeof(pkt) - (size_t)(p - pkt));
    memset(p, 0x5a, len);
    p += len;
    memset(&pi, 0, sizeof(pi));
    pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    pi.pos = pkt;
    pi.last = p;
    return xqc_process_frames(conn, &pi);
}

/* The peer sends 1200-byte frames until the connection or the stream credit
   is spent; returns the new offset. */
static uint64_t
xqc_test_fc_peer_spend(xqc_connection_t *conn, xqc_stream_t *stream,
    uint64_t off)
{
    xqc_conn_flow_ctl_t *fc = &conn->conn_flow_ctl;

    for (;;) {
        uint64_t conn_left = fc->fc_max_data_can_recv - fc->fc_data_recved;
        uint64_t strm_left =
            stream->stream_flow_ctl.fc_max_stream_data_can_recv - off;
        uint64_t len = xqc_min(conn_left, strm_left);

        if (len == 0) {
            break;
        }
        if (len > 1200) {
            len = 1200;
        }
        CU_ASSERT_EQUAL_FATAL(xqc_test_fc_peer_frame(conn, stream, off, len),
                              XQC_OK);
        off += len;
    }
    return off;
}

/*
 * Arrival of data does not resize the connection window; reading half a
 * window does, even when the credit is extended in between.
 */
void
xqc_test_conn_window_resized_by_reads_not_arrivals(void)
{
    xqc_connection_t    *conn = test_engine_connect();
    xqc_stream_t        *stream;
    xqc_conn_flow_ctl_t *fc;
    uint64_t             w = 1048576;
    uint64_t             off = 0;
    uint8_t              buf[4096];
    uint8_t              fin = 0;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID,
                                         NULL, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    fc = &conn->conn_flow_ctl;
    conn->conn_settings.recv_rate_bytes_per_sec = 0;
    stream->stream_flow_ctl.fc_stream_recv_window_size = XQC_MAX_RECV_WINDOW;
    stream->stream_flow_ctl.fc_max_stream_data_can_recv = XQC_MAX_RECV_WINDOW;
    fc->fc_recv_windows_size = w;
    fc->fc_max_data_can_recv = w;
    fc->fc_data_read = fc->fc_data_recved = 0;
    fc->fc_last_window_update_time = 0;
    fc->fc_last_window_update_read = 0;

    /* the peer sends 1 byte, the application reads it, the peer spends its
       credit */
    CU_ASSERT_EQUAL_FATAL(xqc_test_fc_peer_frame(conn, stream, off, 1), XQC_OK);
    off += 1;
    CU_ASSERT_EQUAL_FATAL(xqc_stream_recv(stream, buf, 1, &fin), 1);
    off = xqc_test_fc_peer_spend(conn, stream, off);

    CU_ASSERT_EQUAL(fc->fc_recv_windows_size, w);
    CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, fc->fc_data_read + w);
    CU_ASSERT_EQUAL(fc->fc_data_recved - fc->fc_data_read, w);

    /* 4096-byte reads, each followed by the peer spending the new credit; the
       window stays until more than half of it (524288 bytes) has been read */
    for (;;) {
        CU_ASSERT_EQUAL_FATAL(xqc_stream_recv(stream, buf, sizeof(buf), &fin),
                              sizeof(buf));
        if (fc->fc_data_read > w / 2) {
            break;
        }
        CU_ASSERT_EQUAL(fc->fc_recv_windows_size, w);
        off = xqc_test_fc_peer_spend(conn, stream, off);
        CU_ASSERT_EQUAL(fc->fc_recv_windows_size, w);
    }

    /* 1.5 x the 16 MiB stream window */
    CU_ASSERT_EQUAL(fc->fc_recv_windows_size, 25165824);
    CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, fc->fc_data_read + 25165824);

    xqc_engine_destroy(conn->engine);
}

/*
 * Doubling is measured from the last resize, not from the last credit
 * extension: an extension without a resize leaves the resize time alone.
 */
void
xqc_test_conn_window_doubling_from_last_resize(void)
{
    xqc_connection_t    *conn = test_engine_connect();
    xqc_stream_t        *stream;
    xqc_conn_flow_ctl_t *fc;
    uint64_t             w = 100000;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_test_fc_stream(conn);
    fc = &conn->conn_flow_ctl;
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn->conn_initial_path);
    /* 10 s, as in the monotone test, so the second resize is well within
       2 x srtt */
    conn->conn_initial_path->path_send_ctl->ctl_srtt = 10 * 1000 * 1000;

    fc->fc_recv_windows_size = w;
    fc->fc_last_window_update_time = 0;
    fc->fc_last_window_update_read = 0;

    /* 30000 read, credit spent: extended, but under half a window read */
    fc->fc_data_read = 30000;
    fc->fc_data_recved = 90000;
    fc->fc_max_data_can_recv = 90000;
    CU_ASSERT_EQUAL(xqc_stream_do_recv_conn_flow_ctl(stream), XQC_OK);
    CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, 130000);
    CU_ASSERT_EQUAL(fc->fc_recv_windows_size, w);
    CU_ASSERT_EQUAL(fc->fc_last_window_update_time, 0);

    /* everything read: first resize, no earlier resize to double from */
    fc->fc_data_read = fc->fc_data_recved = 90000;
    CU_ASSERT_EQUAL(xqc_stream_do_recv_conn_flow_ctl(stream), XQC_OK);
    CU_ASSERT_EQUAL(fc->fc_recv_windows_size, w);
    CU_ASSERT_EQUAL(fc->fc_last_window_update_read, 90000);
    CU_ASSERT(fc->fc_last_window_update_time != 0);
    CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, 190000);

    /* second resize within 2 x srtt of the first: doubled */
    fc->fc_data_read = fc->fc_data_recved = 150000;
    CU_ASSERT_EQUAL(xqc_stream_do_recv_conn_flow_ctl(stream), XQC_OK);
    CU_ASSERT_EQUAL(fc->fc_recv_windows_size, 2 * w);
    CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, 350000);

    xqc_engine_destroy(conn->engine);
}

/*
 * The read that passes half a window is resized and extended even though the
 * peer still has credit and the credit check alone would not extend it.
 */
void
xqc_test_conn_window_resized_at_half_window_read_without_credit_due(void)
{
    xqc_connection_t    *conn = test_engine_connect();
    xqc_stream_t        *stream;
    xqc_conn_flow_ctl_t *fc;
    uint64_t             w = 100000;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_test_fc_stream(conn);
    fc = &conn->conn_flow_ctl;
    stream->stream_flow_ctl.fc_stream_recv_window_size = 100000;

    fc->fc_recv_windows_size = w;
    fc->fc_last_window_update_time = 0;
    fc->fc_last_window_update_read = 0;

    /* credit spent, under half a window read: extended, not resized */
    fc->fc_data_read = 40000;
    fc->fc_data_recved = 100000;
    fc->fc_max_data_can_recv = 100000;
    CU_ASSERT_EQUAL(xqc_stream_do_recv_conn_flow_ctl(stream), XQC_OK);
    CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, 140000);
    CU_ASSERT_EQUAL(fc->fc_recv_windows_size, w);

    /* half a window read, 40000 of credit left: resized (1.5 x the stream
       window) and extended */
    fc->fc_data_read = 60000;
    CU_ASSERT_EQUAL(xqc_stream_do_recv_conn_flow_ctl(stream), XQC_OK);
    CU_ASSERT_EQUAL(fc->fc_recv_windows_size, 150000);
    CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, 210000);

    xqc_engine_destroy(conn->engine);
}

/* feed a plain RESET_STREAM (final size below 2^14) for the stream */
static int
xqc_test_fc_peer_reset(xqc_connection_t *conn, xqc_stream_t *stream,
    uint64_t final_size)
{
    xqc_packet_in_t pi;
    uint8_t         frame[16];
    size_t          n = 0;
    uint64_t        id = stream->stream_id;

    frame[n++] = XQC_FRAME_TYPE_RESET_STREAM;
    frame[n++] = (uint8_t)(0x80 | (id >> 24));
    frame[n++] = (uint8_t)(id >> 16);
    frame[n++] = (uint8_t)(id >> 8);
    frame[n++] = (uint8_t)id;
    frame[n++] = 0x40;
    frame[n++] = 0x01;                  /* error 1 */
    frame[n++] = (uint8_t)(0x80 | (final_size >> 24));
    frame[n++] = (uint8_t)(final_size >> 16);
    frame[n++] = (uint8_t)(final_size >> 8);
    frame[n++] = (uint8_t)final_size;
    memset(&pi, 0, sizeof(pi));
    pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    pi.pos = frame;
    pi.last = frame + n;
    return xqc_process_frames(conn, &pi);
}

/* A plain RESET_STREAM whose final size exceeds the connection's remaining
   credit, or the stream's receive limit, closes the connection with
   FLOW_CONTROL_ERROR and grants nothing (RFC 9000 Section 4.1 and 19.9); a
   final size exactly at both limits is accepted. */
void
xqc_test_conn_credit_reset_over_limit_is_flow_control_error(void)
{
    /* stream limit, final size, expect a violation */
    static const struct {
        uint64_t stream_limit;
        uint64_t final_size;
        int      violation;
    } cases[] = {
        { 1000000, 40001, 1 },          /* one past the connection credit */
        { 1000000, 40000, 0 },          /* exactly the connection credit */
        { 30000, 30001, 1 },            /* one past the stream limit */
        { 30000, 30000, 0 },            /* exactly the stream limit */
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        xqc_connection_t    *conn = test_engine_connect();
        xqc_stream_t        *stream;
        xqc_conn_flow_ctl_t *fc;

        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        stream = xqc_test_fc_stream(conn);
        fc = &conn->conn_flow_ctl;
        conn->local_settings.reset_stream_at = XQC_FALSE;
        conn->remote_settings.reset_stream_at = XQC_FALSE;

        /* 60000 received and read of 100000 granted: 40000 of credit left,
           and half a window read, so a resize would extend the credit */
        stream->stream_flow_ctl.fc_max_stream_data_can_recv =
            cases[i].stream_limit;
        fc->fc_recv_windows_size = 100000;
        fc->fc_last_window_update_time = 0;
        fc->fc_last_window_update_read = 0;
        fc->fc_data_read = 60000;
        fc->fc_data_recved = 60000;
        fc->fc_max_data_can_recv = 100000;

        if (cases[i].violation) {
            CU_ASSERT_EQUAL(xqc_test_fc_peer_reset(conn, stream,
                                                   cases[i].final_size),
                            -XQC_EPROTO);
            CU_ASSERT_EQUAL(conn->conn_err, TRA_FLOW_CONTROL_ERROR);
            CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, 100000);
            CU_ASSERT_EQUAL(fc->fc_data_recved, 60000);

        } else {
            CU_ASSERT_EQUAL(xqc_test_fc_peer_reset(conn, stream,
                                                   cases[i].final_size),
                            XQC_OK);
            CU_ASSERT_EQUAL(conn->conn_err, 0);
        }

        xqc_engine_destroy(conn->engine);
    }
}

/* Without a receive rate the window is resized only once more than half a
   window was read since the last resize: exactly half does nothing, one more
   byte resizes. */
void
xqc_test_conn_window_resize_boundary_is_strictly_more_than_half(void)
{
    xqc_connection_t    *conn = test_engine_connect();
    xqc_stream_t        *stream;
    xqc_conn_flow_ctl_t *fc;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_test_fc_stream(conn);
    fc = &conn->conn_flow_ctl;

    fc->fc_recv_windows_size = 100000;
    fc->fc_last_window_update_time = 0;
    fc->fc_last_window_update_read = 0;
    fc->fc_data_recved = 100000;
    fc->fc_max_data_can_recv = 150000;

    /* exactly half a window read, credit not due: nothing happens */
    fc->fc_data_read = 50000;
    CU_ASSERT_EQUAL(xqc_stream_do_recv_conn_flow_ctl(stream), XQC_OK);
    CU_ASSERT_EQUAL(fc->fc_last_window_update_read, 0);
    CU_ASSERT_EQUAL(fc->fc_last_window_update_time, 0);
    CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, 150000);

    /* one more byte read: resized and extended */
    fc->fc_data_read = 50001;
    CU_ASSERT_EQUAL(xqc_stream_do_recv_conn_flow_ctl(stream), XQC_OK);
    CU_ASSERT_EQUAL(fc->fc_last_window_update_read, 50001);
    CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, 150001);

    xqc_engine_destroy(conn->engine);
}

/* With a receive rate set the half-window resize does not apply: more than
   half a window read since the last resize, and no credit due, changes
   nothing and queues no MAX_DATA. */
void
xqc_test_conn_window_not_resized_by_reads_with_receive_rate(void)
{
    xqc_connection_t    *conn = test_engine_connect();
    xqc_stream_t        *stream;
    xqc_conn_flow_ctl_t *fc;
    unsigned             queued;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    stream = xqc_test_fc_stream(conn);
    fc = &conn->conn_flow_ctl;
    conn->conn_settings.recv_rate_bytes_per_sec = 1000000;
    conn->conn_settings.enable_stream_rate_limit = XQC_FALSE;

    fc->fc_recv_windows_size = 100000;
    fc->fc_last_window_update_time = 0;
    fc->fc_last_window_update_read = 0;
    fc->fc_data_read = 60000;
    fc->fc_data_recved = 100000;
    fc->fc_max_data_can_recv = 140000;
    queued = xqc_test_fc_max_data_queued(conn);

    CU_ASSERT_EQUAL(xqc_stream_do_recv_conn_flow_ctl(stream), XQC_OK);
    CU_ASSERT_EQUAL(fc->fc_max_data_can_recv, 140000);
    CU_ASSERT_EQUAL(fc->fc_recv_windows_size, 100000);
    CU_ASSERT_EQUAL(xqc_test_fc_max_data_queued(conn), queued);

    xqc_engine_destroy(conn->engine);
}
