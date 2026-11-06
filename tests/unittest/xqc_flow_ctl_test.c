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
   after the discarded bytes count as read; a second check inside 2 * srtt
   would double the window. Both reliable-reset settings run, as they select
   the handler. */
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
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn->conn_initial_path);
        conn->conn_initial_path->path_send_ctl->ctl_srtt = 60000;
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
    xqc_test_fc_try(conn, stream, 32 * 1024 * 1024, 0, 0, NULL);
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
