/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_flow_ctl_test.h"
#include <CUnit/CUnit.h>
#include <stdint.h>
#include <string.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_stream.h"
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


/**
 * Test: a stream's receive limit follows its type. A peer-opened
 * unidirectional stream on a client gets the local unidirectional limit even
 * when init_recv_window lowers the local bidirectional limit, and an
 * out-of-order frame inside the advertised limit is accepted (RFC 9000 4.1,
 * 18.2).
 */
void
xqc_test_stream_fc_init_by_type(void)
{
    xqc_conn_settings_t cs;
    xqc_conn_ssl_config_t ssl;
    xqc_connection_t *conn;
    xqc_engine_t *engine;
    const xqc_cid_t *cid;
    xqc_stream_t *uni, *bidi;
    xqc_packet_in_t pi;
    xqc_int_t ret;

    /* STREAM, OFF|LEN: stream 3, offset 39990, length 10 (ends at 40000) */
    unsigned char frame[17] = {0x0e, 0x03, 0x80, 0x00, 0x9c, 0x36, 0x0a,
                               'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x',
                               'x'};

    engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    memset(&cs, 0, sizeof(cs));
    memset(&ssl, 0, sizeof(ssl));
    cs.proto_version = XQC_VERSION_V1;
    cs.enable_stream_rate_limit = 1;
    cs.init_recv_window = 15360;

    cid = xqc_connect(engine, &cs, NULL, 0, "", 0, &ssl, NULL, 0,
                      "transport", NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cid);
    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    CU_ASSERT_EQUAL(conn->local_settings.max_stream_data_bidi_local, 15360);

    uni = xqc_create_stream_with_conn(conn, 3, XQC_SVR_UNI, NULL, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(uni);
    bidi = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(bidi);

    CU_ASSERT_EQUAL(uni->stream_flow_ctl.fc_max_stream_data_can_recv,
                    conn->local_settings.max_stream_data_uni);
    CU_ASSERT_EQUAL(uni->stream_flow_ctl.fc_max_stream_data_can_recv,
                    XQC_MAX_RECV_WINDOW);
    CU_ASSERT_EQUAL(bidi->stream_flow_ctl.fc_max_stream_data_can_recv, 15360);

    conn->conn_flow_ctl.fc_max_data_can_recv = 1 << 20;
    memset(&pi, 0, sizeof(pi));
    pi.buf = frame;
    pi.buf_size = sizeof(frame);
    pi.pos = frame;
    pi.last = frame + sizeof(frame);
    pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    ret = xqc_process_stream_frame(conn, &pi);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(conn->conn_err, 0);

    xqc_engine_destroy(engine);
}
