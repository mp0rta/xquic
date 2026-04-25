/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_datagram_test.h"
#include <CUnit/CUnit.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_send_queue.h"
#include "xqc_common_test.h"

void
xqc_test_receive_invalid_dgram()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    const unsigned char payload[100];

    xqc_packet_out_t *packet_out;
    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(packet_out != NULL);

    ret = xqc_gen_datagram_frame(packet_out, payload, (size_t)100);
    CU_ASSERT(ret == XQC_OK);

    xqc_packet_in_t pkt_in;
    pkt_in.pos = packet_out->po_payload;
    pkt_in.last = packet_out->po_buf + packet_out->po_used_size;
    conn->local_settings.max_datagram_frame_size = 0;

    ret = xqc_process_datagram_frame(conn, &pkt_in);
    CU_ASSERT(ret == -XQC_EPROTO);

    conn->local_settings.max_datagram_frame_size = 50;
    ret = xqc_process_datagram_frame(conn, &pkt_in);
    CU_ASSERT(ret == -XQC_EPROTO);

    conn->local_settings.max_datagram_frame_size = 120;
    ret = xqc_process_datagram_frame(conn, &pkt_in);
    CU_ASSERT(ret == XQC_OK);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_datagram_send_on_path()
{
    xqc_int_t ret;
    uint64_t dgram_id = 0;

    /* 1. NULL connection */
    ret = xqc_datagram_send_on_path(NULL, "test", 4, &dgram_id,
                                     XQC_DATA_QOS_HIGH, 0);
    CU_ASSERT_EQUAL(ret, -XQC_EPARAM);

    /* 2. NULL data with non-zero length */
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    ret = xqc_datagram_send_on_path(conn, NULL, 100, &dgram_id,
                                     XQC_DATA_QOS_HIGH, 0);
    CU_ASSERT_EQUAL(ret, -XQC_EPARAM);

    /* 3. Invalid path_id (path not found) —
     *    test_engine_connect creates a conn but no extra paths,
     *    so path_id=999 should not exist. */
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn->remote_settings.max_datagram_frame_size = 1200;
    conn->dgram_mss = 1200;
    ret = xqc_datagram_send_on_path(conn, "test", 4, &dgram_id,
                                     XQC_DATA_QOS_HIGH, 999);
    CU_ASSERT_EQUAL(ret, -XQC_EMP_PATH_NOT_FOUND);

    /* 4. 1RTT not established — should return EAGAIN */
    conn->conn_flag &= ~XQC_CONN_FLAG_CAN_SEND_1RTT;
    ret = xqc_datagram_send_on_path(conn, "test", 4, &dgram_id,
                                     XQC_DATA_QOS_HIGH, 0);
    /* path 0 exists (initial path) but 1RTT not ready */
    CU_ASSERT(ret == -XQC_EMP_PATH_NOT_FOUND || ret == -XQC_EAGAIN);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_datagram_frame_path_pinning()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn->remote_settings.max_datagram_frame_size = 1200;
    conn->dgram_mss = 1200;

    const unsigned char data[] = "path-pin-test";
    uint64_t dgram_id = 0;
    int ret;

    /* Test 1: pin_to_path=FALSE — no path flag should be set */
    ret = xqc_write_datagram_frame_to_packet(
        conn, XQC_PTYPE_SHORT_HEADER,
        data, sizeof(data), &dgram_id, XQC_FALSE,
        XQC_DATA_QOS_HIGH, 0, XQC_FALSE);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    /* Find the packet that was just created (last in send queue) */
    xqc_packet_out_t *po;
    xqc_list_head_t *pos;
    xqc_packet_out_t *last_po = NULL;
    xqc_list_for_each(pos, &conn->conn_send_queue->sndq_send_packets) {
        po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        last_po = po;
    }
    CU_ASSERT(last_po != NULL);
    if (last_po) {
        CU_ASSERT((last_po->po_path_flag & XQC_PATH_SPECIFIED_BY_DATAGRAM) == 0);
    }

    /* Test 2: pin_to_path=TRUE — flag and path_id should be set */
    uint64_t target_path_id = 42;
    ret = xqc_write_datagram_frame_to_packet(
        conn, XQC_PTYPE_SHORT_HEADER,
        data, sizeof(data), &dgram_id, XQC_FALSE,
        XQC_DATA_QOS_HIGH, target_path_id, XQC_TRUE);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    /* Find the newest packet */
    last_po = NULL;
    xqc_list_for_each(pos, &conn->conn_send_queue->sndq_send_packets) {
        po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        last_po = po;
    }
    CU_ASSERT(last_po != NULL);
    if (last_po) {
        CU_ASSERT(last_po->po_path_flag & XQC_PATH_SPECIFIED_BY_DATAGRAM);
        CU_ASSERT_EQUAL(last_po->po_path_id, target_path_id);
    }

    xqc_engine_destroy(conn->engine);
}
