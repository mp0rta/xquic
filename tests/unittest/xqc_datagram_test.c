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
#include "src/transport/xqc_datagram.h"
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

static int g_dgram_write_notified;

static void
xqc_test_dgram_write_notify_cb(xqc_connection_t *conn, void *user_data)
{
    (void)conn;
    (void)user_data;
    g_dgram_write_notified++;
}

/* the oldest unsent DATAGRAM packet in the send queue */
static xqc_packet_out_t *
xqc_test_first_unsent_dgram(xqc_connection_t *conn)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->conn_send_queue->sndq_send_packets) {
        xqc_packet_out_t *po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (po->po_flag & XQC_POF_DGRAM_UNSENT) {
            return po;
        }
    }
    return NULL;
}

/* write one DATAGRAM packet without flushing (the test conn has no peer,
 * so a flush would close it) */
static void
xqc_test_write_dgram(xqc_connection_t *conn)
{
    unsigned char data[100] = {0};
    uint64_t id;
    CU_ASSERT_EQUAL(xqc_write_datagram_frame_to_packet(conn, XQC_PTYPE_SHORT_HEADER,
                        data, sizeof(data), &id, XQC_FALSE, XQC_DATA_QOS_HIGH, 0, XQC_FALSE),
                    XQC_OK);
}

/* max_dgram_unsent_packets: at the cap a DATAGRAM write gets -XQC_EAGAIN;
 * only unsent DATAGRAM packets count, a sent or freed one stops counting,
 * a copy is not counted again, and dgram_write_notify comes once half of
 * them have gone out */
void
xqc_test_datagram_backlog_cap()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_queue_t *sq = conn->conn_send_queue;

    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT | XQC_CONN_FLAG_UPPER_CONN_EXIST;
    conn->remote_settings.max_datagram_frame_size = 1200;
    conn->dgram_mss = 1200;
    conn->conn_settings.max_dgram_unsent_packets = 4;
    conn->app_proto_cbs.dgram_cbs.datagram_write_notify = xqc_test_dgram_write_notify_cb;
    g_dgram_write_notified = 0;

    unsigned char data[100] = {0};
    uint64_t id;
    for (int i = 0; i < 4; i++) {
        xqc_test_write_dgram(conn);
    }
    CU_ASSERT_EQUAL(xqc_send_queue_get_dgram_unsent_num(sq), 4);
    CU_ASSERT_EQUAL(xqc_datagram_send(conn, data, sizeof(data), &id, XQC_DATA_QOS_HIGH),
                    -XQC_EAGAIN);
    CU_ASSERT(sq->sndq_dgram_backlog_full);

    /* other unsent packets do not count against the cap */
    xqc_packet_out_t *other = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT_FATAL(other != NULL);
    other->po_frame_types = XQC_FRAME_BIT_STREAM;
    CU_ASSERT_EQUAL(xqc_send_queue_get_dgram_unsent_num(sq), 4);
    CU_ASSERT(xqc_send_queue_get_unsent_packets_num(sq) >= 5);

    /* a copy (retransmission, reinjection) is not counted */
    xqc_packet_out_t *po = xqc_test_first_unsent_dgram(conn);
    CU_ASSERT_FATAL(po != NULL);
    xqc_packet_out_t *copy = xqc_packet_out_get(sq);
    CU_ASSERT_FATAL(copy != NULL);
    xqc_packet_out_copy(copy, po);
    xqc_send_queue_insert_lost(&copy->po_list, &sq->sndq_lost_packets);
    sq->sndq_packets_used++;
    CU_ASSERT((copy->po_flag & XQC_POF_DGRAM_UNSENT) == 0);
    xqc_send_queue_dgram_unsent_done(sq, copy);
    CU_ASSERT_EQUAL(xqc_send_queue_get_dgram_unsent_num(sq), 4);

    /* sent once: stops counting, and only once */
    xqc_send_queue_dgram_unsent_done(sq, po);
    xqc_send_queue_dgram_unsent_done(sq, po);
    CU_ASSERT_EQUAL(xqc_send_queue_get_dgram_unsent_num(sq), 3);

    /* 3 left is above half the cap: no notify yet */
    CU_ASSERT(!xqc_datagram_notify_backlog_drained(conn));
    CU_ASSERT_EQUAL(g_dgram_write_notified, 0);
    CU_ASSERT(sq->sndq_dgram_backlog_full);

    /* freed without being sent: stops counting too */
    po = xqc_test_first_unsent_dgram(conn);
    CU_ASSERT_FATAL(po != NULL);
    xqc_list_del_init(&po->po_list);
    xqc_send_queue_insert_free(po, &sq->sndq_free_packets, sq);
    CU_ASSERT_EQUAL(xqc_send_queue_get_dgram_unsent_num(sq), 2);

    /* half the cap: notified once */
    CU_ASSERT(xqc_datagram_notify_backlog_drained(conn));
    CU_ASSERT_EQUAL(g_dgram_write_notified, 1);
    CU_ASSERT(!sq->sndq_dgram_backlog_full);
    CU_ASSERT(!xqc_datagram_notify_backlog_drained(conn));
    CU_ASSERT_EQUAL(g_dgram_write_notified, 1);

    /* cap 0 is no cap, whatever is unsent */
    for (int i = 0; i < 8; i++) {
        xqc_test_write_dgram(conn);
    }
    conn->conn_settings.max_dgram_unsent_packets = 0;
    CU_ASSERT_EQUAL(xqc_datagram_send(conn, data, sizeof(data), &id, XQC_DATA_QOS_HIGH),
                    XQC_OK);
    CU_ASSERT(!sq->sndq_dgram_backlog_full);

    xqc_engine_destroy(conn->engine);
}

/* unsent stream packets do not hold DATAGRAM writes back: 3 of each, a cap
 * of 4, and the write goes through */
void
xqc_test_datagram_backlog_cap_ignores_stream()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT | XQC_CONN_FLAG_UPPER_CONN_EXIST;
    conn->remote_settings.max_datagram_frame_size = 1200;
    conn->dgram_mss = 1200;
    conn->conn_settings.max_dgram_unsent_packets = 4;

    for (int i = 0; i < 3; i++) {
        xqc_packet_out_t *po = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
        CU_ASSERT_FATAL(po != NULL);
        po->po_frame_types = XQC_FRAME_BIT_STREAM;
        xqc_test_write_dgram(conn);
    }
    CU_ASSERT_EQUAL(xqc_send_queue_get_dgram_unsent_num(conn->conn_send_queue), 3);

    unsigned char data[100] = {0};
    uint64_t id;
    CU_ASSERT_EQUAL(xqc_datagram_send(conn, data, sizeof(data), &id, XQC_DATA_QOS_HIGH),
                    XQC_OK);

    xqc_engine_destroy(conn->engine);
}
