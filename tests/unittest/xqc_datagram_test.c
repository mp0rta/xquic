/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_datagram_test.h"
#include "src/transport/xqc_datagram.h"
#include <CUnit/CUnit.h>
#include <string.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_send_queue.h"
#include "xqc_common_test.h"

static void xqc_test_init_dgram_packet(xqc_packet_in_t *packet_in,
    xqc_packet_out_t *packet_out, xqc_pkt_type_t pkt_type);

static void
xqc_test_init_dgram_packet(xqc_packet_in_t *packet_in,
    xqc_packet_out_t *packet_out, xqc_pkt_type_t pkt_type)
{
    memset(packet_in, 0, sizeof(*packet_in));
    packet_in->pos = packet_out->po_payload;
    packet_in->last = packet_out->po_buf + packet_out->po_used_size;
    packet_in->pi_pkt.pkt_type = pkt_type;
}

void
xqc_test_receive_invalid_dgram()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    const unsigned char payload[100] = {0};

    xqc_packet_out_t *packet_out;
    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(packet_out != NULL);

    ret = xqc_gen_datagram_frame(packet_out, payload, (size_t)100);
    CU_ASSERT(ret == XQC_OK);

    xqc_packet_in_t pkt_in;
    xqc_test_init_dgram_packet(&pkt_in, packet_out,
                               XQC_PTYPE_SHORT_HEADER);
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

void
xqc_test_receive_dgram_at_valid_encryption_level()
{
    const xqc_pkt_type_t pkt_types[] = {
        XQC_PTYPE_0RTT, XQC_PTYPE_SHORT_HEADER
    };
    const unsigned char payload[1] = {0};
    xqc_connection_t   *conn;
    xqc_packet_out_t   *packet_out;
    xqc_packet_in_t     packet_in;
    xqc_int_t           ret;

    conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->local_settings.max_datagram_frame_size = 64;

    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT_PTR_NOT_NULL_FATAL(packet_out);
    ret = xqc_gen_datagram_frame(packet_out, payload, sizeof(payload));
    CU_ASSERT_EQUAL_FATAL(ret, XQC_OK);

    for (size_t i = 0; i < sizeof(pkt_types) / sizeof(pkt_types[0]); i++) {
        xqc_test_init_dgram_packet(&packet_in, packet_out, pkt_types[i]);

        ret = xqc_process_datagram_frame(conn, &packet_in);

        CU_ASSERT_EQUAL(ret, XQC_OK);
        CU_ASSERT(packet_in.pi_frame_types & XQC_FRAME_BIT_DATAGRAM);
        CU_ASSERT(packet_in.pos == packet_in.last);
    }

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_reject_dgram_at_invalid_encryption_level()
{
    const xqc_pkt_type_t pkt_types[] = {
        XQC_PTYPE_INIT, XQC_PTYPE_HSK
    };
    const unsigned char payload[1] = {0};

    for (size_t i = 0; i < sizeof(pkt_types) / sizeof(pkt_types[0]); i++) {
        xqc_connection_t *conn = test_engine_connect();
        CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
        conn->local_settings.max_datagram_frame_size = 64;

        xqc_packet_out_t *packet_out =
            xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
        CU_ASSERT_PTR_NOT_NULL_FATAL(packet_out);
        xqc_int_t ret = xqc_gen_datagram_frame(packet_out, payload,
                                               sizeof(payload));
        CU_ASSERT_EQUAL_FATAL(ret, XQC_OK);

        xqc_packet_in_t packet_in;
        xqc_test_init_dgram_packet(&packet_in, packet_out, pkt_types[i]);
        unsigned char *frame_start = packet_in.pos;

        ret = xqc_process_datagram_frame(conn, &packet_in);

        CU_ASSERT_EQUAL(ret, -XQC_EPROTO);
        CU_ASSERT_EQUAL(conn->conn_err, TRA_PROTOCOL_VIOLATION);
        CU_ASSERT(packet_in.pos == frame_start);
        CU_ASSERT_FALSE(packet_in.pi_frame_types & XQC_FRAME_BIT_DATAGRAM);

        xqc_engine_destroy(conn->engine);
    }
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

    /* sent (xqc_send_ctl_on_packet_sent): stops counting, and only once */
    xqc_path_ctx_t *path = conn->conn_initial_path;
    po->po_path_id = path->path_id;
    po->po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    xqc_send_ctl_on_packet_sent(path->path_send_ctl, xqc_get_pn_ctl(conn, path), po,
                                xqc_monotonic_timestamp());
    CU_ASSERT((po->po_flag & XQC_POF_DGRAM_UNSENT) == 0);
    CU_ASSERT_EQUAL(xqc_send_queue_get_dgram_unsent_num(sq), 3);
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

/* the internal 0-RTT resend (use_supplied_dgram_id) is not held back by the
 * cap: those datagrams were already accepted, and the resend treats
 * -XQC_EAGAIN as an internal error */
void
xqc_test_datagram_backlog_cap_skips_0rtt_resend()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_queue_t *sq = conn->conn_send_queue;

    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT | XQC_CONN_FLAG_UPPER_CONN_EXIST;
    conn->remote_settings.max_datagram_frame_size = 1200;
    conn->dgram_mss = 1200;
    conn->conn_settings.max_dgram_unsent_packets = 4;
    for (int i = 0; i < 4; i++) {
        xqc_test_write_dgram(conn);
    }
    CU_ASSERT_EQUAL(xqc_send_queue_get_dgram_unsent_num(sq), 4);

    unsigned char data[100] = {0};
    struct iovec iov = {.iov_base = data, .iov_len = sizeof(data)};
    uint64_t ids[1] = {100};
    size_t sent = 0, sent_bytes = 0;

    /* an application write is refused at the cap */
    CU_ASSERT_EQUAL(xqc_datagram_send_multiple_internal(conn, &iov, NULL, 1, &sent,
                        &sent_bytes, XQC_DATA_QOS_HIGH, XQC_FALSE),
                    -XQC_EAGAIN);
    CU_ASSERT_EQUAL(sent, 0);

    /* the 0-RTT resend goes through */
    CU_ASSERT_EQUAL(xqc_datagram_send_multiple_internal(conn, &iov, ids, 1, &sent,
                        &sent_bytes, XQC_DATA_QOS_HIGH, XQC_TRUE),
                    XQC_OK);
    CU_ASSERT_EQUAL(sent, 1);

    xqc_engine_destroy(conn->engine);
}

/*
 * A client and a server engine in this process, packets carried between
 * them by hand, for the DATAGRAM cap tests that need real sends.
 */
#define XQC_TEST_DP_MAX_PKTS 256

typedef struct {
    unsigned char   buf[XQC_TEST_DP_MAX_PKTS][XQC_PACKET_OUT_BUF_CAP];
    size_t          len[XQC_TEST_DP_MAX_PKTS];
    int             n;
} xqc_test_dp_queue_t;

static xqc_test_dp_queue_t  g_dp_to_server, g_dp_to_client;
static xqc_connection_t    *g_dp_client_conn;
static int                  g_dp_notified, g_dp_rounds;

static ssize_t
xqc_test_dp_write(xqc_test_dp_queue_t *q, const unsigned char *buf, size_t size)
{
    if (q->n < XQC_TEST_DP_MAX_PKTS && size <= XQC_PACKET_OUT_BUF_CAP) {
        memcpy(q->buf[q->n], buf, size);
        q->len[q->n++] = size;
    }
    return size;
}

static ssize_t
xqc_test_dp_client_write(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data)
{
    return xqc_test_dp_write(&g_dp_to_server, buf, size);
}

static ssize_t
xqc_test_dp_server_write(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data)
{
    return xqc_test_dp_write(&g_dp_to_client, buf, size);
}

static void
xqc_test_dp_set_timer(xqc_msec_t wake_after, void *user_data)
{
}

static void
xqc_test_dp_save_token(const unsigned char *token, uint32_t token_len, void *user_data)
{
}

static void
xqc_test_dp_save_string(const char *data, size_t data_len, void *user_data)
{
}

static int
xqc_test_dp_conn_create(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *conn_user_data, void *conn_proto_data)
{
    return 0;
}

static int
xqc_test_dp_accept(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data)
{
    return 0;
}

/* the application's refill: write until the cap refuses, for
 * g_dp_rounds notifies, then stop writing */
static void
xqc_test_dp_write_notify(xqc_connection_t *conn, void *user_data)
{
    unsigned char data[100] = {0};
    uint64_t id;

    if (conn != g_dp_client_conn) {
        return;
    }
    if (++g_dp_notified > g_dp_rounds) {
        return;
    }
    while (xqc_datagram_send(conn, data, sizeof(data), &id, XQC_DATA_QOS_HIGH) == XQC_OK) {
    }
}

static xqc_engine_t *
xqc_test_dp_engine(xqc_engine_type_t type)
{
    xqc_engine_ssl_config_t     ssl;
    xqc_engine_callback_t       cb = {
        .log_callbacks = xqc_null_log_cb,
        .set_event_timer = xqc_test_dp_set_timer,
    };
    xqc_transport_callbacks_t   tcbs = {
        .write_socket = type == XQC_ENGINE_CLIENT
                        ? xqc_test_dp_client_write : xqc_test_dp_server_write,
        .server_accept = xqc_test_dp_accept,
        .save_token = xqc_test_dp_save_token,
        .save_session_cb = xqc_test_dp_save_string,
        .save_tp_cb = xqc_test_dp_save_string,
    };
    xqc_app_proto_callbacks_t   ap;

    memset(&ssl, 0, sizeof(ssl));
    ssl.private_key_file = "./server.key";
    ssl.cert_file = "./server.crt";
    ssl.ciphers = XQC_TLS_CIPHERS;
    ssl.groups = XQC_TLS_GROUPS;

    xqc_engine_t *engine = xqc_engine_create(type, NULL, &ssl, &cb, &tcbs, NULL);
    CU_ASSERT_FATAL(engine != NULL);

    memset(&ap, 0, sizeof(ap));
    ap.conn_cbs.conn_create_notify = xqc_test_dp_conn_create;
    ap.dgram_cbs.datagram_write_notify = xqc_test_dp_write_notify;
    CU_ASSERT_FATAL(xqc_engine_register_alpn(engine, "transport", 9, &ap, NULL) == XQC_OK);
    return engine;
}

/* hand every queued packet to the other engine, both ways, then run both */
static void
xqc_test_dp_exchange(xqc_engine_t *client, xqc_engine_t *server)
{
    struct sockaddr_in  srv, cli;

    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(4433);
    srv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cli = srv;
    cli.sin_port = htons(5555);

    for (int i = 0; i < g_dp_to_server.n; i++) {
        xqc_engine_packet_process(server, g_dp_to_server.buf[i], g_dp_to_server.len[i],
                                  (struct sockaddr *)&srv, sizeof(srv),
                                  (struct sockaddr *)&cli, sizeof(cli),
                                  xqc_monotonic_timestamp(), NULL);
    }
    g_dp_to_server.n = 0;
    xqc_engine_main_logic(server);

    for (int i = 0; i < g_dp_to_client.n; i++) {
        xqc_engine_packet_process(client, g_dp_to_client.buf[i], g_dp_to_client.len[i],
                                  (struct sockaddr *)&cli, sizeof(cli),
                                  (struct sockaddr *)&srv, sizeof(srv),
                                  xqc_monotonic_timestamp(), NULL);
    }
    g_dp_to_client.n = 0;
    xqc_engine_main_logic(client);
}

/* an established client connection with DATAGRAM support on both sides */
static xqc_connection_t *
xqc_test_dp_connect(xqc_engine_t **client, xqc_engine_t **server, uint32_t cap)
{
    xqc_conn_settings_t     settings;
    xqc_conn_ssl_config_t   conn_ssl;
    struct sockaddr_in      srv;
    const xqc_cid_t        *cid;
    xqc_connection_t       *conn;

    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(4433);
    srv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    g_dp_to_server.n = 0;
    g_dp_to_client.n = 0;
    g_dp_client_conn = NULL;
    *client = xqc_test_dp_engine(XQC_ENGINE_CLIENT);
    *server = xqc_test_dp_engine(XQC_ENGINE_SERVER);

    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.max_datagram_frame_size = 1200;
    xqc_server_set_conn_settings(*server, &settings);
    settings.max_dgram_unsent_packets = cap;

    memset(&conn_ssl, 0, sizeof(conn_ssl));
    cid = xqc_connect(*client, &settings, NULL, 0, "", 0, &conn_ssl,
                      (struct sockaddr *)&srv, sizeof(srv), "transport", NULL);
    CU_ASSERT_FATAL(cid != NULL);
    conn = xqc_engine_conns_hash_find(*client, cid, 's');
    CU_ASSERT_FATAL(conn != NULL);

    for (int i = 0; i < 10 && !(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_CONFIRMED); i++) {
        xqc_test_dp_exchange(*client, *server);
    }
    CU_ASSERT_FATAL(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_CONFIRMED);
    CU_ASSERT_FATAL(conn->remote_settings.max_datagram_frame_size > 0);
    g_dp_client_conn = conn;
    return conn;
}

/*
 * The application refills the backlog from dgram_write_notify, and the send
 * after the notify drains it again: the next notify comes in the same engine
 * pass, not on the next ACK or timer. Three refills of a cap of 4 fit the
 * initial window.
 */
void
xqc_test_datagram_backlog_cap_renotify_after_send()
{
    xqc_engine_t *client, *server;
    xqc_connection_t *conn = xqc_test_dp_connect(&client, &server, 4);
    xqc_send_queue_t *sq = conn->conn_send_queue;
    unsigned char data[100] = {0};
    uint64_t id;

    /* fill the backlog from inside the engine, so nothing is sent yet */
    g_dp_notified = 0;
    g_dp_rounds = 3;
    client->eng_flag |= XQC_ENG_FLAG_RUNNING;
    while (xqc_datagram_send(conn, data, sizeof(data), &id, XQC_DATA_QOS_HIGH) == XQC_OK) {
    }
    client->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
    CU_ASSERT_EQUAL(xqc_send_queue_get_dgram_unsent_num(sq), 4);
    CU_ASSERT(sq->sndq_dgram_backlog_full);

    /* one pass: sends the 4, then 3 refills of 4, then a notify that
     * writes nothing */
    xqc_engine_conn_logic(client, conn);
    CU_ASSERT_FATAL(conn->conn_state != XQC_CONN_STATE_CLOSED);
    CU_ASSERT_EQUAL(g_dp_notified, g_dp_rounds + 1);
    CU_ASSERT_EQUAL(xqc_send_queue_get_dgram_unsent_num(sq), 0);
    CU_ASSERT(!sq->sndq_dgram_backlog_full);
    CU_ASSERT(g_dp_to_server.n >= 4 * (g_dp_rounds + 1));

    g_dp_client_conn = NULL;
    xqc_engine_destroy(client);
    xqc_engine_destroy(server);
}
