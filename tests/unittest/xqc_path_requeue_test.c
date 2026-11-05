/**
 * @copyright Copyright (c) 2026, Abdul Wasey
 */

#include <CUnit/CUnit.h>
#include <stdlib.h>
#include <string.h>

#include "xqc_path_requeue_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_multipath.h"

/*
 * A second path on a real connection: one path silently stops delivering
 * (link and routes up, nothing acknowledged) while the other keeps working.
 */
typedef struct {
    xqc_connection_t  *conn;
    xqc_path_ctx_t    *dead;      /* the initial path */
    xqc_path_ctx_t     paths[2];  /* added paths, ids 1 and 2 */
    int                n_added;
} requeue_test_t;

/* 1-RTT bytes in flight: the handshake leaves its own packets in flight */
#define APP_INFLIGHT(path) \
    ((path)->path_send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA])

static int
requeue_test_setup(requeue_test_t *t)
{
    memset(t, 0, sizeof(*t));
    t->conn = test_engine_connect();
    if (t->conn == NULL || t->conn->conn_initial_path == NULL) {
        return -1;
    }
    t->conn->enable_multipath = 1;
    t->conn->conn_state = XQC_CONN_STATE_ESTABED;
    t->dead = t->conn->conn_initial_path;
    return 0;
}

static xqc_path_ctx_t *
requeue_test_add_path(requeue_test_t *t, unsigned pto_count)
{
    xqc_path_ctx_t *path = &t->paths[t->n_added];
    memset(path, 0, sizeof(*path));
    path->path_id = ++t->n_added;
    path->parent_conn = t->conn;
    path->path_state = XQC_PATH_STATE_ACTIVE;
    path->app_path_status = XQC_APP_PATH_STATUS_AVAILABLE;
    path->path_send_ctl = xqc_send_ctl_create(path);
    if (path->path_send_ctl == NULL) {
        return NULL;
    }
    path->path_send_ctl->ctl_pto_count = pto_count;
    xqc_list_add_tail(&path->path_list, &t->conn->conn_paths_list);
    return path;
}

static void
requeue_test_teardown(requeue_test_t *t)
{
    for (int i = 0; i < t->n_added; i++) {
        xqc_list_del_init(&t->paths[i].path_list);
        xqc_send_ctl_destroy(t->paths[i].path_send_ctl);
    }
    xqc_engine_destroy(t->conn->engine);
}

/* a STREAM packet in flight on @path */
static xqc_packet_out_t *
requeue_test_stream_in_flight(requeue_test_t *t, xqc_path_ctx_t *path,
                             xqc_packet_number_t pn)
{
    xqc_send_queue_t *sq = t->conn->conn_send_queue;
    xqc_packet_out_t *po = xqc_packet_out_get(sq);
    if (po == NULL) {
        return NULL;
    }
    po->po_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    po->po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    po->po_pkt.pkt_num = pn;
    po->po_path_id = path->path_id;
    po->po_sent_time = 1;
    po->po_frame_types = XQC_FRAME_BIT_STREAM;
    po->po_used_size = 1200;
    xqc_send_queue_insert_unacked(po,
        &sq->sndq_unacked_packets[XQC_PNS_APP_DATA], sq);
    xqc_send_ctl_increase_inflight(t->conn, po);
    return po;
}

static int
requeue_test_list_len(xqc_list_head_t *head)
{
    int n = 0;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, head) {
        n++;
    }
    return n;
}

/* The PTO that makes a path's third in a row, while another path works:
 * what it had in flight goes to the lost queue, to be sent on the other
 * path, instead of waiting for the dead path to come back. */
void
xqc_test_path_requeue_unacked_on_pto(void)
{
    requeue_test_t t;
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    CU_ASSERT_FATAL(requeue_test_add_path(&t, 0) != NULL);
    xqc_send_queue_t *sq = t.conn->conn_send_queue;

    CU_ASSERT_FATAL(requeue_test_stream_in_flight(&t, t.dead, 1) != NULL);
    CU_ASSERT_FATAL(requeue_test_stream_in_flight(&t, t.dead, 2) != NULL);
    CU_ASSERT_EQUAL(APP_INFLIGHT(t.dead), 2400);

    /* the second PTO: not yet */
    t.dead->path_send_ctl->ctl_pto_count = 1;
    xqc_path_requeue_unacked_on_pto(t.dead);
    CU_ASSERT_EQUAL(requeue_test_list_len(&sq->sndq_lost_packets), 0);
    CU_ASSERT_EQUAL(APP_INFLIGHT(t.dead), 2400);

    /* the third */
    t.dead->path_send_ctl->ctl_pto_count = 2;
    xqc_path_requeue_unacked_on_pto(t.dead);
    CU_ASSERT_EQUAL(requeue_test_list_len(&sq->sndq_lost_packets), 2);
    CU_ASSERT_EQUAL(APP_INFLIGHT(t.dead), 0);

    requeue_test_teardown(&t);
}

/* With no other path that works, the data stays where it is: there is
 * nowhere better to send it, and the path may come back. */
void
xqc_test_path_requeue_needs_a_working_path(void)
{
    requeue_test_t t;
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    /* the other path is silent too */
    CU_ASSERT_FATAL(requeue_test_add_path(&t, XQC_PATH_REQUEUE_PTO_THRESH) != NULL);
    xqc_send_queue_t *sq = t.conn->conn_send_queue;

    CU_ASSERT_FATAL(requeue_test_stream_in_flight(&t, t.dead, 1) != NULL);
    t.dead->path_send_ctl->ctl_pto_count = 5;
    xqc_path_requeue_unacked_on_pto(t.dead);
    CU_ASSERT_EQUAL(requeue_test_list_len(&sq->sndq_lost_packets), 0);
    CU_ASSERT_EQUAL(APP_INFLIGHT(t.dead), 1200);

    /* a single-path connection is left alone as well */
    t.conn->enable_multipath = 0;
    t.paths[0].path_send_ctl->ctl_pto_count = 0;
    xqc_path_requeue_unacked_on_pto(t.dead);
    CU_ASSERT_EQUAL(requeue_test_list_len(&sq->sndq_lost_packets), 0);

    requeue_test_teardown(&t);
}
