/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * B3: a VALIDATING path's LOSS_DETECTION (PTO) timer must be visible to
 * xqc_conn_next_wakeup_time, otherwise the engine sleeps through the
 * PATH_CHALLENGE retransmission deadline.
 */

#include <CUnit/CUnit.h>
#include <stdlib.h>

#include "xqc_test_next_wakeup.h"
#include "xqc_test_helpers.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_frame.h"
#include "xqc_common_test.h"
#include <string.h>

void
test_next_wakeup_includes_validating_path_timer(void)
{
    xqc_connection_t *conn = xqc_test_helper_conn_create(NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    xqc_init_list_head(&conn->conn_timer_manager.gp_timer_list);

    /* Stub path (pattern: xqc_ack_with_timestamp_test.c) */
    xqc_path_ctx_t *path = calloc(1, sizeof(*path));
    path->path_send_ctl = calloc(1, sizeof(*path->path_send_ctl));
    path->parent_conn = conn;
    path->path_state = XQC_PATH_STATE_VALIDATING; /* direct write: stub has no
                                                     conn accounting to keep */
    xqc_list_add_tail(&path->path_list, &conn->conn_paths_list);

    /* Disarm every conn-level timer so the path timer is the only candidate,
     * then arm the path's LOSS_DETECTION timer directly
     * (xqc_conn_next_wakeup_time reads timer_is_set/expire_time fields). */
    for (xqc_timer_type_t t = 0; t < XQC_TIMER_N; t++) {
        conn->conn_timer_manager.timer[t].timer_is_set = 0;
    }
    xqc_timer_t *lt =
        &path->path_send_ctl->path_timer_manager.timer[XQC_TIMER_LOSS_DETECTION];
    lt->timer_is_set = 1;
    lt->expire_time = 12345;

    CU_ASSERT_EQUAL(xqc_conn_next_wakeup_time(conn), 12345);

    /* Boundary pin: an INIT path with the same armed timer is also visible. */
    path->path_state = XQC_PATH_STATE_INIT;
    CU_ASSERT_EQUAL(xqc_conn_next_wakeup_time(conn), 12345);

    /* Boundary pin: a CLOSED path with the same armed timer stays skipped. */
    path->path_state = XQC_PATH_STATE_CLOSED;
    CU_ASSERT_EQUAL(xqc_conn_next_wakeup_time(conn), 0);

    /* Boundary pin: a CLOSING path with the same armed timer is also visible. */
    path->path_state = XQC_PATH_STATE_CLOSING;
    CU_ASSERT_EQUAL(xqc_conn_next_wakeup_time(conn), 12345);

    /* Unlink BEFORE freeing — if xqc_test_helper_conn_destroy walks
     * conn_paths_list, a freed-but-linked stub is a use-after-free. */
    xqc_list_del(&path->path_list);
    free(path->path_send_ctl);
    free(path);
    xqc_test_helper_conn_destroy(conn);
}

static xqc_bool_t
xqc_test_queued_frame(xqc_list_head_t *queue, xqc_frame_type_bit_t frame)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, queue) {
        xqc_packet_out_t *po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (po->po_frame_types & frame) {
            return XQC_TRUE;
        }
    }
    return XQC_FALSE;
}

/*
 * draft-21 Section 3.1: when the validation deadline (PATH_IDLE, armed for
 * RFC 9000 Section 8.2.4 when validation starts) expires, the path is closed
 * with PATH_ABANDON, stops using its connection IDs, and is kept until the
 * draining timer (Section 3.4), which a re-armed PATH_IDLE does not cut
 * short.
 */
void
test_validation_deadline_abandons_path(void)
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->enable_multipath = 1;
    conn->local_max_path_id = 1;

    xqc_cid_t scid = {0}, dcid = {0};
    scid.cid_len = dcid.cid_len = 8;
    memset(scid.cid_buf, 0x5a, 8);
    memset(dcid.cid_buf, 0xa5, 8);
    CU_ASSERT_FATAL(xqc_cid_set_add_path(&conn->scid_set, 1) == XQC_OK);
    CU_ASSERT_FATAL(xqc_cid_set_insert_cid(&conn->scid_set, &scid,
                                           XQC_CID_UNUSED, 8, 1) == XQC_OK);
    CU_ASSERT_FATAL(xqc_cid_set_add_path(&conn->dcid_set, 1) == XQC_OK);
    CU_ASSERT_FATAL(xqc_cid_set_insert_cid(&conn->dcid_set, &dcid,
                                           XQC_CID_UNUSED, 8, 1) == XQC_OK);

    xqc_path_ctx_t *path = xqc_conn_create_path_inner(conn, &scid, &dcid,
        XQC_APP_PATH_STATUS_AVAILABLE, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);
    CU_ASSERT_EQUAL(path->path_state, XQC_PATH_STATE_VALIDATING);
    xqc_timer_manager_t *tm = &path->path_send_ctl->path_timer_manager;
    CU_ASSERT_FATAL(xqc_timer_is_set(tm, XQC_TIMER_PATH_IDLE));

    /* the deadline passes with no PATH_RESPONSE */
    xqc_usec_t now = tm->timer[XQC_TIMER_PATH_IDLE].expire_time;
    xqc_timer_expire(tm, now);
    CU_ASSERT_EQUAL(path->path_state, XQC_PATH_STATE_CLOSING);
    CU_ASSERT(xqc_test_queued_frame(&conn->conn_send_queue->sndq_send_packets,
                                    XQC_FRAME_BIT_PATH_ABANDON)
              || xqc_test_queued_frame(
                     &conn->conn_send_queue->sndq_send_packets_high_pri,
                     XQC_FRAME_BIT_PATH_ABANDON));
    CU_ASSERT_EQUAL(xqc_get_path_cid_set(&conn->scid_set, 1)->set_state,
                    XQC_CID_SET_ABANDONED);
    CU_ASSERT_EQUAL(xqc_get_path_cid_set(&conn->dcid_set, 1)->set_state,
                    XQC_CID_SET_ABANDONED);
    CU_ASSERT_FATAL(xqc_timer_is_set(tm, XQC_TIMER_PATH_DRAINING));
    xqc_usec_t drain = tm->timer[XQC_TIMER_PATH_DRAINING].expire_time;

    /* a packet received on the path re-arms PATH_IDLE, which expires first */
    xqc_timer_set(tm, XQC_TIMER_PATH_IDLE, now, 1);
    xqc_timer_expire(tm, now + 1);
    CU_ASSERT_EQUAL(path->path_state, XQC_PATH_STATE_CLOSING);

    xqc_timer_expire(tm, drain);
    CU_ASSERT_EQUAL(path->path_state, XQC_PATH_STATE_CLOSED);

    xqc_engine_destroy(conn->engine);
}
