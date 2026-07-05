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

void
test_validation_pto_counts_attempts_and_abandons(void)
{
    xqc_connection_t *conn = xqc_test_helper_conn_create(NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    xqc_path_ctx_t *path = calloc(1, sizeof(*path));
    path->path_send_ctl = calloc(1, sizeof(*path->path_send_ctl));
    path->parent_conn = conn;
    /* xqc_path_request_abandon's draining backstop calls xqc_timer_set,
     * which unconditionally dereferences path_timer_manager.log via the
     * xqc_log() macro — a calloc()-zeroed (NULL) log would segfault. */
    path->path_send_ctl->path_timer_manager.log = conn->log;

    /* Non-VALIDATING paths are ignored. */
    path->path_state = XQC_PATH_STATE_ACTIVE;
    xqc_path_validation_on_pto(path);
    CU_ASSERT_EQUAL(path->path_challenge_attempts, 0);

    /* VALIDATING: one attempt per PTO; abandon at the cap. */
    path->path_state = XQC_PATH_STATE_VALIDATING;
    xqc_path_validation_on_pto(path);
    CU_ASSERT_EQUAL(path->path_challenge_attempts, 1);
    xqc_path_validation_on_pto(path);
    CU_ASSERT_EQUAL(path->path_challenge_attempts, 2);
    xqc_path_validation_on_pto(path);
    CU_ASSERT_EQUAL(path->path_challenge_attempts, XQC_PATH_VALIDATION_MAX_ATTEMPTS);
    CU_ASSERT_EQUAL(path->path_state, XQC_PATH_STATE_CLOSING);

    /* Draining backstop: without it, CLOSING is terminal whenever the peer
     * never echoes the PATH_ABANDON (the norm for a black-holed path, since
     * the peer typically never learned the path existed). The timer must
     * be armed so CLOSING -> CLOSED -> path_removed_notify still fires. */
    CU_ASSERT_TRUE(xqc_timer_is_set(&path->path_send_ctl->path_timer_manager,
                                    XQC_TIMER_PATH_DRAINING));

    free(path->path_send_ctl);
    free(path);
    xqc_test_helper_conn_destroy(conn);
}
