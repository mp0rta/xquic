/**
 * @copyright Copyright (c) 2026, Abdul Wasey
 */

#include <CUnit/CUnit.h>
#include <stdlib.h>
#include <string.h>

#include "xqc_path_outage_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/scheduler/xqc_scheduler_wlb.h"
#include "src/common/xqc_time.h"

/*
 * A second path on a real connection: one path silently stops delivering
 * (link and routes up, nothing acknowledged) while the other keeps working.
 */
typedef struct {
    xqc_connection_t  *conn;
    xqc_path_ctx_t    *dead;      /* the initial path */
    xqc_path_ctx_t     paths[2];  /* added paths, ids 1 and 2 */
    int                n_added;
} outage_test_t;

static xqc_usec_t outage_fake_now = 10000000;

static xqc_usec_t
outage_test_now(void)
{
    return outage_fake_now;
}

static int
outage_test_setup(outage_test_t *t)
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
outage_test_add_path(outage_test_t *t, unsigned pto_count)
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
outage_test_teardown(outage_test_t *t)
{
    for (int i = 0; i < t->n_added; i++) {
        xqc_list_del_init(&t->paths[i].path_list);
        xqc_send_ctl_destroy(t->paths[i].path_send_ctl);
    }
    xqc_engine_destroy(t->conn->engine);
}

static int
outage_test_pings_on(outage_test_t *t, uint64_t path_id)
{
    int n = 0;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next,
                           &t->conn->conn_send_queue->sndq_send_packets) {
        xqc_packet_out_t *po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (po->po_path_id == path_id
            && po->po_frame_types == XQC_FRAME_BIT_PING)
        {
            n++;
        }
    }
    return n;
}

/* WLB probes a path it evicted with one PING per interval, round robin
 * across evicted paths, and never with payload. */
void
xqc_test_wlb_evicted_paths_probed_with_ping(void)
{
    outage_test_t t;
    CU_ASSERT_FATAL(outage_test_setup(&t) == 0);
    /* the initial path works; paths 1 and 2 are blackholed */
    xqc_path_ctx_t *p1 = outage_test_add_path(&t, 3);
    xqc_path_ctx_t *p2 = outage_test_add_path(&t, 3);
    CU_ASSERT_FATAL(p1 != NULL && p2 != NULL);

    xqc_timestamp_pt saved = xqc_monotonic_timestamp;
    xqc_monotonic_timestamp = outage_test_now;

    size_t sz = xqc_wlb_scheduler_cb.xqc_scheduler_size();
    void *sched = calloc(1, sz);
    CU_ASSERT_FATAL(sched != NULL);
    xqc_wlb_scheduler_cb.xqc_scheduler_init(sched, t.conn->log, NULL);

    /* the first round only arms the interval */
    xqc_wlb_scheduler_cb.xqc_scheduler_handle_conn_event(
        sched, t.conn, XQC_SCHED_EVENT_CONN_ROUND_START, NULL);
    CU_ASSERT_EQUAL(outage_test_pings_on(&t, 1) + outage_test_pings_on(&t, 2), 0);

    for (int i = 0; i < 4; i++) {
        outage_fake_now += 600000;
        /* several rounds within one interval send one PING */
        for (int r = 0; r < 3; r++) {
            xqc_wlb_scheduler_cb.xqc_scheduler_handle_conn_event(
                sched, t.conn, XQC_SCHED_EVENT_CONN_ROUND_START, NULL);
        }
    }
    CU_ASSERT_EQUAL(outage_test_pings_on(&t, 1), 2);
    CU_ASSERT_EQUAL(outage_test_pings_on(&t, 2), 2);
    CU_ASSERT_EQUAL(outage_test_pings_on(&t, 0), 0);

    /* A keep-alive is not a PTO: do not bypass a full congestion window. */
    p1->path_schedule_bytes = p2->path_schedule_bytes = 100 * 1000 * 1000;
    outage_fake_now += 600000;
    xqc_wlb_scheduler_cb.xqc_scheduler_handle_conn_event(
        sched, t.conn, XQC_SCHED_EVENT_CONN_ROUND_START, NULL);
    CU_ASSERT_EQUAL(outage_test_pings_on(&t, 1) + outage_test_pings_on(&t, 2), 4);
    CU_ASSERT(xqc_list_empty(&t.conn->conn_send_queue->sndq_pto_probe_packets));
    p1->path_schedule_bytes = p2->path_schedule_bytes = 0;

    /* nothing probes a path that is not evicted */
    p1->path_send_ctl->ctl_pto_count = 0;
    p2->path_send_ctl->ctl_pto_count = 0;
    outage_fake_now += 600000;
    xqc_wlb_scheduler_cb.xqc_scheduler_handle_conn_event(
        sched, t.conn, XQC_SCHED_EVENT_CONN_ROUND_START, NULL);
    CU_ASSERT_EQUAL(outage_test_pings_on(&t, 1) + outage_test_pings_on(&t, 2), 4);

    free(sched);
    xqc_monotonic_timestamp = saved;
    outage_test_teardown(&t);
}
