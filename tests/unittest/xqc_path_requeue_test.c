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
#include "src/transport/scheduler/xqc_scheduler_minrtt.h"
#include "src/transport/scheduler/xqc_scheduler_backup.h"

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

/* minrtt's choice for a new STREAM packet, cwnd checked */
static xqc_path_ctx_t *
requeue_test_minrtt_pick(requeue_test_t *t, xqc_packet_out_t *po,
                         xqc_bool_t *cc_blocked)
{
    return xqc_minrtt_scheduler_cb.xqc_scheduler_get_path(NULL, t->conn, po,
                                                          1, 0, cc_blocked);
}

/* After the third PTO in a row the dead path's data went to the other path,
 * so its cwnd has room again, and it still has the lowest RTT. While the
 * working path is blocked by its cwnd, minrtt must wait for it, not send
 * new data on the dead path, where it would only be lost too. */
void
xqc_test_minrtt_skips_dead_path(void)
{
    requeue_test_t t;
    xqc_bool_t cc_blocked = XQC_FALSE;
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    xqc_path_ctx_t *alive = requeue_test_add_path(&t, 0);
    CU_ASSERT_FATAL(alive != NULL);
    xqc_packet_out_t *po = requeue_test_stream_in_flight(&t, alive, 1);
    CU_ASSERT_FATAL(po != NULL);

    t.dead->path_send_ctl->ctl_srtt = 10000;
    alive->path_send_ctl->ctl_srtt = 40000;
    t.dead->path_send_ctl->ctl_pto_count = XQC_PATH_REQUEUE_PTO_THRESH;

    /* the working path has room: it is used */
    CU_ASSERT_EQUAL(requeue_test_minrtt_pick(&t, po, &cc_blocked), alive);

    /* the working path is blocked by its cwnd: wait */
    alive->path_schedule_bytes = 100 * 1000 * 1000;
    CU_ASSERT_EQUAL(requeue_test_minrtt_pick(&t, po, &cc_blocked), NULL);
    CU_ASSERT_EQUAL(cc_blocked, XQC_TRUE);

    /* the dead path answered a probe: it is the lowest RTT path again */
    t.dead->path_send_ctl->ctl_pto_count = 0;
    CU_ASSERT_EQUAL(requeue_test_minrtt_pick(&t, po, &cc_blocked), t.dead);

    alive->path_schedule_bytes = 0;
    requeue_test_teardown(&t);
}

/* When no other path works either, a path with PTOs is not skipped: there
 * is nothing better, and it may come back. */
void
xqc_test_minrtt_keeps_path_without_alternative(void)
{
    requeue_test_t t;
    xqc_bool_t cc_blocked = XQC_FALSE;
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    xqc_path_ctx_t *other = requeue_test_add_path(&t, XQC_PATH_REQUEUE_PTO_THRESH);
    CU_ASSERT_FATAL(other != NULL);
    xqc_packet_out_t *po = requeue_test_stream_in_flight(&t, other, 1);
    CU_ASSERT_FATAL(po != NULL);

    t.dead->path_send_ctl->ctl_srtt = 10000;
    other->path_send_ctl->ctl_srtt = 40000;
    t.dead->path_send_ctl->ctl_pto_count = XQC_PATH_REQUEUE_PTO_THRESH;

    CU_ASSERT_EQUAL(requeue_test_minrtt_pick(&t, po, &cc_blocked), t.dead);

    requeue_test_teardown(&t);
}

/* PINGs queued for @path on the probe list */
static int
requeue_test_probe_pings(requeue_test_t *t, xqc_path_ctx_t *path)
{
    int n = 0;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next,
                           &t->conn->conn_send_queue->sndq_pto_probe_packets)
    {
        xqc_packet_out_t *po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (po->po_path_id == path->path_id
            && (po->po_frame_types & XQC_FRAME_BIT_PING))
        {
            n++;
        }
    }
    return n;
}

/* A dead path that minrtt skips is sent a PING, so that it can be used
 * again once it answers: once per interval, not once per send round. A path
 * that is skipped for nothing (no working alternative) is not probed by the
 * scheduler. */
void
xqc_test_minrtt_probes_dead_path(void)
{
    requeue_test_t t;
    char state[64] = {0};
    CU_ASSERT_FATAL(xqc_minrtt_scheduler_cb.xqc_scheduler_size() <= sizeof(state));
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    xqc_path_ctx_t *alive = requeue_test_add_path(&t, 0);
    CU_ASSERT_FATAL(alive != NULL);
    t.dead->path_send_ctl->ctl_pto_count = XQC_PATH_REQUEUE_PTO_THRESH;

    xqc_minrtt_scheduler_cb.xqc_scheduler_handle_conn_event(state, t.conn,
        XQC_SCHED_EVENT_CONN_ROUND_START, NULL);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, t.dead), 1);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, alive), 0);

    /* the next send round, right after: no second PING */
    xqc_minrtt_scheduler_cb.xqc_scheduler_handle_conn_event(state, t.conn,
        XQC_SCHED_EVENT_CONN_ROUND_START, NULL);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, t.dead), 1);

    requeue_test_teardown(&t);

    /* no working alternative: the path is not skipped, so not probed */
    char state2[64] = {0};
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    CU_ASSERT_FATAL(requeue_test_add_path(&t, XQC_PATH_REQUEUE_PTO_THRESH) != NULL);
    t.dead->path_send_ctl->ctl_pto_count = XQC_PATH_REQUEUE_PTO_THRESH;
    xqc_minrtt_scheduler_cb.xqc_scheduler_handle_conn_event(state2, t.conn,
        XQC_SCHED_EVENT_CONN_ROUND_START, NULL);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, t.dead), 0);
    requeue_test_teardown(&t);
}


/* Failover with the backup scheduler: the AVAILABLE path carries everything
 * while it is healthy, also when its cwnd is full; the STANDBY path is used
 * once the AVAILABLE one times out, and the AVAILABLE one is used again as
 * soon as its PTO count clears. */
void
xqc_test_backup_failover(void)
{
    requeue_test_t t;
    xqc_bool_t cc_blocked = XQC_FALSE;
    const xqc_scheduler_callback_t *cb = &xqc_backup_scheduler_cb;
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    xqc_path_ctx_t *primary = t.dead;
    xqc_path_ctx_t *backup = requeue_test_add_path(&t, 0);
    CU_ASSERT_FATAL(backup != NULL);
    backup->app_path_status = XQC_APP_PATH_STATUS_STANDBY;
    xqc_packet_out_t *po = requeue_test_stream_in_flight(&t, backup, 1);
    CU_ASSERT_FATAL(po != NULL);
    primary->path_send_ctl->ctl_srtt = 10000;
    backup->path_send_ctl->ctl_srtt = 40000;

    CU_ASSERT_EQUAL(cb->xqc_scheduler_get_path(NULL, t.conn, po, 1, 0, &cc_blocked),
                    primary);

    /* the primary is blocked by its cwnd: wait for it, no spill to standby */
    primary->path_schedule_bytes = 100 * 1000 * 1000;
    CU_ASSERT_EQUAL(cb->xqc_scheduler_get_path(NULL, t.conn, po, 1, 0, &cc_blocked),
                    NULL);
    primary->path_schedule_bytes = 0;

    /* the primary times out: fail over */
    primary->path_send_ctl->ctl_pto_count =
        t.conn->conn_settings.scheduler_params.pto_cnt_thr;
    CU_ASSERT_EQUAL(cb->xqc_scheduler_get_path(NULL, t.conn, po, 1, 0, &cc_blocked),
                    backup);

    /* the primary answered: back to it */
    primary->path_send_ctl->ctl_pto_count = 0;
    CU_ASSERT_EQUAL(cb->xqc_scheduler_get_path(NULL, t.conn, po, 1, 0, &cc_blocked),
                    primary);

    requeue_test_teardown(&t);
}

/* A dead primary gets no data while the backup works, so the backup
 * scheduler PINGs it, once per interval, like minrtt does. */
void
xqc_test_backup_probes_dead_path(void)
{
    requeue_test_t t;
    char state[64] = {0};
    const xqc_scheduler_callback_t *cb = &xqc_backup_scheduler_cb;
    CU_ASSERT_FATAL(cb->xqc_scheduler_size() <= sizeof(state));
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    xqc_path_ctx_t *backup = requeue_test_add_path(&t, 0);
    CU_ASSERT_FATAL(backup != NULL);
    backup->app_path_status = XQC_APP_PATH_STATUS_STANDBY;
    t.dead->path_send_ctl->ctl_pto_count = XQC_PATH_REQUEUE_PTO_THRESH;

    cb->xqc_scheduler_handle_conn_event(state, t.conn,
                                        XQC_SCHED_EVENT_CONN_ROUND_START, NULL);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, t.dead), 1);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, backup), 0);

    cb->xqc_scheduler_handle_conn_event(state, t.conn,
                                        XQC_SCHED_EVENT_CONN_ROUND_START, NULL);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, t.dead), 1);

    requeue_test_teardown(&t);
}

/* The primary is dead and its data went to the backup, which is now
 * blocked by its cwnd. The backup scheduler goes down its classes and
 * would reach the primary (AVAILABLE, low class) next: it must wait for
 * the backup instead, or the data goes back into the outage. */
void
xqc_test_backup_skips_dead_primary(void)
{
    requeue_test_t t;
    xqc_bool_t cc_blocked = XQC_FALSE;
    const xqc_scheduler_callback_t *cb = &xqc_backup_scheduler_cb;
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    xqc_path_ctx_t *primary = t.dead;
    xqc_path_ctx_t *backup = requeue_test_add_path(&t, 0);
    CU_ASSERT_FATAL(backup != NULL);
    backup->app_path_status = XQC_APP_PATH_STATUS_STANDBY;
    xqc_packet_out_t *po = requeue_test_stream_in_flight(&t, backup, 1);
    CU_ASSERT_FATAL(po != NULL);
    primary->path_send_ctl->ctl_srtt = 10000;
    backup->path_send_ctl->ctl_srtt = 40000;
    primary->path_send_ctl->ctl_pto_count = XQC_PATH_REQUEUE_PTO_THRESH;

    CU_ASSERT_EQUAL(cb->xqc_scheduler_get_path(NULL, t.conn, po, 1, 0, &cc_blocked),
                    backup);

    backup->path_schedule_bytes = 100 * 1000 * 1000;
    CU_ASSERT_EQUAL(cb->xqc_scheduler_get_path(NULL, t.conn, po, 1, 0, &cc_blocked),
                    NULL);
    CU_ASSERT_EQUAL(cc_blocked, XQC_TRUE);
    backup->path_schedule_bytes = 0;

    requeue_test_teardown(&t);
}

/* the path idle timer callback (xqc_timer.c) */
void xqc_timer_path_idle_timeout(xqc_timer_type_t type, xqc_usec_t now,
                                 void *user_data);

/* keep-alive PINGs queued for @path */
static int
requeue_test_keepalive_pings(requeue_test_t *t, xqc_path_ctx_t *path)
{
    int n = 0;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next,
                           &t->conn->conn_send_queue->sndq_send_packets_high_pri)
    {
        xqc_packet_out_t *po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (po->po_path_id == path->path_id
            && (po->po_frame_types & XQC_FRAME_BIT_PING))
        {
            n++;
        }
    }
    return n;
}

/* A STANDBY path is quiet only with standby probing off and another path
 * working: once the primary is dead, the backup carries the traffic. */
void
xqc_test_quiet_standby_rule(void)
{
    requeue_test_t t;
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    xqc_path_ctx_t *primary = t.dead;
    xqc_path_ctx_t *backup = requeue_test_add_path(&t, 0);
    CU_ASSERT_FATAL(backup != NULL);
    backup->app_path_status = XQC_APP_PATH_STATUS_STANDBY;
    t.conn->conn_settings.standby_path_probe_timeout = 0;

    CU_ASSERT_TRUE(xqc_path_is_quiet_standby(backup));
    CU_ASSERT_FALSE(xqc_path_is_quiet_standby(primary));

    t.conn->conn_settings.standby_path_probe_timeout = 1000;
    CU_ASSERT_FALSE(xqc_path_is_quiet_standby(backup));
    t.conn->conn_settings.standby_path_probe_timeout = 0;

    primary->path_send_ctl->ctl_pto_count = XQC_PATH_REQUEUE_PTO_THRESH;
    CU_ASSERT_FALSE(xqc_path_is_quiet_standby(backup));

    requeue_test_teardown(&t);
}

/* The keep-alive PINGs every path but a quiet backup. A PING the
 * application asked for (notify) still goes on every path. */
void
xqc_test_keepalive_skips_quiet_standby(void)
{
    requeue_test_t t;
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    t.conn->conn_settings.mp_ping_on = 1;
    t.conn->conn_settings.standby_path_probe_timeout = 0;
    xqc_path_ctx_t *primary = t.dead;
    xqc_path_ctx_t *backup = requeue_test_add_path(&t, 0);
    CU_ASSERT_FATAL(backup != NULL);
    backup->app_path_status = XQC_APP_PATH_STATUS_STANDBY;

    CU_ASSERT_EQUAL(xqc_conn_send_ping_internal(t.conn, NULL, XQC_FALSE), XQC_OK);
    CU_ASSERT_EQUAL(requeue_test_keepalive_pings(&t, primary), 1);
    CU_ASSERT_EQUAL(requeue_test_keepalive_pings(&t, backup), 0);

    /* the primary is dead: the backup is pinged again */
    primary->path_send_ctl->ctl_pto_count = XQC_PATH_REQUEUE_PTO_THRESH;
    CU_ASSERT_EQUAL(xqc_conn_send_ping_internal(t.conn, NULL, XQC_FALSE), XQC_OK);
    CU_ASSERT_EQUAL(requeue_test_keepalive_pings(&t, backup), 1);

    requeue_test_teardown(&t);
}

/* Two backups and a primary that goes silent with its link up: another
 * STANDBY path does not make a backup quiet, since an idle backup has a
 * PTO count of 0 whether its link works or not. Both backups are pinged
 * again, so the connection stays alive. */
void
xqc_test_two_backups_not_quiet_without_primary(void)
{
    requeue_test_t t;
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    t.conn->conn_settings.mp_ping_on = 1;
    t.conn->conn_settings.standby_path_probe_timeout = 0;
    xqc_path_ctx_t *primary = t.dead;
    xqc_path_ctx_t *b1 = requeue_test_add_path(&t, 0);
    xqc_path_ctx_t *b2 = requeue_test_add_path(&t, 0);
    CU_ASSERT_FATAL(b1 != NULL && b2 != NULL);
    b1->app_path_status = XQC_APP_PATH_STATUS_STANDBY;
    b2->app_path_status = XQC_APP_PATH_STATUS_STANDBY;

    /* the primary works: both backups are quiet */
    CU_ASSERT_TRUE(xqc_path_is_quiet_standby(b1));
    CU_ASSERT_TRUE(xqc_path_is_quiet_standby(b2));
    CU_ASSERT_EQUAL(xqc_conn_send_ping_internal(t.conn, NULL, XQC_FALSE), XQC_OK);
    CU_ASSERT_EQUAL(requeue_test_keepalive_pings(&t, b1), 0);
    CU_ASSERT_EQUAL(requeue_test_keepalive_pings(&t, b2), 0);

    /* the primary is dead: neither backup is quiet, both are pinged */
    primary->path_send_ctl->ctl_pto_count = XQC_PATH_REQUEUE_PTO_THRESH;
    CU_ASSERT_FALSE(xqc_path_is_quiet_standby(b1));
    CU_ASSERT_FALSE(xqc_path_is_quiet_standby(b2));
    CU_ASSERT_EQUAL(xqc_conn_send_ping_internal(t.conn, NULL, XQC_FALSE), XQC_OK);
    CU_ASSERT_EQUAL(requeue_test_keepalive_pings(&t, b1), 1);
    CU_ASSERT_EQUAL(requeue_test_keepalive_pings(&t, b2), 1);

    requeue_test_teardown(&t);
}

/* A backup that stops being quiet gets a PING at the next send round, once,
 * rather than at the next keep-alive: its NAT mapping may have expired
 * while it was quiet. */
void
xqc_test_quiet_standby_woken_once(void)
{
    requeue_test_t t;
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    t.conn->conn_settings.standby_path_probe_timeout = 0;
    xqc_path_ctx_t *primary = t.dead;
    xqc_path_ctx_t *b1 = requeue_test_add_path(&t, 0);
    xqc_path_ctx_t *b2 = requeue_test_add_path(&t, 0);
    CU_ASSERT_FATAL(b1 != NULL && b2 != NULL);
    b1->app_path_status = XQC_APP_PATH_STATUS_STANDBY;
    b2->app_path_status = XQC_APP_PATH_STATUS_STANDBY;

    xqc_conn_wake_quiet_standby(t.conn);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, b1), 0);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, b2), 0);

    /* the primary goes silent: each backup is pinged once */
    primary->path_send_ctl->ctl_pto_count = XQC_PATH_REQUEUE_PTO_THRESH;
    for (int i = 0; i < 3; i++) {
        xqc_conn_wake_quiet_standby(t.conn);
    }
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, b1), 1);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, b2), 1);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, primary), 0);

    requeue_test_teardown(&t);
}

/* The path idle timer keeps a quiet backup: it re-arms instead of closing
 * the path. (A probed STANDBY path is closed as before; closing needs a full
 * path, which this fixture does not build.) */
void
xqc_test_idle_timer_keeps_quiet_standby(void)
{
    requeue_test_t t;
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    t.conn->conn_settings.standby_path_probe_timeout = 0;
    xqc_path_ctx_t *backup = requeue_test_add_path(&t, 0);
    CU_ASSERT_FATAL(backup != NULL);
    backup->app_path_status = XQC_APP_PATH_STATUS_STANDBY;
    t.conn->active_path_count = 2;

    xqc_timer_path_idle_timeout(XQC_TIMER_PATH_IDLE, xqc_monotonic_timestamp(),
                                backup->path_send_ctl);
    CU_ASSERT_EQUAL(backup->path_state, XQC_PATH_STATE_ACTIVE);
    CU_ASSERT_TRUE(xqc_timer_is_set(&backup->path_send_ctl->path_timer_manager,
                                    XQC_TIMER_PATH_IDLE));

    requeue_test_teardown(&t);
}

/* A path that counts as dead only from PTO expiries hidden by sends gets no
 * PING before its third PTO fires: the PING would re-arm its loss detection
 * timer and hold off the PTO that moves its data to the other paths. Nor
 * does a dead path whose congestion window is full: the probe list is not
 * held back by congestion control. Both schedulers that probe dead paths
 * share xqc_scheduler_probe_dead_paths(). */
static void
requeue_test_dead_probe_waits(const xqc_scheduler_callback_t *cb,
                              xqc_app_path_status_t alt_status)
{
    requeue_test_t t;
    char state[64] = {0};
    CU_ASSERT_FATAL(cb->xqc_scheduler_size() <= sizeof(state));
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    xqc_path_ctx_t *alt = requeue_test_add_path(&t, 0);
    CU_ASSERT_FATAL(alt != NULL);
    alt->app_path_status = alt_status;

    /* nothing acknowledged for many PTOs, with sends hiding the expiries */
    t.conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    t.conn->conn_settings.pto_backoff_factor = 2.0;
    xqc_send_ctl_t *ctl = t.dead->path_send_ctl;
    CU_ASSERT_FATAL(requeue_test_stream_in_flight(&t, t.dead, 1) != NULL);
    ctl->ctl_pto_count = 0;
    ctl->ctl_progress_time = 1;
    ctl->ctl_time_of_last_sent_ack_eliciting_packet[XQC_PNS_APP_DATA] =
        ctl->ctl_progress_time + 64 * xqc_send_ctl_calc_pto(ctl);
    CU_ASSERT_FATAL(xqc_path_is_dead_with_alternative(t.dead));

    cb->xqc_scheduler_handle_conn_event(state, t.conn,
                                        XQC_SCHED_EVENT_CONN_ROUND_START, NULL);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, t.dead), 0);

    /* the third PTO fired: the path is probed */
    ctl->ctl_pto_count = XQC_PATH_REQUEUE_PTO_THRESH;
    cb->xqc_scheduler_handle_conn_event(state, t.conn,
                                        XQC_SCHED_EVENT_CONN_ROUND_START, NULL);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, t.dead), 1);
    requeue_test_teardown(&t);

    /* a full congestion window: not probed */
    char state2[64] = {0};
    CU_ASSERT_FATAL(requeue_test_setup(&t) == 0);
    alt = requeue_test_add_path(&t, 0);
    CU_ASSERT_FATAL(alt != NULL);
    alt->app_path_status = alt_status;
    ctl = t.dead->path_send_ctl;
    ctl->ctl_pto_count = XQC_PATH_REQUEUE_PTO_THRESH;
    ctl->ctl_bytes_in_flight =
        ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong);
    CU_ASSERT_FATAL(xqc_path_is_dead_with_alternative(t.dead));
    cb->xqc_scheduler_handle_conn_event(state2, t.conn,
                                        XQC_SCHED_EVENT_CONN_ROUND_START, NULL);
    CU_ASSERT_EQUAL(requeue_test_probe_pings(&t, t.dead), 0);
    ctl->ctl_bytes_in_flight = 0;
    requeue_test_teardown(&t);
}

void
xqc_test_dead_probe_waits_for_fired_ptos(void)
{
    requeue_test_dead_probe_waits(&xqc_minrtt_scheduler_cb,
                                  XQC_APP_PATH_STATUS_AVAILABLE);
    requeue_test_dead_probe_waits(&xqc_backup_scheduler_cb,
                                  XQC_APP_PATH_STATUS_STANDBY);
}
