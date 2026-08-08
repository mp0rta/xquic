/**
 * @copyright Copyright (c) 2026, mp0rta
 */

#include <CUnit/CUnit.h>
#include <stdlib.h>
#include <string.h>
#include "xquic/xquic.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h" /* xqc_connection_t, XQC_CONN_FLAG_TICKING */
#include "src/transport/xqc_packet_out.h"       /* XQC_MAX_PACKET_OUT_SIZE */
#include "src/transport/xqc_transport_params.h" /* XQC_DEFAULT_INIT_MAX_PATH_ID */
#include "src/congestion_control/xqc_bbr.h"     /* xqc_bbr_cb */
#include "xqc_set_conn_settings_test.h"

/* Stand-in for an xqc_engine_t whose only used field is
 * default_conn_settings. calloc-zeroed; never touched by the SUT. */
static xqc_engine_t *
make_zero_engine(void)
{
    xqc_engine_t *e = calloc(1, sizeof(*e));
    CU_ASSERT_PTR_NOT_NULL_FATAL(e);
    return e;
}

/* The 18 fields below are the subset of xqc_conn_settings_t that
 * mqvpn (the primary downstream consumer) populates today. Each
 * picks a non-default sentinel value so a missing copy line in
 * xqc_server_set_conn_settings would zero the field and trip an
 * assertion.
 *
 * Keep that claim literally true when adding to it: the scheduler and
 * reinjection callbacks were absent for a while, which quietly made the
 * guarantee above false for exactly the field whose loss is most expensive
 * (a dropped scheduler_callback copy line puts every accepted server
 * connection on the engine default instead of WLB). */
void
xqc_test_server_set_conn_settings_propagation(void)
{
    xqc_engine_t *e = make_zero_engine();

    xqc_conn_settings_t in;
    memset(&in, 0, sizeof(in));

    /* --- direct-copy fields (always assigned verbatim) --- */
    in.pacing_on = 1;
    in.mp_ping_on = 1;
    in.enable_multipath = 1;
    in.so_sndbuf = 4 * 1024 * 1024;
    in.sndq_packets_used_max = 4096;
    in.max_datagram_frame_size = 1500;
    in.cong_ctrl_callback = xqc_bbr_cb; /* defined header, address only */
    in.cc_params.customize_on = 1;      /* nested struct, sub-field probe */
    in.cc_params.init_cwnd = 32;

    /* --- conditional fields (>0 wins, else untouched) --- */
    in.idle_time_out = 60 * 1000;
    in.init_idle_time_out = 10 * 1000;

    /* --- special fields --- */
    in.max_pkt_out_size = 1300;          /* below cap → verbatim copy */
    in.proto_version = XQC_VERSION_V1;   /* valid → wins over engine default */
    in.init_max_path_id = 16;            /* non-zero → wins over default */
    in.max_path_id_grant_max_value = 32; /* direct copy */
    in.defer_send_flush = 1;             /* direct copy */

    /* mqvpn_build_conn_settings() runs mqvpn_apply_scheduler() and
     * mqvpn_apply_reinjection() unconditionally, so a server's input always
     * carries these three as well. Sentinels chosen to differ from both zero
     * and mqvpn's own defaults. */
    in.scheduler_callback = xqc_minrtt_scheduler_cb;
    in.reinj_ctl_callback = xqc_deadline_reinj_ctl_cb;
    in.mp_enable_reinjection = XQC_REINJ_UNACK_BEFORE_SCHED;

    xqc_server_set_conn_settings(e, &in);

    /* direct */
    CU_ASSERT_EQUAL(e->default_conn_settings.pacing_on, 1);
    CU_ASSERT_EQUAL(e->default_conn_settings.mp_ping_on, 1);
    CU_ASSERT_EQUAL(e->default_conn_settings.enable_multipath, 1);
    CU_ASSERT_EQUAL(e->default_conn_settings.so_sndbuf, 4 * 1024 * 1024);
    CU_ASSERT_EQUAL(e->default_conn_settings.sndq_packets_used_max, 4096);
    CU_ASSERT_EQUAL(e->default_conn_settings.max_datagram_frame_size, 1500);
    CU_ASSERT_EQUAL(memcmp(&e->default_conn_settings.cong_ctrl_callback, &xqc_bbr_cb,
                           sizeof(xqc_cong_ctrl_callback_t)),
                    0);
    CU_ASSERT_EQUAL(e->default_conn_settings.cc_params.customize_on, 1);
    CU_ASSERT_EQUAL(e->default_conn_settings.cc_params.init_cwnd, 32);

    /* conditional */
    CU_ASSERT_EQUAL(e->default_conn_settings.idle_time_out, 60 * 1000);
    CU_ASSERT_EQUAL(e->default_conn_settings.init_idle_time_out, 10 * 1000);

    /* special */
    CU_ASSERT_EQUAL(e->default_conn_settings.max_pkt_out_size, 1300);
    CU_ASSERT_EQUAL(e->default_conn_settings.proto_version, XQC_VERSION_V1);
    CU_ASSERT_EQUAL(e->default_conn_settings.init_max_path_id, 16);
    CU_ASSERT_EQUAL(e->default_conn_settings.max_path_id_grant_max_value, 32);
    /* This one was missing for a while: the copier is field-by-field, so an
     * appended setting nobody adds a line for reaches every server connection
     * as 0 while the API call still reports success. Nothing else catches it
     * — the client path assigns the whole struct so it cannot notice, and a
     * downstream builder test only proves the input side. */
    CU_ASSERT_EQUAL(e->default_conn_settings.defer_send_flush, 1);

    /* Scheduler / reinjection: the copy lines these pin are the ones whose
     * silent loss costs the most (default scheduler instead of WLB). */
    CU_ASSERT_EQUAL(memcmp(&e->default_conn_settings.scheduler_callback,
                           &xqc_minrtt_scheduler_cb, sizeof(xqc_scheduler_callback_t)),
                    0);
    CU_ASSERT_EQUAL(memcmp(&e->default_conn_settings.reinj_ctl_callback,
                           &xqc_deadline_reinj_ctl_cb, sizeof(xqc_reinj_ctl_callback_t)),
                    0);
    CU_ASSERT_EQUAL(e->default_conn_settings.mp_enable_reinjection,
                    XQC_REINJ_UNACK_BEFORE_SCHED);

    free(e);
}

/* When the conditional / sanitised fields are zero (or invalid),
 * xqc_server_set_conn_settings must apply its documented defaults
 * rather than zeroing the engine's existing value. */
void
xqc_test_server_set_conn_settings_zero_defaults(void)
{
    xqc_engine_t *e = make_zero_engine();

    /* Seed an engine-side prior value for max_pkt_out_size so we can
     * tell "unchanged" from "zeroed". */
    e->default_conn_settings.max_pkt_out_size = 1200;

    xqc_conn_settings_t in;
    memset(&in, 0, sizeof(in));

    /* All zero / invalid: each special branch should keep engine prior
     * or substitute its documented default. */
    in.max_pkt_out_size = 0;                /* falsy → engine prior preserved */
    in.proto_version = XQC_IDRAFT_INIT_VER; /* invalid → engine prior preserved */
    in.init_max_path_id = 0;                /* 0 → XQC_DEFAULT_INIT_MAX_PATH_ID */

    xqc_server_set_conn_settings(e, &in);

    CU_ASSERT_EQUAL(e->default_conn_settings.max_pkt_out_size, 1200);
    CU_ASSERT_EQUAL(e->default_conn_settings.proto_version, XQC_IDRAFT_INIT_VER);
    CU_ASSERT_EQUAL(e->default_conn_settings.init_max_path_id,
                    XQC_DEFAULT_INIT_MAX_PATH_ID);

    free(e);
}

/* max_pkt_out_size is clamped to XQC_MAX_PACKET_OUT_SIZE — overshoot
 * must be reduced, not propagated. */
void
xqc_test_server_set_conn_settings_clamp(void)
{
    xqc_engine_t *e = make_zero_engine();

    xqc_conn_settings_t in;
    memset(&in, 0, sizeof(in));
    in.max_pkt_out_size = XQC_MAX_PACKET_OUT_SIZE + 100;

    xqc_server_set_conn_settings(e, &in);

    CU_ASSERT_EQUAL(e->default_conn_settings.max_pkt_out_size, XQC_MAX_PACKET_OUT_SIZE);

    free(e);
}

/* Arming a wakeup is the deferred branch's only externally visible effect, so
 * the timer callback is what this counts. */
static int flush_or_defer_wakeups;

static void
mock_set_event_timer(xqc_usec_t wake_after, void *engine_user_data)
{
    (void)wake_after;
    (void)engine_user_data;
    flush_or_defer_wakeups++;
}

void
xqc_test_conn_flush_or_defer(void)
{
    xqc_engine_t *e = make_zero_engine();
    e->eng_callback.set_event_timer = mock_set_event_timer;
    /* Marked running so the immediate branch's xqc_engine_conn_logic()
     * returns at its top instead of driving this half-built connection —
     * the same no-op it performs for a send issued from inside a callback. */
    e->eng_flag |= XQC_ENG_FLAG_RUNNING;

    /* calloc'd log: log_level 0 keeps every xqc_log() on the paths below
     * below its threshold, so nothing is emitted and no formatter runs. */
    xqc_log_t *log = calloc(1, sizeof(*log));
    CU_ASSERT_PTR_NOT_NULL_FATAL(log);

    xqc_connection_t *c = calloc(1, sizeof(*c));
    CU_ASSERT_PTR_NOT_NULL_FATAL(c);
    c->engine = e;
    c->log = log;
    c->conn_flag |= XQC_CONN_FLAG_TICKING;

    /* Deferral off: nothing latches and no wakeup is owed.
     *
     * What this does NOT prove: that the immediate branch actually drives the
     * engine. The engine is marked RUNNING above (it has to be — this conn is
     * a stub), so xqc_engine_conn_logic() returns at its top and leaves no
     * observable trace, which means a helper that simply returned on this
     * branch would satisfy the assertions below too. Pinning the immediate
     * flush needs a real driven connection; that lives in the e2e suite (the
     * UdpGso=false arm, whose batching factor is exactly 1.0000 only because
     * every send still flushes). Here the claim is narrower and honest: the
     * DEFERRED bookkeeping stays untouched when the knob is off. */
    flush_or_defer_wakeups = 0;
    c->conn_settings.defer_send_flush = 0;
    xqc_conn_flush_or_defer(c);
    CU_ASSERT_EQUAL(c->deferred_flush_pending, 0);
    CU_ASSERT_EQUAL(flush_or_defer_wakeups, 0);

    /* Deferral on, conn scheduled: latch and arm exactly one wakeup. */
    c->conn_settings.defer_send_flush = 1;
    xqc_conn_flush_or_defer(c);
    CU_ASSERT_EQUAL(c->deferred_flush_pending, 1);
    CU_ASSERT_EQUAL(flush_or_defer_wakeups, 1);

    /* Further deferred sends in the same run must not re-arm — that is the
     * whole point of the pending flag. Both send kinds share it, so this also
     * covers a run mixing datagram and stream writes. */
    xqc_conn_flush_or_defer(c);
    xqc_conn_flush_or_defer(c);
    CU_ASSERT_EQUAL(c->deferred_flush_pending, 1);
    CU_ASSERT_EQUAL(flush_or_defer_wakeups, 1);

    /* The abnormal branch: XQC_CONN_FLAG_TICKING is clear when the
     * active-queue push failed, so the conn sits in neither engine queue.
     * Deferring there would strand it — nothing would ever run it, and since
     * the pending flag is only cleared by a completed engine run, no later
     * send would re-arm either.
     *
     * Pinned here: with the knob ON but TICKING clear, the helper must NOT
     * take the deferred branch. Same caveat as above — that it instead
     * performs the immediate flush is not observable through a RUNNING
     * engine, so what this rules out is the specific regression of deferring
     * an unscheduled conn, which is the failure that strands a connection
     * until the idle timeout. */
    c->deferred_flush_pending = 0;
    c->conn_flag &= ~XQC_CONN_FLAG_TICKING;
    flush_or_defer_wakeups = 0;
    c->conn_settings.defer_send_flush = 1;
    xqc_conn_flush_or_defer(c);
    CU_ASSERT_EQUAL(c->deferred_flush_pending, 0);
    CU_ASSERT_EQUAL(flush_or_defer_wakeups, 0);

    free(c);
    free(log);
    free(e);
}
