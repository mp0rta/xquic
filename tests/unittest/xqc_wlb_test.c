/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WLB scheduler invariant tests.
 *
 * These tests exercise the public scheduler callback table
 * (xqc_wlb_scheduler_cb) against a minimal hand-built connection +
 * path-context fixture. The cong-control callback table is mocked so each
 * path's cwnd / inflight can be set independently. SRTT is poked directly
 * into the per-path send_ctl. xqc_monotonic_timestamp is replaced with a
 * fake clock so wlb_flow_expire (gated at 1/sec) can be driven step by
 * step without sleeping.
 *
 * Pin direction is read INDIRECTLY: after invoking the scheduler once to
 * establish a pin for a flow, a second invocation with the same flow hash
 * goes through wlb_flow_lookup and returns the pinned path. We only assert
 * on path_id; we never reach into the scheduler's internal flow table.
 */

#include <CUnit/CUnit.h>
#include <stdlib.h>
#include <string.h>

#include "xquic/xquic.h"
#include "xquic/xquic_typedef.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/scheduler/xqc_scheduler_wlb.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_time.h"

#include "xqc_wlb_test.h"

/* ───────────────────────── fake clock ───────────────────────── */

static xqc_usec_t g_fake_now_us = 1000000;  /* start at 1s so non-zero */

static xqc_usec_t
wlb_test_fake_now(void)
{
    return g_fake_now_us;
}

static void
wlb_test_clock_advance(xqc_usec_t delta_us)
{
    g_fake_now_us += delta_us;
}

/* ───────────────────────── mocked CC callback ───────────────────────── */

typedef struct {
    uint64_t cwnd_bytes;
} wlb_mock_cong_t;

static uint64_t
wlb_mock_get_cwnd(void *cong)
{
    return ((wlb_mock_cong_t *)cong)->cwnd_bytes;
}

static const xqc_cong_ctrl_callback_t WLB_MOCK_CC = {
    .xqc_cong_ctl_get_cwnd = wlb_mock_get_cwnd,
    /* other callbacks unused by the WLB scheduler path */
};

/* ───────────────────────── fixture ───────────────────────── */

#define WLB_TEST_MAX_PATHS 4

typedef struct {
    xqc_connection_t      conn;
    xqc_log_t             log;

    /* path state, owned here so callers can mutate freely between invocations */
    xqc_path_ctx_t        paths[WLB_TEST_MAX_PATHS];
    xqc_send_ctl_t        send_ctls[WLB_TEST_MAX_PATHS];
    wlb_mock_cong_t       cong_states[WLB_TEST_MAX_PATHS];
    int                   n_paths_owned;

    /* scheduler state — opaque heap blob sized by xqc_scheduler_size */
    void                 *scheduler;

    /* saved global clock pointer so we can restore on teardown */
    xqc_timestamp_pt      saved_monotonic_ts;
} wlb_test_fixture_t;

static void
wlb_test_setup(wlb_test_fixture_t *f)
{
    memset(f, 0, sizeof(*f));

    f->log.log_level = XQC_LOG_FATAL;  /* suppress per-test noise */
    f->conn.log = &f->log;
    xqc_init_list_head(&f->conn.conn_paths_list);

    /* Allocate scheduler state and init through the public vtable so the
     * test exercises exactly the production code path. */
    size_t sz = xqc_wlb_scheduler_cb.xqc_scheduler_size();
    f->scheduler = calloc(1, sz);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f->scheduler);
    xqc_wlb_scheduler_cb.xqc_scheduler_init(f->scheduler, &f->log, NULL);

    /* Install fake clock so wlb_flow_expire's 1/sec throttle and recovery
     * grace window are deterministic. */
    f->saved_monotonic_ts = xqc_monotonic_timestamp;
    xqc_monotonic_timestamp = wlb_test_fake_now;
    g_fake_now_us = 1000000;
}

static void
wlb_test_teardown(wlb_test_fixture_t *f)
{
    xqc_monotonic_timestamp = f->saved_monotonic_ts;
    if (f->scheduler) {
        free(f->scheduler);
        f->scheduler = NULL;
    }
}

/* Attach a new path to the connection. Defaults the path to ACTIVE with the
 * given SRTT and a cwnd big enough to never block — set inflight separately
 * to simulate cwnd-block. */
static xqc_path_ctx_t *
wlb_test_add_path(wlb_test_fixture_t *f, uint64_t path_id, xqc_usec_t srtt_us,
                  uint64_t cwnd_bytes, uint32_t inflight_bytes)
{
    /* Non-fatal so an overflow doesn't abort the test mid-flight and leak
     * the fake-clock global override into subsequent test cases.
     * WLB_TEST_MAX_PATHS is high enough that this is purely defensive. */
    CU_ASSERT(f->n_paths_owned < WLB_TEST_MAX_PATHS);
    if (f->n_paths_owned >= WLB_TEST_MAX_PATHS) {
        return NULL;
    }
    int i = f->n_paths_owned++;

    xqc_path_ctx_t        *p   = &f->paths[i];
    xqc_send_ctl_t        *ctl = &f->send_ctls[i];
    wlb_mock_cong_t       *cs  = &f->cong_states[i];

    memset(p, 0, sizeof(*p));
    memset(ctl, 0, sizeof(*ctl));
    memset(cs, 0, sizeof(*cs));

    p->path_id          = path_id;
    p->path_state       = XQC_PATH_STATE_ACTIVE;
    p->app_path_status  = XQC_APP_PATH_STATUS_AVAILABLE;
    p->path_send_ctl    = ctl;

    cs->cwnd_bytes      = cwnd_bytes;

    ctl->ctl_path       = p;
    ctl->ctl_conn       = &f->conn;
    ctl->ctl_srtt       = srtt_us;
    ctl->ctl_cong       = cs;
    ctl->ctl_cong_callback = &WLB_MOCK_CC;
    ctl->ctl_bytes_in_flight = inflight_bytes;

    xqc_list_add_tail(&p->path_list, &f->conn.conn_paths_list);
    return p;
}

/* Detach a previously-added path (simulates path failover by removing it
 * from conn->conn_paths_list). The struct keeps existing so a later
 * wlb_test_reattach_path can re-insert it with the same path_id, exercising
 * the "path went down then came back" recovery case. */
static void
wlb_test_detach_path(xqc_path_ctx_t *p)
{
    xqc_list_del_init(&p->path_list);
}

static void
wlb_test_reattach_path(wlb_test_fixture_t *f, xqc_path_ctx_t *p)
{
    xqc_list_add_tail(&p->path_list, &f->conn.conn_paths_list);
}

/* Build a minimal in-flight-bearing datagram packet_out. */
static void
wlb_test_make_packet_out(xqc_packet_out_t *po, uint32_t flow_hash)
{
    memset(po, 0, sizeof(*po));
    po->po_flow_hash   = flow_hash;
    /* DATAGRAM bit is "can be in flight" so xqc_send_packet_cwnd_allows
     * actually runs the cwnd check — this makes inflight-vs-cwnd
     * comparisons in the fixture meaningful. */
    po->po_frame_types = XQC_FRAME_BIT_DATAGRAM;
    po->po_used_size   = 100;
}

/* Drive one scheduler call and return the selected path_id (or UINT64_MAX
 * if scheduler returned NULL). */
static uint64_t
wlb_test_invoke(wlb_test_fixture_t *f, uint32_t flow_hash)
{
    xqc_packet_out_t po;
    wlb_test_make_packet_out(&po, flow_hash);
    xqc_bool_t cc_blk = XQC_FALSE;
    xqc_path_ctx_t *p = xqc_wlb_scheduler_cb.xqc_scheduler_get_path(
        f->scheduler, &f->conn, &po,
        /* check_cwnd */ 1, /* reinject */ 0, &cc_blk);
    return p ? p->path_id : UINT64_MAX;
}

/* ───────────────────────── tests ───────────────────────── */

/* I1: asymmetric paths, single TCP flow → pin lands on wide path.
 *     The first scheduler call sends; the second hits the flow table and
 *     returns the pinned path → that's what we assert on. */
void
xqc_test_wlb_asym_p1_pin_to_wide(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    /* path 0 = wide  (300 Mbit/10ms BDP-ish cwnd 64 KB) */
    wlb_test_add_path(&f, 0, /* srtt */ 10000, /* cwnd */ 64 * 1024, /* inflight */ 0);
    /* path 1 = narrow (80 Mbit/30ms BDP-ish cwnd 16 KB) */
    wlb_test_add_path(&f, 1, /* srtt */ 30000, /* cwnd */ 16 * 1024, /* inflight */ 0);

    uint32_t flow = 0xDEADBEEF;
    (void)wlb_test_invoke(&f, flow);            /* establishes pin */
    uint64_t pinned = wlb_test_invoke(&f, flow); /* flow-table hit */

    CU_ASSERT_EQUAL(pinned, 0 /* wide */);

    wlb_test_teardown(&f);
}

/* I1+I3: at the moment of first pin the wide path is cwnd-blocked. The
 * scheduler must still pin to the wide path — the soft-pin contract says
 * cwnd state is a transient send-side concern, not a routing decision. */
void
xqc_test_wlb_asym_p1_pin_to_wide_when_wide_blocked(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    /* Wide is "blocked" right now: inflight > cwnd by more than po_used_size. */
    wlb_test_add_path(&f, 0, 10000, /* cwnd */ 16 * 1024,
                            /* inflight */ 16 * 1024);
    /* Narrow has full cwnd headroom. */
    wlb_test_add_path(&f, 1, 30000, /* cwnd */ 16 * 1024, /* inflight */ 0);

    uint32_t flow = 0xCAFEBABE;
    uint64_t first_send = wlb_test_invoke(&f, flow);
    /* Sanity: this packet must go somewhere; with wide blocked WRR picks
     * narrow. */
    CU_ASSERT_EQUAL(first_send, 1 /* narrow, sendable */);

    /* Unblock wide and re-invoke for the same flow. flow_lookup hits the
     * pin; if the pin landed on narrow (the cwnd-skipped-wide bug) this
     * returns narrow even though wide is now the obvious choice. */
    f.send_ctls[0].ctl_bytes_in_flight = 0;

    uint64_t pinned = wlb_test_invoke(&f, flow);
    CU_ASSERT_EQUAL(pinned, 0 /* wide — pin survived the transient block */);

    wlb_test_teardown(&f);
}

/* I3: once the pin is on a path, transient cwnd-block of that path causes
 * a spillover to another path WITHOUT updating the flow table; when the
 * pin path is sendable again the flow returns to it. */
void
xqc_test_wlb_soft_pin_no_repin_on_block(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 10000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 30000, 64 * 1024, 0);

    uint32_t flow = 0xA1B2C3D4;
    (void)wlb_test_invoke(&f, flow);              /* pin to wide */
    uint64_t base = wlb_test_invoke(&f, flow);
    CU_ASSERT_EQUAL(base, 0);

    /* Block wide. Next packet on this flow must spill to narrow without
     * re-pinning. */
    f.send_ctls[0].ctl_bytes_in_flight = 64 * 1024;
    uint64_t spill = wlb_test_invoke(&f, flow);
    CU_ASSERT_EQUAL(spill, 1 /* narrow — temporary spillover */);

    /* Unblock wide. Pin must still be wide; next packet returns there. */
    f.send_ctls[0].ctl_bytes_in_flight = 0;
    uint64_t back = wlb_test_invoke(&f, flow);
    CU_ASSERT_EQUAL(back, 0 /* wide — pin unchanged after spillover */);

    wlb_test_teardown(&f);
}

/* I2: with multiple flows across equal-weight paths, pins must distribute
 * across paths (no convergence). */
void
xqc_test_wlb_sym_multiflow_distributes(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    /* Two identical paths. */
    wlb_test_add_path(&f, 0, 10000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 10000, 64 * 1024, 0);

    int on_path0 = 0, on_path1 = 0;
    /* 8 distinct flows; with quantum 1:1 we expect a 4/4 split. */
    for (int i = 0; i < 8; i++) {
        uint32_t flow = 0x10000000u + (uint32_t)i;
        (void)wlb_test_invoke(&f, flow);            /* establish pin */
        uint64_t pinned = wlb_test_invoke(&f, flow); /* read pin */
        if (pinned == 0)      on_path0++;
        else if (pinned == 1) on_path1++;
    }

    /* Both paths must have picked up at least one flow. Asserting balance
     * exactly would over-constrain tie-break behaviour; the regression we
     * care about is "all 8 collapse onto paths[0]". */
    CU_ASSERT_TRUE(on_path0 > 0);
    CU_ASSERT_TRUE(on_path1 > 0);

    wlb_test_teardown(&f);
}

/* Initial 2nd-path-up scenario: secondary path joins after the first flow
 * has already been pinned. The "newly appeared path = recovery" heuristic
 * is supposed to fire only after a previously-seen path went down and came
 * back; here no path has ever been lost. The bug surfaces when a NEW flow
 * arrives during the 1 s recovery_unpin grace window the broken heuristic
 * opens on the same call as the path-add expire — that new flow then pins
 * to the just-added (narrow) path even though WRR would have picked the
 * wide path on weight. */
void
xqc_test_wlb_recovery_prefer_skips_initial_path_addition(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    /* Only path 0 (wide) up at handshake time. */
    wlb_test_add_path(&f, 0, 10000, 64 * 1024, 0);

    uint32_t flow_pre = 0x11112222;
    (void)wlb_test_invoke(&f, flow_pre);
    CU_ASSERT_EQUAL(wlb_test_invoke(&f, flow_pre), 0);

    /* Secondary (narrow) path appears later. */
    wlb_test_add_path(&f, 1, 30000, 16 * 1024, 0);
    wlb_test_clock_advance(1100000);  /* unblock 1/sec expire throttle */

    /* Triggers the path-add expire sweep: pre-fix, this latches
     * recovery_unpin_until_us = now + 1 s and recovery_prefer_path_id = 1
     * (the bug). The in_recovery_grace flag itself is sampled BEFORE the
     * expire on this same call, so this invocation doesn't yet use
     * recovery_prefer — that branch only fires for SUBSEQUENT calls inside
     * the grace window. The pre-existing flow's pin is also tombstoned by
     * the same expire sweep, but the WRR fall-through on this same call
     * re-pins it (still wide, max-deficit) so flow_pre survives in
     * principle. We assert that below. */
    (void)wlb_test_invoke(&f, flow_pre);

    /* The pre-existing flow's pin must survive a spurious expire sweep.
     * Pre-fix tombstones it; the on-this-call WRR re-pin lands it back on
     * the wide path. Asserting both halves makes the regression scope
     * (existing pins + new flows) explicit. */
    CU_ASSERT_EQUAL(wlb_test_invoke(&f, flow_pre), 0 /* wide */);

    /* Within the would-be grace: a brand-new flow's first packet. Pre-fix
     * code finds in_recovery_grace=TRUE and pins this flow to path 1
     * unconditionally; the documented behaviour is that an initial path
     * addition is NOT a recovery event, so this flow should pin to the
     * wide path (max LATE weight) via the normal WRR branch. */
    uint32_t flow_new = 0xAAAA1111;
    uint64_t pin_new = wlb_test_invoke(&f, flow_new);
    CU_ASSERT_EQUAL(pin_new, 0 /* wide; spurious recovery_prefer ⇒ 1 */);

    wlb_test_teardown(&f);
}

/* Real failover scenario: both paths up, flow pinned. Path 1 disappears
 * (e.g. socket error), then comes back. The recovery-prefer heuristic IS
 * supposed to fire on this second appearance — a new flow arriving while
 * the grace window is open pins to the recovered path so traffic can use
 * the restored capacity instead of piling onto the surviving path. */
void
xqc_test_wlb_recovery_prefer_fires_after_real_failover(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    xqc_path_ctx_t *p0 = wlb_test_add_path(&f, 0, 10000, 64 * 1024, 0);
    xqc_path_ctx_t *p1 = wlb_test_add_path(&f, 1, 10000, 64 * 1024, 0);
    (void)p0;

    uint32_t flow = 0x33334444;
    (void)wlb_test_invoke(&f, flow);
    (void)wlb_test_invoke(&f, flow);

    /* Path 1 disappears. The next expire sweep observes a previously-
     * seen path missing and latches ever_lost_path. */
    wlb_test_detach_path(p1);
    wlb_test_clock_advance(1100000);
    (void)wlb_test_invoke(&f, flow);

    /* Path 1 comes back. The expire sweep on the next call sees a new
     * path appear with ever_lost_path latched → has_new_path TRUE,
     * recovery_unpin_until_us set, recovery_prefer_path_id = 1. */
    wlb_test_reattach_path(&f, p1);
    wlb_test_clock_advance(1100000);
    (void)wlb_test_invoke(&f, flow);  /* arms the grace window */

    /* Within the grace: a brand-new flow lands. flow_lookup misses,
     * in_recovery_grace=TRUE, recovery_prefer_path_id=1 → pin to
     * recovered path 1. This is the documented recovery behaviour. */
    uint32_t fresh = 0x55556666;
    uint64_t pin_after_recovery = wlb_test_invoke(&f, fresh);
    CU_ASSERT_EQUAL(pin_after_recovery, 1 /* recovered path */);

    wlb_test_teardown(&f);
}

/* rev6: the n_paths==1 fast path must NOT pin the flow — otherwise when a
 * secondary path appears later, the flow is stuck on paths[0] forever
 * (Fix A prevents the wipe that would otherwise rescue it).
 *
 * Strategy: drive one flow through the scheduler while only path 0 exists,
 * then attach path 1, advance the clock past the 1/sec flow_expire throttle
 * so wlb_flow_expire's path-count-increase detector fires (Edit B:
 * force_refresh_paths is now decoupled from ever_lost_path), then issue
 * new flows and confirm pin distribution — proving that pick_pin's
 * max-deficit alternation is engaging and nothing got permanently
 * anchored to paths[0]. */
void
xqc_test_wlb_single_path_does_not_pin(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    /* Only ONE path — n_paths==1 fast path will fire. */
    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);

    /* First call: fast path returns paths[0]. With Edit A, NO pin is
     * inserted. */
    uint32_t early_flow = 0xABCDEF01;
    uint64_t early_pick = wlb_test_invoke(&f, early_flow);
    CU_ASSERT_EQUAL(early_pick, 0);

    /* Add the secondary path. Advance the clock past the 1/sec
     * flow_expire throttle so the next invoke triggers the expire
     * sweep, which (per Edit B) detects path_count_increased and
     * sets force_refresh_paths = 1 → wlb_refresh_paths runs →
     * s->n_paths becomes 2 → the n_paths==1 fast path no longer
     * fires; subsequent flows go through pick_pin's max-deficit
     * branch. With two equal-weight paths the wrr_select decrement
     * + pick_pin pairing naturally alternates flows across paths. */
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_clock_advance(1100000);

    /* Issue a batch of NEW flows. With two equal paths, wrr_select
     * decrements one deficit per packet → pick_pin sees the other path
     * as max → flows alternate. We assert both paths receive flows —
     * proving (a) the n_paths==1 anchor was not set on early_flow (it
     * wasn't — but we can't distinguish that from here); (b) more
     * importantly, that max-deficit alternation is firing after the
     * secondary path becomes visible. */
    int seen_p0 = 0, seen_p1 = 0;
    for (int i = 0; i < 8; i++) {
        uint32_t flow = 0x30000000u + (uint32_t)i;
        (void)wlb_test_invoke(&f, flow);             /* establish pin */
        uint64_t pinned = wlb_test_invoke(&f, flow); /* read pin */
        if (pinned == 0)      seen_p0++;
        else if (pinned == 1) seen_p1++;
    }
    CU_ASSERT_TRUE(seen_p1 > 0);  /* alternation active after path 1 visible */
    CU_ASSERT_TRUE(seen_p0 > 0);  /* not all on path 1 either */

    wlb_test_teardown(&f);
}

/* Root cause (WLB_INSTR-confirmed): the scheduler detects a newly-active
 * secondary path ONLY inside wlb_flow_expire(), which is throttled to run at
 * most once per second. If the path appears just after an expire() run, its
 * entry into s->paths is delayed up to ~1s — long enough for the primary to
 * warm its cwnd and capture every flow pin (sym P=16 collapse: 17/0 split).
 *
 * This test pins down the fix contract: after the secondary becomes active,
 * new flows must distribute across BOTH paths WITHOUT first advancing the
 * clock past the 1/sec throttle. It differs from single_path_does_not_pin
 * precisely in that it does NOT call wlb_test_clock_advance(1.1s) — so the
 * old code (which only notices the new path via the throttled expire) leaves
 * n_paths==1, the single-path fast path returns paths[0] for every flow, and
 * nothing distributes. */
void
xqc_test_wlb_new_path_detected_without_expire_throttle(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    /* Only path 0 up at handshake. Drive one flow so the scheduler settles
     * into its n_paths==1 state (first expire records a single healthy
     * path and latches last_expire_ts). */
    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    uint32_t warmup = 0x0BADF00D;
    CU_ASSERT_EQUAL(wlb_test_invoke(&f, warmup), 0);

    /* Secondary path becomes active ~100ms later — still WELL within the
     * 1/sec expire throttle window (last_expire_ts was just set). The old
     * code cannot see it until the throttle elapses. */
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_clock_advance(100000);  /* 100ms — deliberately < 1s throttle */

    /* New flows must reach the WRR/pick_pin path and distribute across both
     * paths. Pre-fix: n_paths stays 1, all flows return paths[0]. */
    int seen_p0 = 0, seen_p1 = 0;
    for (int i = 0; i < 8; i++) {
        uint32_t flow = 0x40000000u + (uint32_t)i;
        (void)wlb_test_invoke(&f, flow);             /* establish pin */
        uint64_t pinned = wlb_test_invoke(&f, flow); /* read pin */
        if (pinned == 0)      seen_p0++;
        else if (pinned == 1) seen_p1++;
    }

    CU_ASSERT_TRUE(seen_p1 > 0);  /* secondary detected promptly, gets flows */
    CU_ASSERT_TRUE(seen_p0 > 0);  /* primary still used too */

    wlb_test_teardown(&f);
}
