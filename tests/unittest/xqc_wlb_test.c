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
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
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
    uint32_t bandwidth_Bps;
} wlb_mock_cong_t;

static uint64_t
wlb_mock_get_cwnd(void *cong)
{
    return ((wlb_mock_cong_t *)cong)->cwnd_bytes;
}

static uint32_t
wlb_mock_get_bandwidth(void *cong)
{
    return ((wlb_mock_cong_t *)cong)->bandwidth_Bps;
}

static const xqc_cong_ctrl_callback_t WLB_MOCK_CC = {
    .xqc_cong_ctl_get_cwnd = wlb_mock_get_cwnd,
    .xqc_cong_ctl_get_bandwidth_estimate = wlb_mock_get_bandwidth,
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
    f->conn.scheduler = f->scheduler;
    f->conn.scheduler_callback = &xqc_wlb_scheduler_cb;

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
    cs->bandwidth_Bps   = srtt_us > 0
                          ? (uint32_t)((cwnd_bytes * 1000000) / srtt_us)
                          : 1024 * 1024;

    ctl->ctl_path       = p;
    ctl->ctl_conn       = &f->conn;
    ctl->ctl_srtt       = srtt_us;
    ctl->ctl_cong       = cs;
    ctl->ctl_cong_callback = &WLB_MOCK_CC;
    ctl->ctl_bytes_in_flight = inflight_bytes;
    ctl->ctl_delivered_time = g_fake_now_us;

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

/* Like wlb_test_invoke, but lets the caller set po_path_id (the packet's
 * origin path, used by reinjection queries) and the reinject flag. */
static uint64_t
wlb_test_invoke_ex(wlb_test_fixture_t *f, uint32_t flow_hash,
                    uint64_t origin_path_id, int reinject)
{
    xqc_packet_out_t po;
    wlb_test_make_packet_out(&po, flow_hash);
    po.po_path_id = origin_path_id;
    xqc_bool_t cc_blk = XQC_FALSE;
    xqc_path_ctx_t *p = xqc_wlb_scheduler_cb.xqc_scheduler_get_path(
        f->scheduler, &f->conn, &po,
        /* check_cwnd */ 1, reinject, &cc_blk);
    return p ? p->path_id : UINT64_MAX;
}

static uint64_t
wlb_test_invoke_stream(wlb_test_fixture_t *f)
{
    xqc_packet_out_t po;
    wlb_test_make_packet_out(&po, 0);
    po.po_frame_types = XQC_FRAME_BIT_STREAM;
    xqc_bool_t cc_blk = XQC_FALSE;
    xqc_path_ctx_t *p = xqc_wlb_scheduler_cb.xqc_scheduler_get_path(
        f->scheduler, &f->conn, &po,
        /* check_cwnd */ 1, /* reinject */ 0, &cc_blk);
    return p ? p->path_id : UINT64_MAX;
}

/* The WRR driver. STREAM data takes the MinRTT fallback by design, so a test
 * that wants to exercise weighted round robin sends an UNPINNED datagram --
 * same path through the scheduler, minus the flow table. */
static uint64_t
wlb_test_invoke_unpinned(wlb_test_fixture_t *f)
{
    return wlb_test_invoke(f, UINT32_MAX); /* WLB_FLOW_HASH_UNPINNED */
}

static uint64_t
wlb_test_invoke_control(wlb_test_fixture_t *f)
{
    xqc_packet_out_t po;
    wlb_test_make_packet_out(&po, 0);
    po.po_frame_types = XQC_FRAME_BIT_ACK;
    xqc_bool_t cc_blk = XQC_FALSE;
    xqc_path_ctx_t *p = xqc_wlb_scheduler_cb.xqc_scheduler_get_path(
        f->scheduler, &f->conn, &po,
        /* check_cwnd */ 1, /* reinject */ 0, &cc_blk);
    return p ? p->path_id : UINT64_MAX;
}

static void
wlb_test_drain_initial_round(wlb_test_fixture_t *f)
{
    for (int i = 0; i < 100; i++) {
        (void)wlb_test_invoke_unpinned(f);
    }
}

static void
wlb_test_record_acked_packet(wlb_test_fixture_t *f, int path_index,
                             xqc_frame_type_bit_t frame_types,
                             uint64_t acknowledged_bytes,
                             uint64_t app_payload_bytes)
{
    f->send_ctls[path_index].ctl_delivered += acknowledged_bytes;
    f->send_ctls[path_index].ctl_delivered_time = g_fake_now_us;

    xqc_packet_out_t po;
    memset(&po, 0, sizeof(po));
    po.po_frame_types = frame_types;
    po.po_path_id = f->paths[path_index].path_id;
    po.po_used_size = (unsigned int)acknowledged_bytes;
    if (frame_types & XQC_FRAME_BIT_DATAGRAM) {
        po.po_dgram_payload_size = app_payload_bytes;
    }
    if (frame_types & XQC_FRAME_BIT_STREAM) {
        po.po_stream_frames[0].ps_is_used = 1;
        po.po_stream_frames[0].ps_length =
            (unsigned int)app_payload_bytes;
    }
    xqc_send_ctl_on_packet_acked(&f->send_ctls[path_index], &po,
                                 g_fake_now_us, 1);
}

static void
wlb_test_record_delivery(wlb_test_fixture_t *f, int path_index,
                         uint64_t delivered_bytes)
{
    wlb_test_record_acked_packet(f, path_index, XQC_FRAME_BIT_DATAGRAM,
                                 delivered_bytes, delivered_bytes);
}

static void
wlb_test_record_stream_delivery(wlb_test_fixture_t *f, int path_index,
                                uint64_t delivered_bytes)
{
    wlb_test_record_acked_packet(f, path_index, XQC_FRAME_BIT_STREAM,
                                 delivered_bytes, delivered_bytes);
}

static void
wlb_test_record_generated_datagram_delivery(wlb_test_fixture_t *f,
                                             int path_index, int packet_count,
                                             size_t payload_size)
{
    unsigned char payload[XQC_QUIC_MAX_MSS];
    memset(payload, 0xA5, sizeof(payload));
    if (payload_size > sizeof(payload)) {
        CU_FAIL("generated DATAGRAM payload exceeds the packet buffer");
        return;
    }

    for (int i = 0; i < packet_count; i++) {
        xqc_packet_out_t *po = xqc_packet_out_create(XQC_QUIC_MAX_MSS);
        if (po == NULL) {
            CU_FAIL("could not allocate generated DATAGRAM packet");
            return;
        }
        if (xqc_gen_datagram_frame(po, payload, payload_size) != XQC_OK) {
            CU_FAIL("could not generate DATAGRAM frame");
            xqc_packet_out_destroy(po);
            return;
        }
        po->po_path_id = f->paths[path_index].path_id;
        f->send_ctls[path_index].ctl_delivered += po->po_used_size;
        f->send_ctls[path_index].ctl_delivered_time = g_fake_now_us;
        xqc_send_ctl_on_packet_acked(&f->send_ctls[path_index], po,
                                     g_fake_now_us, 1);
        xqc_packet_out_destroy(po);
    }
}

static int
wlb_test_count_unpinned_path(wlb_test_fixture_t *f, uint64_t path_id,
                           int opportunities)
{
    int count = 0;
    for (int i = 0; i < opportunities; i++) {
        if (wlb_test_invoke_unpinned(f) == path_id) {
            count++;
        }
    }
    return count;
}

/* Learned goodput for one path, read back through the stats surface the
 * tests already use. Returns 0 when the path is not in the WRR cache. */
static uint64_t
wlb_test_goodput_of(wlb_test_fixture_t *f, uint64_t path_id)
{
    xqc_wlb_path_stats_t stats[WLB_TEST_MAX_PATHS];
    size_t n = 0;
    if (xqc_wlb_scheduler_copy_path_stats(f->scheduler, stats,
                                          WLB_TEST_MAX_PATHS, &n) != XQC_OK) {
        return 0;
    }
    for (size_t i = 0; i < n && i < WLB_TEST_MAX_PATHS; i++) {
        if (stats[i].path_id == path_id) {
            return stats[i].goodput_Bps;
        }
    }
    return 0;
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

    /* Deliberately lopsided: plain WRR would pin a fresh flow to the wide
     * path 0. With equal weights the assertion below was satisfied either
     * way, so disabling the recovery grace entirely left the test green. */
    xqc_path_ctx_t *p0 = wlb_test_add_path(&f, 0, 10000, 512 * 1024, 0);
    xqc_path_ctx_t *p1 = wlb_test_add_path(&f, 1, 10000, 16 * 1024, 0);
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

/* Reinjection queries must bypass flow pinning. A datagram replica inherits
 * po_flow_hash from its origin via xqc_packet_out_replicate's memcpy, so
 * without routing reinject=1 through wlb_minrtt_fallback, a pinned flow's
 * reinject query would hit the flow table and return the SAME path as
 * po_path_id (the origin) — defeating path diversity for the replica.
 * reinject=1 must exclude the origin path regardless of any existing pin. */
void
xqc_test_wlb_reinject_bypasses_pin(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 10000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 30000, 64 * 1024, 0);

    uint32_t flow = 0x7E17EC70;
    (void)wlb_test_invoke(&f, flow);              /* establishes pin */
    uint64_t pinned = wlb_test_invoke(&f, flow);
    CU_ASSERT_EQUAL(pinned, 0 /* sanity: flow pins to wide path 0 */);

    /* Reinject query for a replica of a packet the origin sent on path 0,
     * same flow_hash as the pinned flow. Must NOT return path 0. */
    uint64_t reinj_path = wlb_test_invoke_ex(&f, flow, /* origin */ 0,
                                              /* reinject */ 1);
    CU_ASSERT_NOT_EQUAL(reinj_path, 0);
    CU_ASSERT_EQUAL(reinj_path, 1 /* only remaining path */);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_stream_data_prefers_lowest_srtt(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0,  20000, 1024 * 1024, 0);   /* 20 ms  */
    wlb_test_add_path(&f, 1, 170000, 1024 * 1024, 0);   /* 170 ms */

    /* A reliable stream is one ordered byte sequence, so while the low-SRTT
     * path has cwnd headroom there is nothing to gain by putting bytes on a
     * path 150 ms further away -- every one of them is a reassembly hole the
     * reader has to wait behind. STREAM data therefore takes the MinRTT
     * fallback, not WRR. Measured before this was pinned down: WRR put 35%
     * of the stream on the slow path here and never backed off, because an
     * under-fed path reads as app-limited and keeps a capacity-proportional
     * weight. */
    int on_slow = 0;
    for (int i = 0; i < 50; i++) {
        if (wlb_test_invoke_stream(&f) == 1) {
            on_slow++;
        }
    }
    CU_ASSERT_EQUAL(on_slow, 0);

    wlb_test_teardown(&f);
}

/**
 * ...and it still aggregates. MinRTT is not "one path only": the cwnd gate
 * counts bytes already scheduled this pass, so once the near path is full the
 * next packet spills to the far one. That is what makes a shaped two-path
 * stream lane reach ~96% of the sum of its legs without any weighting.
 */
void
xqc_test_wlb_stream_data_spills_when_primary_is_full(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    /* Near path cwnd fits exactly two 100-byte packets; far path is wide. */
    wlb_test_add_path(&f, 0,  20000,        250, 0);
    wlb_test_add_path(&f, 1, 170000, 1024 * 1024, 0);

    CU_ASSERT_EQUAL(wlb_test_invoke_stream(&f), 0);
    /* path_schedule_bytes, not bytes_in_flight: this is the counter the send
     * pass accumulates as it assigns packets, and it is what makes the spill
     * happen WITHIN one pass rather than one RTT later. Scope: this covers
     * the scheduler's use of the field. The accumulation itself lives in
     * xqc_path_send_buffer_append, which this fixture never runs -- breaking
     * that += would not fail here. */
    f.paths[0].path_schedule_bytes = 200;

    int on_far = 0;
    for (int i = 0; i < 10; i++) {
        if (wlb_test_invoke_stream(&f) == 1) {
            on_far++;
        }
    }
    CU_ASSERT_EQUAL(on_far, 10);

    /* And it returns as soon as the near path drains. */
    f.paths[0].path_schedule_bytes = 0;
    CU_ASSERT_EQUAL(wlb_test_invoke_stream(&f), 0);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_path_replacement_refreshes_cache(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    xqc_path_ctx_t *old_relay =
        wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);

    (void)wlb_test_invoke_unpinned(&f);
    (void)wlb_test_invoke_unpinned(&f);

    wlb_test_detach_path(old_relay);
    wlb_test_add_path(&f, 2, 25000, 64 * 1024, 0);

    int saw_replacement = 0;
    for (int i = 0; i < 8; i++) {
        if (wlb_test_invoke_unpinned(&f) == 2) {
            saw_replacement = 1;
        }
    }
    CU_ASSERT_TRUE(saw_replacement);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_control_packets_use_minrtt(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 50000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 10000, 64 * 1024, 0);

    CU_ASSERT_EQUAL(wlb_test_invoke_control(&f), 1);
    CU_ASSERT_EQUAL(wlb_test_invoke_control(&f), 1);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_evicted_path_gets_recovery_probe(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    xqc_path_ctx_t *relay = wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(relay);

    /* Evict the relay: blackholed but still ACTIVE. */
    relay->path_send_ctl->ctl_pto_count = 3;

    /* Without probing, an evicted path never carries payload, nothing can
     * ACK on it, and ctl_pto_count can never reset — eviction would be
     * permanent. One probe per interval breaks that deadlock. */
    /* First payload packet arms the probe interval; it must never itself
     * be a probe. */
    CU_ASSERT_EQUAL(wlb_test_invoke(&f, UINT32_MAX), 0);

    int probes = 0;
    int healthy = 0;
    for (int round = 0; round < 4; round++) {
        wlb_test_clock_advance(600000); /* past the 500ms probe interval */
        for (int i = 0; i < 8; i++) {
            uint64_t selected = wlb_test_invoke(&f, UINT32_MAX);
            if (selected == 1) {
                probes++;
            } else if (selected == 0) {
                healthy++;
            }
        }
    }
    CU_ASSERT_EQUAL(probes, 4);      /* exactly one probe per interval */
    CU_ASSERT_EQUAL(healthy, 28);    /* everything else stays on the live path */

    /* The probe got through: the path heals and re-enters scheduling. */
    relay->path_send_ctl->ctl_pto_count = 0;
    int on_relay = 0;
    for (int i = 0; i < 32; i++) {
        if (wlb_test_invoke_unpinned(&f) == 1) {
            on_relay++;
        }
    }
    CU_ASSERT_TRUE(on_relay > 1); /* real share again, not just probes */

    wlb_test_teardown(&f);
}

/**
 * The recovery-probe round robin has to survive a candidate it cannot send
 * on. A blackholed path normally has everything it sent still in flight, so
 * it is exactly the candidate that fails the cwnd check -- and if the cursor
 * does not move past it, it holds the rotation and no other evicted path is
 * ever probed, which is the one thing the round robin exists to prevent.
 */
void
xqc_test_wlb_evicted_probe_rotates_past_blocked_path(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    /* Candidate 0: blackholed AND cwnd-blocked (inflight == cwnd). */
    xqc_path_ctx_t *blocked = wlb_test_add_path(&f, 1, 25000, 1024, 1024);
    /* Candidate 1: blackholed but sendable -- this is the one that can heal. */
    xqc_path_ctx_t *sendable = wlb_test_add_path(&f, 2, 25000, 64 * 1024, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(blocked);
    CU_ASSERT_PTR_NOT_NULL_FATAL(sendable);

    blocked->path_send_ctl->ctl_pto_count = 3;  /* WLB_PTO_EVICT_THRESH */
    sendable->path_send_ctl->ctl_pto_count = 3;  /* WLB_PTO_EVICT_THRESH */

    /* First payload packet only arms the interval. */
    (void)wlb_test_invoke(&f, UINT32_MAX);

    int probed_sendable = 0;
    for (int round = 0; round < 4; round++) {
        wlb_test_clock_advance(600000); /* past the probe interval */
        for (int i = 0; i < 4; i++) {
            if (wlb_test_invoke(&f, UINT32_MAX) == 2) {
                probed_sendable++;
            }
        }
    }
    /* The blocked candidate must not be able to starve this one. */
    CU_ASSERT_TRUE(probed_sendable > 0);

    /* And the probe is still rate limited: it is a recovery mechanism, not a
     * second traffic class. Four intervals cannot yield more than four. */
    CU_ASSERT_TRUE(probed_sendable <= 4);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_stream_data_never_rides_a_blackholed_path(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    xqc_path_ctx_t *relay = wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(relay);
    relay->path_send_ctl->ctl_pto_count = 3;

    CU_ASSERT_EQUAL(wlb_test_invoke_stream(&f), 0); /* arm interval */
    for (int i = 0; i < 4; i++) {
        wlb_test_clock_advance(600000);
        CU_ASSERT_EQUAL(wlb_test_invoke_stream(&f), 0);
    }

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_blackholed_path_does_not_stall_rounds(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    /* path 0 = the healthy direct link, path 1 = the relay that blackholes. */
    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    xqc_path_ctx_t *relay = wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(relay);

    /* Blackholed: still ACTIVE with no socket error, only consecutive PTOs.
     * This is the LAN-relay failure mode -- the phone stops forwarding while
     * the path itself looks alive. */
    /* Mirrors WLB_PTO_EVICT_THRESH, which is private to the scheduler. */
    relay->path_send_ctl->ctl_pto_count = 3;

    for (int i = 0; i < 32; i++) {
        uint64_t selected = wlb_test_invoke_unpinned(&f);
        CU_ASSERT_EQUAL(selected, 0);
    }

    /* The relay recovers. It must re-enter scheduling with a fresh quantum,
     * not with a deficit banked over every round it sat out -- otherwise it
     * monopolises the link and starves the path that stayed healthy. */
    relay->path_send_ctl->ctl_pto_count = 0;

    int on_direct = 0;
    int on_relay = 0;
    for (int i = 0; i < 32; i++) {
        uint64_t selected = wlb_test_invoke_unpinned(&f);
        if (selected == 0) {
            on_direct++;
        } else if (selected == 1) {
            on_relay++;
        }
    }
    CU_ASSERT_TRUE(on_relay > 0);
    CU_ASSERT_TRUE(on_direct > 0);
    CU_ASSERT_TRUE(on_relay <= 20);
    CU_ASSERT_TRUE(on_direct >= 12);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_unpinned_blackhole_refreshes_topology(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    /* Give the relay a larger initial quantum so a stale positive deficit is
     * observable after it silently blackholes and later recovers. */
    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    xqc_path_ctx_t *relay = wlb_test_add_path(&f, 1, 25000, 256 * 1024, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(relay);

    /* Prime the WRR cache while both paths are healthy.  UINT32_MAX is the
     * production sentinel for per-packet, unpinned UDP/QUIC datagrams. */
    (void)wlb_test_invoke(&f, UINT32_MAX);

    relay->path_send_ctl->ctl_pto_count = 3;
    for (int i = 0; i < 32; i++) {
        CU_ASSERT_EQUAL(wlb_test_invoke(&f, UINT32_MAX), 0);
    }

    relay->path_send_ctl->ctl_pto_count = 0;
    int on_direct = 0;
    int on_relay = 0;
    for (int i = 0; i < 32; i++) {
        uint64_t selected = wlb_test_invoke(&f, UINT32_MAX);
        if (selected == 0) {
            on_direct++;
        } else if (selected == 1) {
            on_relay++;
        }
    }
    CU_ASSERT_TRUE(on_direct > 0);
    CU_ASSERT_TRUE(on_relay > 0);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_routine_path_event_preserves_round(void)
{
    wlb_test_fixture_t baseline;
    wlb_test_fixture_t with_events;
    wlb_test_setup(&baseline);
    wlb_test_setup(&with_events);

    wlb_test_add_path(&baseline, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&baseline, 1, 25000, 16 * 1024, 0);
    xqc_path_ctx_t *wide =
        wlb_test_add_path(&with_events, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&with_events, 1, 25000, 16 * 1024, 0);

    int saw_narrow = 0;
    for (int i = 0; i < 16; i++) {
        uint64_t expected = wlb_test_invoke_unpinned(&baseline);
        uint64_t selected = wlb_test_invoke_unpinned(&with_events);
        CU_ASSERT_EQUAL(selected, expected);
        if (selected == 1) {
            saw_narrow = 1;
        }
        xqc_wlb_scheduler_cb.xqc_scheduler_handle_path_event(
            with_events.scheduler, wide, XQC_SCHED_EVENT_PATH_NOT_FULL, NULL);
    }
    CU_ASSERT_TRUE(saw_narrow);

    wlb_test_teardown(&with_events);
    wlb_test_teardown(&baseline);
}

void
xqc_test_wlb_measured_goodput_ignores_loss_penalty(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    xqc_path_ctx_t *lossy = wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(lossy);
    wlb_test_drain_initial_round(&f);

    /* Equal ACKNOWLEDGED delivery on both paths; path 1 additionally shows
     * 6% recent loss (cellular always carries a few percent). Acked goodput
     * is already net of that loss — penalizing it again would starve a
     * lossy-but-delivering link to a third of its measured share. */
    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 1024 * 1024);
    wlb_test_record_delivery(&f, 1, 1024 * 1024);
    lossy->path_send_ctl->ctl_recent_send_count[0] = 100;
    lossy->path_send_ctl->ctl_recent_lost_count[0] = 6;

    int path0_count = wlb_test_count_unpinned_path(&f, 0, 100);
    CU_ASSERT_TRUE(path0_count >= 45 && path0_count <= 55);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_idle_path_goodput_decays(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    /* Both paths deliver equally, then path 1 goes silent while path 0
     * keeps delivering. Under ack-to-ack sampling a silent path produced
     * no sample at all, so its last (possibly burst-inflated) average was
     * frozen and it kept out-weighting the path doing the actual work. A
     * wall-clock sampler emits zero-rate samples for the idle span, so the
     * stale average decays and the working path takes the round. */
    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 1024 * 1024);
    wlb_test_record_delivery(&f, 1, 1024 * 1024);
    (void)wlb_test_count_unpinned_path(&f, 0, 100); /* absorb one round */

    int path0_count = 0;
    for (int round = 0; round < 6; round++) {
        wlb_test_clock_advance(1000000);
        wlb_test_record_delivery(&f, 0, 1024 * 1024);
        path0_count = wlb_test_count_unpinned_path(&f, 0, 100);
    }
    CU_ASSERT_TRUE(path0_count >= 80);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_warmed_zero_goodput_ignores_stale_estimate(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    /* Warm both paths with real delivery, then leave path 1 silent long
     * enough for its measured goodput to decay all the way to zero. Keep a
     * deliberately stale, very large congestion-controller estimate on the
     * silent path: once warmup is over, that estimate must not override the
     * measured zero. The steady exploration floor is the only traffic the
     * path should receive until it delivers again. */
    f.cong_states[1].bandwidth_Bps = 100 * 1024 * 1024;
    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 1024 * 1024);
    wlb_test_record_delivery(&f, 1, 1024 * 1024);
    (void)wlb_test_count_unpinned_path(&f, 0, 100);

    for (int round = 0; round < 120; round++) {
        wlb_test_clock_advance(1000000);
        wlb_test_record_delivery(&f, 0, 1024 * 1024);
        (void)wlb_test_count_unpinned_path(&f, 0, 100);
    }

    int silent_path_count = wlb_test_count_unpinned_path(&f, 1, 100);
    CU_ASSERT_TRUE(silent_path_count >= 5 && silent_path_count <= 6);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_equal_goodput_is_balanced(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 1024 * 1024);
    wlb_test_record_delivery(&f, 1, 1024 * 1024);

    int path0_count = wlb_test_count_unpinned_path(&f, 0, 100);
    CU_ASSERT_TRUE(path0_count >= 45 && path0_count <= 55);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_bloated_path_sheds_weight(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    /* Equal acknowledged goodput on both paths, but path 1 is deeply
     * bufferbloated: 2 s smoothed RTT over a 90 ms floor (a live cellular
     * attach exhibited exactly this). Goodput alone would split the load
     * 50/50 and keep feeding the queue; the bloat haircut must scale
     * path 1 down to 2*min/srtt = 9% of its measured share so the queue
     * can drain. Path 0 sits at 100 ms srtt over the same floor -- inside
     * the 2x operating point, untouched. */
    xqc_path_ctx_t *healthy = wlb_test_add_path(&f, 0, 100000, 64 * 1024, 0);
    xqc_path_ctx_t *bloated = wlb_test_add_path(&f, 1, 2000000, 64 * 1024, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(healthy);
    CU_ASSERT_PTR_NOT_NULL_FATAL(bloated);
    healthy->path_send_ctl->ctl_minrtt = 90000;
    bloated->path_send_ctl->ctl_minrtt = 90000;
    wlb_test_drain_initial_round(&f);

    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 1024 * 1024);
    wlb_test_record_delivery(&f, 1, 1024 * 1024);

    int path0_count = wlb_test_count_unpinned_path(&f, 0, 100);
    CU_ASSERT_TRUE(path0_count >= 80);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_four_to_one_goodput_after_acked_warmup(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 4 * 1024 * 1024);
    wlb_test_record_delivery(&f, 1, 1024 * 1024);

    int path0_count = wlb_test_count_unpinned_path(&f, 0, 100);
    CU_ASSERT_TRUE(path0_count >= 75 && path0_count <= 85);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_new_path_gets_warmup_floor(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 64 * 1024 * 1024);
    (void)wlb_test_invoke_unpinned(&f);

    xqc_wlb_path_stats_t stats[2];
    size_t n = 0;
    CU_ASSERT_EQUAL(xqc_wlb_scheduler_copy_path_stats(
                        f.scheduler, stats, 2, &n),
                    XQC_OK);
    CU_ASSERT_EQUAL(n, 1);
    CU_ASSERT_EQUAL(stats[0].warmup, 0);

    wlb_test_add_path(&f, 1, 25000, 1024, 0);
    (void)wlb_test_invoke_unpinned(&f);
    CU_ASSERT_EQUAL(xqc_wlb_scheduler_copy_path_stats(
                        f.scheduler, stats, 2, &n),
                    XQC_OK);
    CU_ASSERT_EQUAL(n, 2);
    CU_ASSERT_EQUAL(stats[1].warmup, 1);

    int new_path_count = wlb_test_count_unpinned_path(&f, 1, 100);
    CU_ASSERT_TRUE(new_path_count >= 20);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_steady_path_gets_exploration_floor(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 64 * 1024 * 1024);
    wlb_test_record_delivery(&f, 1, 1024 * 1024);

    int slow_path_count = wlb_test_count_unpinned_path(&f, 1, 100);
    CU_ASSERT_TRUE(slow_path_count >= 5);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_active_time_ends_warmup(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    wlb_test_clock_advance(100000);
    wlb_test_record_delivery(&f, 0, 400 * 1024);
    wlb_test_record_delivery(&f, 1, 100 * 1024);
    for (int i = 0; i < 31; i++) {
        wlb_test_clock_advance(100000);
        (void)wlb_test_invoke_unpinned(&f);
    }
    for (int i = 31; i < 100; i++) {
        (void)wlb_test_invoke_unpinned(&f);
    }

    int path0_count = wlb_test_count_unpinned_path(&f, 0, 100);
    CU_ASSERT_TRUE(path0_count >= 75 && path0_count <= 85);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_idle_time_does_not_end_warmup(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    wlb_test_clock_advance(10000000);
    wlb_test_record_delivery(&f, 0, 400 * 1024);
    wlb_test_record_delivery(&f, 1, 100 * 1024);

    int slow_path_count = wlb_test_count_unpinned_path(&f, 1, 100);
    CU_ASSERT_TRUE(slow_path_count >= 27);

    wlb_test_teardown(&f);
}

/**
 * Measured goodput is demand-limited, not a capacity reading: a path handed
 * little delivers little, which would keep it handed little. An under-fed
 * path is app-limited -- it ran out of packets to send, not out of room --
 * so its weight comes from the controller's bandwidth estimate instead. A
 * path that WAS handed work and failed to deliver it is not app-limited and
 * keeps its measured weight.
 */
void
xqc_test_wlb_app_limited_path_is_weighted_by_capacity(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    /* Equal measured delivery, but path 1 has 16x the capacity. */
    wlb_test_add_path(&f, 0, 25000,  16 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 256 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 64 * 1024);
    wlb_test_record_delivery(&f, 1, 64 * 1024);
    f.send_ctls[1].ctl_app_limited = 0;
    int fed = wlb_test_count_unpinned_path(&f, 1, 100);

    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 64 * 1024);
    wlb_test_record_delivery(&f, 1, 64 * 1024);
    f.send_ctls[1].ctl_app_limited = 1;
    int under_fed = wlb_test_count_unpinned_path(&f, 1, 100);

    CU_ASSERT_TRUE(under_fed > fed);

    wlb_test_teardown(&f);
}

/**
 * A goodput sample has to span real wall clock. Timing the inside of an ACK
 * burst reads a path delivering 1 MiB in 50 ms once a second as a 20 MB/s
 * path instead of a 1 MB/s one, and that inflated average then out-weighted
 * the paths doing the actual work.
 */
void
xqc_test_wlb_goodput_sample_ignores_sub_interval_burst(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 64 * 1024);
    wlb_test_record_delivery(&f, 1, 64 * 1024);
    (void)wlb_test_count_unpinned_path(&f, 0, 100);
    uint64_t settled = wlb_test_goodput_of(&f, 0);
    CU_ASSERT_TRUE(settled > 0);

    /* A big delivery, then a refresh only 50 ms later: inside the interval,
     * so nothing may be sampled and the average may not move. */
    wlb_test_clock_advance(50000);
    wlb_test_record_delivery(&f, 0, 8 * 1024 * 1024);
    (void)wlb_test_count_unpinned_path(&f, 0, 100);
    CU_ASSERT_EQUAL(wlb_test_goodput_of(&f, 0), settled);

    /* Past the interval the same bytes are counted, over their real span. */
    wlb_test_clock_advance(300000);
    (void)wlb_test_count_unpinned_path(&f, 0, 100);
    CU_ASSERT_TRUE(wlb_test_goodput_of(&f, 0) > settled);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_path_stats_snapshot(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);
    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 1024 * 1024);
    wlb_test_record_delivery(&f, 1, 1024 * 1024);
    (void)wlb_test_invoke_unpinned(&f);

    xqc_wlb_path_stats_t stats[4];
    memset(stats, 0xA5, sizeof(stats));
    size_t n = 0;
    CU_ASSERT_EQUAL(xqc_wlb_scheduler_copy_path_stats(f.scheduler, stats, 4, &n),
                    XQC_OK);
    CU_ASSERT_EQUAL(n, 2);
    CU_ASSERT_TRUE(stats[0].weight_pct + stats[1].weight_pct >= 100);
    CU_ASSERT_EQUAL(xqc_wlb_scheduler_copy_path_stats(NULL, stats, 4, &n),
                    -XQC_EPARAM);

    /* Truncation: report the full count, write only what fits, leave the
     * caller's remaining slots untouched. */
    memset(stats, 0xA5, sizeof(stats));
    n = 0;
    CU_ASSERT_EQUAL(xqc_wlb_scheduler_copy_path_stats(f.scheduler, stats, 1, &n),
                    XQC_OK);
    CU_ASSERT_EQUAL(n, 2);
    CU_ASSERT_EQUAL(stats[0].path_id, 0);
    CU_ASSERT_EQUAL(stats[1].path_id, UINT64_C(0xA5A5A5A5A5A5A5A5));

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_pinned_flow_refreshes_delivery_sample(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);

    uint32_t flow = 0x12345678;
    CU_ASSERT_EQUAL(wlb_test_invoke(&f, flow), 0);

    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 8 * 1024 * 1024);
    for (int i = 0; i < 100; i++) {
        CU_ASSERT_EQUAL(wlb_test_invoke(&f, flow), 0);
    }

    xqc_wlb_path_stats_t stats[2];
    size_t n = 0;
    CU_ASSERT_EQUAL(xqc_wlb_scheduler_copy_path_stats(
                        f.scheduler, stats, 2, &n),
                    XQC_OK);
    CU_ASSERT_EQUAL(n, 2);
    CU_ASSERT_EQUAL(stats[0].goodput_Bps, 1024 * 1024);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_warmup_time_only_credits_selected_path(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 64 * 1024);
    CU_ASSERT_EQUAL(wlb_test_invoke_unpinned(&f), 0);

    for (int i = 0; i < 31; i++) {
        wlb_test_clock_advance(100000);
        CU_ASSERT_EQUAL(wlb_test_invoke_unpinned(&f), 0);
    }

    xqc_wlb_path_stats_t stats[2];
    size_t n = 0;
    CU_ASSERT_EQUAL(xqc_wlb_scheduler_copy_path_stats(
                        f.scheduler, stats, 2, &n),
                    XQC_OK);
    CU_ASSERT_EQUAL(n, 2);
    CU_ASSERT_EQUAL(stats[0].warmup, 0);
    CU_ASSERT_EQUAL(stats[1].warmup, 1);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_topology_refresh_clears_packet_deficit(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    xqc_path_ctx_t *old_path =
        wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    CU_ASSERT_EQUAL(wlb_test_invoke_unpinned(&f), 0);

    wlb_test_detach_path(old_path);
    wlb_test_add_path(&f, 2, 25000, 64 * 1024, 0);

    CU_ASSERT_EQUAL(wlb_test_invoke_unpinned(&f), 0);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_topology_refresh_clears_pin_deficit(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    xqc_path_ctx_t *old_path =
        wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    (void)wlb_test_invoke(&f, 0x11111111);

    wlb_test_detach_path(old_path);
    wlb_test_add_path(&f, 2, 25000, 64 * 1024, 0);

    uint32_t flow = 0x22222222;
    (void)wlb_test_invoke(&f, flow);
    CU_ASSERT_EQUAL(wlb_test_invoke(&f, flow), 0);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_ewma_uses_exact_seven_eighths_history(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 8 * 1024 * 1024);
    wlb_test_record_delivery(&f, 1, 8 * 1024 * 1024);
    (void)wlb_test_invoke_unpinned(&f);

    xqc_wlb_path_stats_t stats[2];
    size_t n = 0;
    CU_ASSERT_EQUAL(xqc_wlb_scheduler_copy_path_stats(
                        f.scheduler, stats, 2, &n),
                    XQC_OK);
    CU_ASSERT_EQUAL(stats[0].goodput_Bps, 1024 * 1024);

    for (int i = 0; i < 99; i++) {
        (void)wlb_test_invoke_unpinned(&f);
    }
    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 8 * 1024 * 1024);
    wlb_test_record_delivery(&f, 1, 8 * 1024 * 1024);
    (void)wlb_test_invoke_unpinned(&f);

    CU_ASSERT_EQUAL(xqc_wlb_scheduler_copy_path_stats(
                        f.scheduler, stats, 2, &n),
                    XQC_OK);
    CU_ASSERT_EQUAL(stats[0].goodput_Bps, 15 * 1024 * 1024 / 8);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_loss_above_two_percent_downweights_path(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    /* Heavy loss must still visibly shed load even when acked goodput is
     * equal: the gentle (100-loss)% haircut on measured goodput covers a
     * degrading path before the EWMA reflects it. Mild loss (see
     * measured_goodput_ignores_loss_penalty) must NOT be punished twice. */
    f.send_ctls[1].ctl_recent_send_count[0] = 100;
    f.send_ctls[1].ctl_recent_lost_count[0] = 30;
    wlb_test_clock_advance(1000000);
    wlb_test_record_delivery(&f, 0, 8 * 1024 * 1024);
    wlb_test_record_delivery(&f, 1, 8 * 1024 * 1024);

    int path0_count = wlb_test_count_unpinned_path(&f, 0, 100);
    CU_ASSERT_TRUE(path0_count >= 55 && path0_count <= 65);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_control_delivery_does_not_advance_learning(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    /* ctl_delivered includes these validation/handshake bytes. */
    wlb_test_clock_advance(1000000);
    wlb_test_record_acked_packet(
        &f, 0, XQC_FRAME_BIT_PATH_CHALLENGE, 2 * 1024 * 1024, 0);
    wlb_test_record_acked_packet(
        &f, 1, XQC_FRAME_BIT_CRYPTO, 2 * 1024 * 1024, 0);
    (void)wlb_test_invoke_unpinned(&f);

    xqc_wlb_path_stats_t stats[2];
    size_t n = 0;
    CU_ASSERT_EQUAL(xqc_wlb_scheduler_copy_path_stats(
                        f.scheduler, stats, 2, &n),
                    XQC_OK);
    CU_ASSERT_EQUAL(n, 2);
    CU_ASSERT_EQUAL(stats[0].goodput_Bps, 0);
    CU_ASSERT_EQUAL(stats[1].goodput_Bps, 0);
    CU_ASSERT_EQUAL(stats[0].warmup, 1);
    CU_ASSERT_EQUAL(stats[1].warmup, 1);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_application_delivery_advances_learning(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    wlb_test_clock_advance(1000000);
    wlb_test_record_stream_delivery(&f, 0, 8 * 1024 * 1024);
    wlb_test_record_generated_datagram_delivery(&f, 1, 1049, 1000);
    (void)wlb_test_invoke_unpinned(&f);

    xqc_wlb_path_stats_t stats[2];
    size_t n = 0;
    CU_ASSERT_EQUAL(xqc_wlb_scheduler_copy_path_stats(
                        f.scheduler, stats, 2, &n),
                    XQC_OK);
    CU_ASSERT_EQUAL(n, 2);
    CU_ASSERT_EQUAL(stats[0].goodput_Bps, 1024 * 1024);
    CU_ASSERT_EQUAL(stats[1].goodput_Bps, 1049000 / 8);
    CU_ASSERT_EQUAL(stats[0].warmup, 0);
    CU_ASSERT_EQUAL(stats[1].warmup, 0);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_rejected_0rtt_does_not_advance_learning(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    wlb_test_clock_advance(1000000);
    xqc_packet_out_t rejected;
    memset(&rejected, 0, sizeof(rejected));
    rejected.po_pkt.pkt_type = XQC_PTYPE_0RTT;
    rejected.po_frame_types = XQC_FRAME_BIT_DATAGRAM;
    rejected.po_path_id = 0;
    rejected.po_dgram_payload_size = 2 * 1024 * 1024;
    xqc_conn_decrease_unacked_stream_ref(&f.conn, &rejected);
    (void)wlb_test_invoke_unpinned(&f);

    xqc_wlb_path_stats_t stats[2];
    size_t n = 0;
    CU_ASSERT_EQUAL(xqc_wlb_scheduler_copy_path_stats(
                        f.scheduler, stats, 2, &n),
                    XQC_OK);
    CU_ASSERT_EQUAL(n, 2);
    CU_ASSERT_EQUAL(stats[0].goodput_Bps, 0);
    CU_ASSERT_EQUAL(stats[0].warmup, 1);

    wlb_test_teardown(&f);
}

void
xqc_test_wlb_duplicate_ack_counts_application_once(void)
{
    wlb_test_fixture_t f;
    wlb_test_setup(&f);

    wlb_test_add_path(&f, 0, 25000, 64 * 1024, 0);
    wlb_test_add_path(&f, 1, 25000, 64 * 1024, 0);
    wlb_test_drain_initial_round(&f);

    wlb_test_clock_advance(1000000);
    xqc_packet_out_t acked;
    memset(&acked, 0, sizeof(acked));
    acked.po_frame_types = XQC_FRAME_BIT_DATAGRAM;
    acked.po_path_id = 0;
    acked.po_dgram_payload_size = 8 * 1024 * 1024;
    xqc_send_ctl_on_packet_acked(&f.send_ctls[0], &acked,
                                 g_fake_now_us, 1);
    xqc_send_ctl_on_packet_acked(&f.send_ctls[0], &acked,
                                 g_fake_now_us, 1);
    (void)wlb_test_invoke_unpinned(&f);

    xqc_wlb_path_stats_t stats[2];
    size_t n = 0;
    CU_ASSERT_EQUAL(xqc_wlb_scheduler_copy_path_stats(
                        f.scheduler, stats, 2, &n),
                    XQC_OK);
    CU_ASSERT_EQUAL(n, 2);
    CU_ASSERT_EQUAL(stats[0].goodput_Bps, 1024 * 1024);
    CU_ASSERT_EQUAL(stats[0].warmup, 0);

    wlb_test_teardown(&f);
}
