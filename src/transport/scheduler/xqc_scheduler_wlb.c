/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WLB (Weighted Load Balancing) multipath scheduler for QUIC Datagrams.
 *
 * Key difference from MinRTT: packets belonging to the same inner flow
 * (identified by po_flow_hash) are pinned to the same QUIC path.  This
 * prevents TCP reordering inside VPN tunnels while still aggregating
 * bandwidth across paths via weighted round-robin of flows.
 *
 * Algorithm:
 *   1. Compute real-time weights for all active paths using an iterative
 *      LATE model (Yang 2021) simplified for unreliable datagrams:
 *      no FR/RTO categories, expected-value cwnd update per round.
 *   2. Distribute packets via OLB round-based WRR (deficit counter).
 *   3. Pin inner flows to paths via hash table to prevent TCP reordering.
 *   4. If no path can send (all cwnd-blocked), fall back to MinRTT.
 *
 * Soft pinning (cwnd-blocked spillover):
 *   When a flow's pinned path is temporarily cwnd-blocked, the packet is
 *   sent on another path via WRR WITHOUT updating the flow table.  The
 *   flow remains pinned to the original path and returns to it once cwnd
 *   headroom is available.
 *
 *   This "soft pin" trades occasional TCP reordering (caused by RTT
 *   disparity between the pinned path and the spillover path) for two
 *   critical benefits:
 *     - Avoids flow oscillation: strict re-pinning caused flows to get
 *       stuck on a slower path after transient cwnd saturation on the
 *       fast path, degrading throughput by ~20% with few TCP streams.
 *     - Preserves loss resilience: unlike the alternative of blocking
 *       sends until the pinned path's cwnd opens, soft pin keeps packets
 *       flowing during loss events where a path may be blocked for
 *       extended periods.
 *
 *   Measured impact: ~4% throughput overhead with 1 TCP stream over
 *   asymmetric paths (300Mbit/10ms + 80Mbit/30ms) vs single-path.
 *   With 8+ streams the overhead disappears and aggregation gains
 *   dominate (+15-23%).
 *
 * References:
 *   - OLB: "Optimal Load Balancing", Computer Communications, 2017
 *   - LATE: "Loss-Aware Throughput Estimation", IEEE TWC, 2021
 */

#include "src/transport/scheduler/xqc_scheduler_wlb.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_multipath.h"
#include "src/common/xqc_time.h"

/* ---------- constants ---------- */

#define WLB_MAX_PATHS         XQC_MAX_PATHS_COUNT
#define LATE_MSS              1200    /* typical QUIC datagram payload bytes */

/* Flow table — open-addressing hash table for flow-to-path pinning */
#define WLB_FLOW_TABLE_SIZE   4096
#define WLB_FLOW_TABLE_MASK   (WLB_FLOW_TABLE_SIZE - 1)
#define WLB_MAX_PROBE         16      /* linear probe limit */
#define WLB_FLOW_EXPIRE_US    (60ULL * 1000000)  /* 60 s idle expiry */
#define WLB_LOSS_EVICT_THRESH 0.02  /* evict flows from paths with loss >= 2% (BBR2+ aligned) */
#define WLB_PTO_EVICT_THRESH  3    /* evict flows from paths with >= 3 consecutive PTOs (~500ms) */
#define WLB_RECOVERY_UNPIN_GRACE_US (1000ULL * 1000) /* 1s temporary unpin after path recovery */
#define WLB_NO_PATH_ID UINT64_MAX

/*
 * Tombstone marker for deleted flow table entries.
 * Using 0xFFFFFFFF which equals WLB_FLOW_HASH_UNPINNED — safe because
 * unpinned packets never enter the flow table (pin_flow == false).
 *
 * Semantics:  hash == 0          → empty slot (end of probe chain)
 *             hash == TOMBSTONE  → deleted slot (continue probing)
 *             hash == other      → valid entry
 */
#define WLB_FLOW_TOMBSTONE    0xFFFFFFFFU

/* ---------- data types ---------- */

/** Flow table entry — maps an inner-flow hash to a QUIC path. */
typedef struct {
    uint32_t    hash;       /* 0 = empty slot */
    uint64_t    path_id;
    uint64_t    last_ts;    /* last-used timestamp (usec) */
} wlb_flow_entry_t;

/** Per-path WRR state. */
typedef struct {
    uint64_t    path_id;
    uint64_t    weight;     /* LATE estimated throughput (scaled ×1000) */
    int64_t     deficit;    /* WRR deficit counter */
} wlb_path_weight_t;

/** Top-level scheduler state, allocated by xquic via xqc_wlb_scheduler_size(). */
typedef struct {
    wlb_path_weight_t   paths[WLB_MAX_PATHS];
    int                  n_paths;
    wlb_flow_entry_t     flows[WLB_FLOW_TABLE_SIZE];
    uint64_t             last_expire_ts;  /* throttle expire scans to 1/sec */
    int                  last_healthy_paths; /* for recovery-triggered rebalance */
    uint64_t             last_healthy_path_ids[WLB_MAX_PATHS];
    int                  last_healthy_path_ids_n;
    int                  force_refresh_paths; /* refresh WRR cache on recovery */
    uint64_t             recovery_unpin_until_us; /* temporarily disable TCP pinning after recovery */
    uint64_t             recovery_prefer_path_id; /* newly recovered path to prefer for first re-pin */
    xqc_log_t           *log;
} xqc_wlb_scheduler_t;

/* Forward declaration — used by wlb_flow_expire() for loss-triggered eviction */
static xqc_path_ctx_t *wlb_find_path_ctx(xqc_connection_t *conn, uint64_t path_id);

/* ================================================================
 *  Flow table helpers
 *
 *  Open-addressing hash table with linear probing.  Entries expire
 *  after WLB_FLOW_EXPIRE_US of inactivity (scanned at most once/sec).
 * ================================================================ */

/**
 * Look up a flow by its hash.
 * Returns the matching entry, or NULL if not found within the probe window.
 */
static wlb_flow_entry_t *
wlb_flow_lookup(xqc_wlb_scheduler_t *s, uint32_t hash)
{
    if (hash == 0) {
        return NULL;
    }
    uint32_t idx = hash & WLB_FLOW_TABLE_MASK;
    for (int i = 0; i < WLB_MAX_PROBE; i++) {
        wlb_flow_entry_t *e = &s->flows[(idx + i) & WLB_FLOW_TABLE_MASK];
        if (e->hash == hash) {
            return e;
        }
        if (e->hash == 0) {
            return NULL;
        }
    }
    return NULL;
}

/**
 * Insert or update a flow→path mapping.
 * Reuses tombstone slots left by eviction.
 * On probe-region exhaustion, overwrites the first slot (LRU-ish eviction).
 */
static void
wlb_flow_insert(xqc_wlb_scheduler_t *s, uint32_t hash, uint64_t path_id, uint64_t now_us)
{
    if (hash == 0) {
        return;
    }
    uint32_t idx = hash & WLB_FLOW_TABLE_MASK;
    for (int i = 0; i < WLB_MAX_PROBE; i++) {
        wlb_flow_entry_t *e = &s->flows[(idx + i) & WLB_FLOW_TABLE_MASK];
        if (e->hash == 0 || e->hash == WLB_FLOW_TOMBSTONE || e->hash == hash) {
            e->hash    = hash;
            e->path_id = path_id;
            e->last_ts = now_us;
            return;
        }
    }
    /* Probe region full — overwrite first slot */
    wlb_flow_entry_t *e = &s->flows[idx];
    e->hash    = hash;
    e->path_id = path_id;
    e->last_ts = now_us;
}

/**
 * Expire idle flow entries and evict flows from lossy or dead paths.
 *
 * Scans the full table at most once per second to amortize cost.
 * Uses tombstones (not zero) to preserve open-addressing probe chains.
 *
 * Eviction triggers:
 *   1. Idle for > 60 seconds
 *   2. Pinned path is no longer active (removed/frozen)
 *   3. Pinned path loss >= 2% (BBR2+ loss_thresh)
 */
static void
wlb_flow_expire(xqc_wlb_scheduler_t *s, uint64_t now_us, xqc_connection_t *conn)
{
    if ((now_us - s->last_expire_ts) < 1000000) {
        return;
    }
    s->last_expire_ts = now_us;

    /*
     * Detect path recovery/addition (e.g. failover path comes back) without
     * mutating scheduler WRR state here.  Updating s->paths inside expire()
     * caused regressions in failover behavior because expire() runs on the
     * pinned-flow fast path.
     */
    int active_healthy_paths = 0;
    uint64_t active_healthy_ids[WLB_MAX_PATHS];
    int active_healthy_ids_n = 0;
    uint64_t newly_seen_path_id = WLB_NO_PATH_ID;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *scan_path;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        scan_path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (scan_path->path_state != XQC_PATH_STATE_ACTIVE
            || scan_path->app_path_status == XQC_APP_PATH_STATUS_FROZEN
            || (scan_path->path_flag & XQC_PATH_FLAG_SOCKET_ERROR))
        {
            continue;
        }
        /* Blackholed paths can stay ACTIVE without socket error. Treat a path
         * with repeated PTOs as unhealthy for recovery-detection purposes. */
        if (scan_path->path_send_ctl
            && scan_path->path_send_ctl->ctl_pto_count >= WLB_PTO_EVICT_THRESH)
        {
            continue;
        }
        active_healthy_paths++;
        if (active_healthy_ids_n < WLB_MAX_PATHS) {
            active_healthy_ids[active_healthy_ids_n++] = scan_path->path_id;
        }
    }
    /* Detect any newly appeared healthy path_id first so recovery-prefer can
     * target a concrete path even when count-based detection also fires. */
    if (s->last_healthy_path_ids_n > 0) {
        for (int i = 0; i < active_healthy_ids_n; i++) {
            xqc_bool_t seen = XQC_FALSE;
            for (int j = 0; j < s->last_healthy_path_ids_n; j++) {
                if (active_healthy_ids[i] == s->last_healthy_path_ids[j]) {
                    seen = XQC_TRUE;
                    break;
                }
            }
            if (!seen) {
                newly_seen_path_id = active_healthy_ids[i];
                break; /* one path is enough as recovery hint */
            }
        }
    }

    xqc_bool_t has_new_path = XQC_FALSE;
    if (s->last_healthy_paths > 0 && active_healthy_paths > s->last_healthy_paths) {
        has_new_path = XQC_TRUE; /* recovery/addition relative to previous sweep */
    }
    if (!has_new_path && newly_seen_path_id != WLB_NO_PATH_ID) {
        has_new_path = XQC_TRUE; /* path-id replacement with constant count */
    }

    if (has_new_path) {
        s->force_refresh_paths = 1;
        s->recovery_unpin_until_us = now_us + WLB_RECOVERY_UNPIN_GRACE_US;
    }

    if (has_new_path) {
        if (newly_seen_path_id != WLB_NO_PATH_ID) {
            s->recovery_prefer_path_id = newly_seen_path_id;
            xqc_log(conn->log, XQC_LOG_INFO,
                    "|wlb|recovery_detected|new_path_id:%ui|healthy_prev:%d|healthy_now:%d|",
                    (unsigned)newly_seen_path_id, s->last_healthy_paths, active_healthy_paths);
        } else {
            s->recovery_prefer_path_id = WLB_NO_PATH_ID;
            xqc_log(conn->log, XQC_LOG_INFO,
                    "|wlb|recovery_detected|healthy_prev:%d|healthy_now:%d|",
                    s->last_healthy_paths, active_healthy_paths);
        }
    }

    s->last_healthy_paths = active_healthy_paths;
    s->last_healthy_path_ids_n = active_healthy_ids_n;
    for (int i = 0; i < active_healthy_ids_n; i++) {
        s->last_healthy_path_ids[i] = active_healthy_ids[i];
    }

    for (int i = 0; i < WLB_FLOW_TABLE_SIZE; i++) {
        wlb_flow_entry_t *e = &s->flows[i];
        if (e->hash == 0 || e->hash == WLB_FLOW_TOMBSTONE) {
            continue;
        }

        if (has_new_path) {
            /* Re-pin active flows after path recovery so throughput can climb
             * back to the restored path capacity without waiting for idle/loss. */
            e->hash = WLB_FLOW_TOMBSTONE;
            continue;
        }

        /* Idle expiry */
        if ((now_us - e->last_ts) > WLB_FLOW_EXPIRE_US) {
            e->hash = WLB_FLOW_TOMBSTONE;
            continue;
        }

        /* Check pinned path status */
        xqc_path_ctx_t *path = wlb_find_path_ctx(conn, e->path_id);
        if (!path) {
            /* Path removed or frozen → evict immediately */
            e->hash = WLB_FLOW_TOMBSTONE;
            continue;
        }

        /* Loss-triggered eviction: move flows off paths with high loss */
        double loss = xqc_path_recent_loss_rate(path) / 100.0;
        if (loss >= WLB_LOSS_EVICT_THRESH) {
            e->hash = WLB_FLOW_TOMBSTONE;
        }
    }
}

/* ---------- path helpers ---------- */

/** Find a schedulable path context by path_id.
 *
 * Treat repeated-PTO paths as temporarily unavailable for app-data scheduling.
 * A blackholed path can remain ACTIVE without socket error, which otherwise
 * causes WLB to keep selecting it and stall throughput after link-down.
 */
static xqc_path_ctx_t *
wlb_find_path_ctx(xqc_connection_t *conn, uint64_t path_id)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t  *path;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_id == path_id
            && path->path_state == XQC_PATH_STATE_ACTIVE
            && path->app_path_status != XQC_APP_PATH_STATUS_FROZEN
            && !(path->path_flag & XQC_PATH_FLAG_SOCKET_ERROR)
            && !(path->path_send_ctl
                 && path->path_send_ctl->ctl_pto_count >= WLB_PTO_EVICT_THRESH))
        {
            return path;
        }
    }
    return NULL;
}

/* ================================================================
 *  LATE throughput estimation — Datagram-simplified iterative model
 *
 *  QUIC Datagrams are unreliable: no FR/RTO at the QUIC layer.
 *  Instead of 3-category recursive splitting, we use an iterative
 *  per-round model with expected-value cwnd updates:
 *
 *    Each round:
 *      delivered += w * (1 - loss)
 *      p_no_loss  = (1 - loss)^w
 *      w_next     = p_no_loss * grow(w) + (1 - p_no_loss) * max(w/2, 1)
 * ================================================================ */

/**
 * Compute base^n via binary exponentiation (no libm dependency).
 */
static double
late_ipow(double base, int n)
{
    if (n <= 0) {
        return 1.0;
    }
    double result = 1.0;
    double b = base;
    int e = n;
    while (e > 0) {
        if (e & 1) {
            result *= b;
        }
        b *= b;
        e >>= 1;
    }
    return result;
}

/**
 * Iterative LATE estimate for QUIC Datagrams, aligned with BBR2+ behavior.
 *
 * Returns expected number of packets delivered within time budget T.
 * Models per-round binomial loss with expected-value cwnd transitions
 * (no FR/RTO since datagrams are unreliable).
 *
 * BBR2+ alignment (xqc_bbr2.c):
 *   - loss_thresh = 0.02: loss below 2% is tolerated (no cwnd reduction)
 *   - beta = 0.3: cwnd shrinks to 70% on loss (not 50% like Reno)
 *   - fast_convergence: lower bounds reset every 5-9 RTTs, so we cap
 *     the number of loss-reduction rounds to avoid compounding beyond
 *     what BBR2+ actually sustains
 *
 * @param T_us      time budget (microseconds)
 * @param rtt_us    path RTT (microseconds)
 * @param cwnd      congestion window (packets)
 * @param ssthresh  slow-start threshold (packets)
 * @param loss      per-packet loss probability [0, 1]
 */
static double
late_estimate_dgram(double T_us, double rtt_us,
                    int cwnd, int ssthresh, double loss)
{
    if (T_us <= 0.0 || cwnd <= 0 || rtt_us <= 0.0) {
        return 0.0;
    }
    if (loss < 0.0) loss = 0.0;
    if (loss > 1.0) loss = 1.0;

    /* BBR2 tolerates up to 2% random loss without reducing (xqc_bbr2_loss_thresh) */
    if (loss < 0.02) {
        loss = 0.0;
    }

    /* T < RTT/2 — nothing delivered */
    if (T_us < rtt_us / 2.0) {
        return 0.0;
    }

    double N = 0.0;
    double w = (double)cwnd;
    double sst = (double)ssthresh;
    double remaining = T_us;
    int rounds = 0;

    /*
     * BBR2+ fast_convergence resets bw_lo/inflight_lo every 5-9 RTTs
     * (xqc_bbr2_fast_convergence_probe_round_base=4, rand=4).
     * Cap loss-reduction rounds to 7 (midpoint) to prevent unrealistic
     * compounding beyond a single probe cycle.
     */
    const int max_loss_rounds = 7;

    while (remaining >= rtt_us / 2.0 && w >= 0.5) {
        /* Packets delivered this round: E[successes] = w·(1-l) */
        N += w * (1.0 - loss);

        /* Probability of zero loss this round */
        double p_no_loss = late_ipow(1.0 - loss, (int)(w + 0.5));
        double p_loss = 1.0 - p_no_loss;

        /* cwnd growth (no loss): SS doubles, CA increments */
        double w_grow;
        if (w < sst) {
            w_grow = 2.0 * w;
            if (w_grow > sst) w_grow = sst;
        } else {
            w_grow = w + 1.0;
        }

        /*
         * cwnd shrink (loss): BBR2 beta=0.3 → retain 70%
         * (xqc_bbr2_inflight_lo_beta = 0.3, applied as 1-beta = 0.7)
         *
         * After max_loss_rounds, stop compounding shrink — BBR2+ would
         * have reset lower bounds and re-probed by then.
         */
        double w_shrink;
        if (rounds < max_loss_rounds) {
            w_shrink = w * 0.7;
        } else {
            w_shrink = w;  /* no further reduction after reset cycle */
        }
        if (w_shrink < 1.0) w_shrink = 1.0;

        /* Expected-value cwnd for next round */
        double w_next = p_no_loss * w_grow + p_loss * w_shrink;
        double sst_next = p_no_loss * sst + p_loss * w_shrink;

        w = w_next;
        sst = sst_next;
        remaining -= rtt_us;
        rounds++;
    }

    return N;
}

/**
 * Compute LATE weight for a path.
 *
 * @param path         the path to evaluate
 * @param max_rtt_us   maximum SRTT across all active paths (microseconds)
 * @return weight proportional to estimated throughput (scaled ×1000)
 */
static uint64_t
wlb_compute_weight(xqc_path_ctx_t *path, uint64_t max_rtt_us)
{
    xqc_send_ctl_t *ctl = path->path_send_ctl;

    uint64_t srtt_us = xqc_send_ctl_get_srtt(ctl);
    if (srtt_us == 0) {
        return 1;
    }

    /* cwnd in packets */
    uint64_t cwnd_bytes = ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong);
    int cwnd_pkts = (int)(cwnd_bytes / LATE_MSS);
    if (cwnd_pkts < 1) cwnd_pkts = 1;

    /* ssthresh: BBR2 has no traditional ssthresh.
     * Use 2×cwnd so LATE's SS phase models BBR2's probing headroom. */
    int ssthresh = cwnd_pkts * 2;

    /* Loss probability [0, 1] */
    double loss = xqc_path_recent_loss_rate(path) / 100.0;
    if (loss < 0.0) loss = 0.0;
    if (loss > 1.0) loss = 1.0;

    /* Time budget: max_rtt / 2 (LATE scheduling window) */
    double T_us = (double)max_rtt_us / 2.0;
    if (T_us < (double)srtt_us) {
        T_us = (double)srtt_us;     /* ensure at least 1 RTT of budget */
    }

    double N = late_estimate_dgram(T_us, (double)srtt_us,
                                   cwnd_pkts, ssthresh, loss);

    /* Scale ×1000 to preserve precision in integer weight */
    uint64_t weight = (uint64_t)(N * 1000.0);
    return weight > 0 ? weight : 1;
}

/* ================================================================
 *  WRR scheduling
 *
 *  OLB-style deficit-counter WRR.  Each round adds a normalized quantum
 *  (weight / min_weight) to each path's deficit.  The path with the
 *  highest positive deficit is selected and its deficit decremented.
 *  When all deficits are exhausted, a new round begins and LATE weights
 *  are recomputed from real-time path metrics.
 * ================================================================ */

/**
 * Refresh path list and LATE weights from real-time metrics.
 * Deficit counters are preserved for paths that already existed (by path_id).
 */
static void
wlb_refresh_paths(xqc_wlb_scheduler_t *s, xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t  *path;

    /* Save old state for deficit preservation */
    wlb_path_weight_t old[WLB_MAX_PATHS];
    int old_n = s->n_paths;
    memcpy(old, s->paths, sizeof(wlb_path_weight_t) * old_n);

    /* First pass: find max SRTT across active, healthy paths */
    uint64_t max_rtt_us = 0;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE
            || path->app_path_status == XQC_APP_PATH_STATUS_FROZEN
            || (path->path_flag & XQC_PATH_FLAG_SOCKET_ERROR))
        {
            continue;
        }
        uint64_t srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        if (srtt > max_rtt_us) {
            max_rtt_us = srtt;
        }
    }
    if (max_rtt_us == 0) {
        max_rtt_us = 50000;  /* 50ms default */
    }

    /* Second pass: compute LATE weights and build path list */
    int n = 0;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE
            || path->app_path_status == XQC_APP_PATH_STATUS_FROZEN
            || (path->path_flag & XQC_PATH_FLAG_SOCKET_ERROR))
        {
            continue;
        }
        if (n >= WLB_MAX_PATHS) {
            break;
        }
        s->paths[n].path_id = path->path_id;
        s->paths[n].weight  = wlb_compute_weight(path, max_rtt_us);

        /* Preserve deficit for existing paths */
        s->paths[n].deficit = 0;
        for (int j = 0; j < old_n; j++) {
            if (old[j].path_id == path->path_id) {
                s->paths[n].deficit = old[j].deficit;
                break;
            }
        }
        n++;
    }
    s->n_paths = n;
}

/**
 * Check if all paths have exhausted their deficit (round complete).
 */
static xqc_bool_t
wlb_needs_new_round(xqc_wlb_scheduler_t *s)
{
    for (int i = 0; i < s->n_paths; i++) {
        if (s->paths[i].deficit > 0) {
            return XQC_FALSE;
        }
    }
    return XQC_TRUE;
}

/**
 * Start a new WRR round: add normalized weight quantum to deficit counters.
 * Weights are normalized so that min_weight maps to 1.
 */
static void
wlb_start_round(xqc_wlb_scheduler_t *s)
{
    if (s->n_paths == 0) {
        return;
    }

    uint64_t min_w = UINT64_MAX;
    for (int i = 0; i < s->n_paths; i++) {
        if (s->paths[i].weight < min_w) {
            min_w = s->paths[i].weight;
        }
    }
    if (min_w == 0) {
        min_w = 1;
    }

    for (int i = 0; i < s->n_paths; i++) {
        int64_t quantum = (int64_t)(s->paths[i].weight / min_w);
        if (quantum < 1) {
            quantum = 1;
        }
        s->paths[i].deficit += quantum;
    }
}

/**
 * WRR: select the path with the highest deficit that can send.
 */
static uint64_t
wlb_wrr_select(xqc_wlb_scheduler_t *s, xqc_connection_t *conn,
                xqc_packet_out_t *packet_out, int check_cwnd)
{
    int best = -1;
    int64_t best_deficit = INT64_MIN;

    for (int i = 0; i < s->n_paths; i++) {
        xqc_path_ctx_t *path = wlb_find_path_ctx(conn, s->paths[i].path_id);
        if (path == NULL) {
            continue;
        }
        if (check_cwnd && !xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }
        if (s->paths[i].deficit > best_deficit) {
            best_deficit = s->paths[i].deficit;
            best = i;
        }
    }

    if (best >= 0) {
        s->paths[best].deficit -= 1;
        return s->paths[best].path_id;
    }
    return UINT64_MAX;
}

/* ================================================================
 *  MinRTT fallback
 *
 *  Used for non-datagram packets (po_flow_hash == 0) and when WRR
 *  has no active paths.  Selects the path with the lowest SRTT that
 *  has cwnd headroom.
 * ================================================================ */

static xqc_path_ctx_t *
wlb_minrtt_fallback(xqc_connection_t *conn, xqc_packet_out_t *packet_out,
                     int check_cwnd, int reinject, xqc_bool_t *cc_blocked)
{
    xqc_path_ctx_t *best_path = NULL;
    uint64_t best_srtt = UINT64_MAX;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (path->path_state != XQC_PATH_STATE_ACTIVE
            || path->app_path_status == XQC_APP_PATH_STATUS_FROZEN
            || (path->path_flag & XQC_PATH_FLAG_SOCKET_ERROR)
            || (reinject && (packet_out->po_path_id == path->path_id)))
        {
            continue;
        }

        /* Keep control/ACK traffic off blackholed paths as well.  WLB routes
         * po_flow_hash==0 packets via this MinRTT fallback, so omitting the
         * PTO guard can stall failover even if app datagrams are re-pinned. */
        if (path->path_send_ctl
            && path->path_send_ctl->ctl_pto_count >= WLB_PTO_EVICT_THRESH)
        {
            continue;
        }

        if (!reached_cwnd_check) {
            reached_cwnd_check = XQC_TRUE;
            if (cc_blocked) {
                *cc_blocked = XQC_TRUE;
            }
        }

        if (!xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }

        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        uint64_t srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        if (srtt < best_srtt) {
            best_srtt = srtt;
            best_path = path;
        }
    }
    return best_path;
}

/* ================================================================
 *  Scheduler callback interface
 * ================================================================ */

static size_t
xqc_wlb_scheduler_size(void)
{
    return sizeof(xqc_wlb_scheduler_t);
}

static void
xqc_wlb_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    xqc_wlb_scheduler_t *s = (xqc_wlb_scheduler_t *)scheduler;
    memset(s, 0, sizeof(*s));
    s->log = log;
    s->recovery_prefer_path_id = WLB_NO_PATH_ID;
}

/* Sentinel: per-packet WRR without flow pinning (UDP/QUIC datagrams) */
#define WLB_FLOW_HASH_UNPINNED  0xFFFFFFFFU

/**
 * Main scheduling entry point.
 *
 * 1. po_flow_hash == 0 (non-datagram packets) → MinRTT fallback.
 * 2. po_flow_hash == UNPINNED (UDP/QUIC)      → WRR without flow table.
 * 3. Otherwise (TCP)                           → flow table lookup + WRR with pinning.
 */
static xqc_path_ctx_t *
xqc_wlb_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out,
    int check_cwnd, int reinject, xqc_bool_t *cc_blocked)
{
    xqc_wlb_scheduler_t *s = (xqc_wlb_scheduler_t *)scheduler;

    /* Non-datagram packets → MinRTT fallback */
    if (packet_out->po_flow_hash == 0) {
        return wlb_minrtt_fallback(conn, packet_out, check_cwnd, reinject, cc_blocked);
    }

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    /* TCP flows are pinned to paths; UDP/QUIC use per-packet WRR */
    xqc_bool_t pin_flow = (packet_out->po_flow_hash != WLB_FLOW_HASH_UNPINNED);

    uint64_t now_us = xqc_monotonic_timestamp();

    /* After path recovery, allow a brief per-packet WRR phase so existing TCP
     * flows don't immediately re-pin to the surviving path before the restored
     * path accumulates sendability/weight signal. */
    xqc_bool_t in_recovery_grace =
        (pin_flow && s->recovery_unpin_until_us != 0 && now_us < s->recovery_unpin_until_us);
    if (in_recovery_grace) {
        xqc_log(conn->log, XQC_LOG_INFO,
                "|wlb|recovery_grace|flow:%ui|remain_ms:%ui|",
                packet_out->po_flow_hash,
                (unsigned)((s->recovery_unpin_until_us - now_us) / 1000));
    }

    /* Flow table lookup — reuse existing flow→path pinning (TCP only).
     * During recovery grace, skip flow-hit fast path so the flow can be
     * re-evaluated (and potentially steered to the recovered path). */
    if (pin_flow && !in_recovery_grace) {
        wlb_flow_expire(s, now_us, conn);

        wlb_flow_entry_t *entry = wlb_flow_lookup(s, packet_out->po_flow_hash);
        if (entry) {
            xqc_path_ctx_t *path = wlb_find_path_ctx(conn, entry->path_id);

            /* PTO-based eviction: if the pinned path has been unresponsive
             * for several consecutive PTOs, the path is likely dead (e.g.
             * link down where sendto still succeeds but packets are silently
             * dropped).  Evict the flow so it gets re-pinned to a live path
             * via WRR below. */
            if (path
                && path->path_send_ctl->ctl_pto_count >= WLB_PTO_EVICT_THRESH)
            {
                xqc_log(conn->log, XQC_LOG_INFO,
                        "|wlb|flow_evict|reason:pto|flow:%ui|path:%ui|pto:%ud|",
                        packet_out->po_flow_hash, path->path_id,
                        path->path_send_ctl->ctl_pto_count);
                entry->hash = WLB_FLOW_TOMBSTONE;
                path = NULL;
            }

            if (path && xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
                entry->last_ts = now_us;
                xqc_log(conn->log, XQC_LOG_INFO,
                        "|wlb|flow_hit|flow:%ui|path:%ui|",
                        packet_out->po_flow_hash, path->path_id);
                return path;
            }
            if (path) {
                /* Pinned path exists but cwnd-blocked — use another path
                 * temporarily WITHOUT re-pinning.  This prevents oscillation
                 * where a flow bounces between a fast and slow path whenever
                 * the fast path's cwnd is momentarily full. */
                pin_flow = XQC_FALSE;
            }
        }
    } else if (pin_flow) {
        /* Still run maintenance during recovery grace even though we bypass
         * the pinned-flow fast path. */
        wlb_flow_expire(s, now_us, conn);
    }

    /* Recovery hint: when a path has just returned, prefer it for the first
     * re-pin of a flow that currently has no usable pin. This helps the heavy
     * surviving-path flow migrate back instead of immediately re-pinning to the
     * already-hot path. */
    if (pin_flow && in_recovery_grace && s->recovery_prefer_path_id != WLB_NO_PATH_ID) {
        xqc_path_ctx_t *rpath = wlb_find_path_ctx(conn, s->recovery_prefer_path_id);
        if (rpath && xqc_scheduler_check_path_can_send(rpath, packet_out, check_cwnd)) {
            wlb_flow_insert(s, packet_out->po_flow_hash, rpath->path_id, now_us);
            xqc_log(conn->log, XQC_LOG_INFO,
                    "|wlb|recovery_prefer|flow:%ui|path:%ui|",
                    packet_out->po_flow_hash, rpath->path_id);
            return rpath;
        }
    }

    /* Start new WRR round if current round is exhausted.
     * Recompute LATE weights from real-time metrics at round boundary. */
    if (s->force_refresh_paths || wlb_needs_new_round(s)) {
        if (s->force_refresh_paths) {
            xqc_log(conn->log, XQC_LOG_INFO,
                    "|wlb|refresh|reason:recovery|old_n_paths:%d|",
                    s->n_paths);
        }
        wlb_refresh_paths(s, conn);
        wlb_start_round(s);
        xqc_log(conn->log, XQC_LOG_INFO,
                "|wlb|round_start|n_paths:%d|p0:%ui|d0:%lld|p1:%ui|d1:%lld|",
                s->n_paths,
                (unsigned)(s->n_paths > 0 ? s->paths[0].path_id : UINT32_MAX),
                (long long)(s->n_paths > 0 ? s->paths[0].deficit : -1),
                (unsigned)(s->n_paths > 1 ? s->paths[1].path_id : UINT32_MAX),
                (long long)(s->n_paths > 1 ? s->paths[1].deficit : -1));
        s->force_refresh_paths = 0;
    }

    if (s->n_paths == 0) {
        return wlb_minrtt_fallback(conn, packet_out, check_cwnd, reinject, cc_blocked);
    }

    /* Single active path — skip WRR overhead */
    if (s->n_paths == 1) {
        xqc_path_ctx_t *path = wlb_find_path_ctx(conn, s->paths[0].path_id);
        if (path && xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            if (pin_flow) {
                wlb_flow_insert(s, packet_out->po_flow_hash, path->path_id, now_us);
            }
            return path;
        }
        if (cc_blocked) {
            *cc_blocked = XQC_TRUE;
        }
        return NULL;
    }

    /* WRR assignment — pin flow to selected path only for TCP */
    uint64_t sel_path_id = wlb_wrr_select(s, conn, packet_out, check_cwnd);
    if (sel_path_id == UINT64_MAX) {
        /*
         * If no path could be selected, force a fresh round once.
         * This avoids stalling on stale deficits when one path keeps a
         * positive deficit but is temporarily unsendable.
         */
        wlb_refresh_paths(s, conn);
        wlb_start_round(s);
        sel_path_id = wlb_wrr_select(s, conn, packet_out, check_cwnd);
    }

    if (sel_path_id != UINT64_MAX) {
        if (pin_flow) {
            wlb_flow_insert(s, packet_out->po_flow_hash, sel_path_id, now_us);
            xqc_log(conn->log, XQC_LOG_INFO,
                    "|wlb|flow_pin|flow:%ui|path:%ui|",
                    packet_out->po_flow_hash, sel_path_id);
        }
        xqc_path_ctx_t *path = wlb_find_path_ctx(conn, sel_path_id);
        xqc_log(conn->log, XQC_LOG_INFO,
                 "|wlb|select|path_id:%ui|n_paths:%d|pinned:%d|",
                 sel_path_id, s->n_paths, (int)pin_flow);
        return path;
    }

    /* All paths cwnd-blocked */
    if (cc_blocked) {
        *cc_blocked = XQC_TRUE;
    }
    return NULL;
}

static void
xqc_wlb_scheduler_handle_path_event(void *scheduler,
    xqc_path_ctx_t *path, xqc_scheduler_path_event_t event, void *event_arg)
{
    /* No action needed — weights are recomputed at round boundary */
}

static void
xqc_wlb_scheduler_handle_conn_event(void *scheduler,
    xqc_connection_t *conn, xqc_scheduler_conn_event_t event, void *event_arg)
{
    /* No action needed */
}

const xqc_scheduler_callback_t xqc_wlb_scheduler_cb = {
    .xqc_scheduler_size             = xqc_wlb_scheduler_size,
    .xqc_scheduler_init             = xqc_wlb_scheduler_init,
    .xqc_scheduler_get_path         = xqc_wlb_scheduler_get_path,
    .xqc_scheduler_handle_path_event = xqc_wlb_scheduler_handle_path_event,
    .xqc_scheduler_handle_conn_event = xqc_wlb_scheduler_handle_conn_event,
};
