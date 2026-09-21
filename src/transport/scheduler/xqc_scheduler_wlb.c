/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WLB (Weighted Load Balancing) multipath scheduler for QUIC Datagrams.
 *
 * WLB spreads DATAGRAM traffic across paths in proportion to what each
 * path is measured to deliver, while keeping the datagrams of one inner TCP
 * flow (identified by po_flow_hash) on one QUIC path.  This prevents TCP
 * reordering inside VPN tunnels while still aggregating bandwidth across
 * paths via weighted round-robin of flows.
 *
 * Packet classes (see xqc_wlb_scheduler_get_path):
 *   - reinjected replica        -> MinRTT, origin path excluded.
 *   - po_flow_hash == 0         -> MinRTT.  STREAM data and control
 *     packets; for STREAM that is a measured choice, not an omission -- see
 *     the rationale at that branch.
 *   - po_flow_hash == UNPINNED  -> per-packet WRR, no flow table (inner
 *     UDP/QUIC).
 *   - any other po_flow_hash    -> flow table lookup; a miss is placed by
 *     WRR and pinned (inner TCP).
 *
 * Algorithm:
 *   1. Learn acknowledged application goodput for every schedulable path,
 *      sampled over wall clock (xqc_wlb_scheduler_on_app_packet_acked,
 *      wlb_compute_goodput_weight).
 *   2. Turn goodput into a raw weight: credit the congestion controller's
 *      bandwidth estimate while the path is app-limited (under-fed, not
 *      slow), then discount for recent loss and for a standing queue (srtt
 *      well above min_rtt).
 *   3. Normalize raw weights into quanta summing to WLB_QUANTUM_TOTAL, with
 *      a floor per path -- WLB_WARMUP_FLOOR_PCT while warming up,
 *      WLB_STEADY_FLOOR_PCT afterwards -- so a new or recovering path always
 *      carries enough payload to be measured (wlb_normalize_weights).
 *   4. Distribute packets with smooth weighted round robin (wlb_wrr_select).
 *      Weights are recomputed at round boundaries (wlb_start_round) and
 *      immediately when the set of schedulable paths changes.
 *   5. Pin inner TCP flows to paths via hash table to prevent TCP
 *      reordering.  The pin target comes from a second smooth WRR over the
 *      same weights that ignores cwnd (wlb_pick_pin_path), so the packet
 *      that creates a pin may itself leave on a different path.
 *   6. If every schedulable path is cwnd-blocked, return no path and report
 *      cc_blocked.  MinRTT is NOT the fallback for that case: it serves the
 *      packet classes above, and hashed packets only when WRR has no
 *      schedulable path at all.
 *
 * Path eviction and recovery:
 *   A path that is not ACTIVE, is FROZEN, has a socket error, or has reached
 *   WLB_PTO_EVICT_THRESH consecutive PTOs (blackholed) is not schedulable:
 *   it leaves the WRR set and pins to it are dropped.  Flows are also moved
 *   off a path whose recent loss reaches WLB_LOSS_EVICT_THRESH
 *   (wlb_flow_expire).  A blackholed path is handed nothing that could be
 *   ACKed, so one DATAGRAM per WLB_EVICTED_PROBE_INTERVAL_US is sent on it
 *   as a probe (wlb_pick_evicted_probe).  When a path returns after a loss,
 *   every pin is wiped and, for WLB_RECOVERY_UNPIN_GRACE_US, existing pins
 *   are not honoured: each packet re-pins its flow, onto the returned path
 *   when that path can send.  The wipe is gated on ever_lost_path so that a
 *   secondary path coming up during initial setup does not trigger it.
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
 *   Measured impact (2026-02, under the model-derived weights this
 *   scheduler used before goodput learning; not re-measured since): ~4%
 *   throughput overhead with 1 TCP stream over asymmetric paths
 *   (300Mbit/10ms + 80Mbit/30ms) vs single-path.  With 8+ streams the
 *   overhead disappears and aggregation gains dominate (+15-23%).
 *
 * References:
 *   - OLB: "Optimal Load Balancing", Computer Communications, 2017.
 *     Origin of the round-based weighted distribution (weights held fixed
 *     for a round); the weights themselves are now measured, not modelled.
 */

#include "src/transport/scheduler/xqc_scheduler_wlb.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_multipath.h"
#include "src/common/xqc_time.h"

/* ---------- constants ---------- */

/* WLB ceiling = the defensive hard cap on paths, not the legacy 8. Per-path
 * state sized by it lives in the heap-allocated scheduler struct; anything
 * of WLB_MAX_PATHS * sizeof(wlb_path_weight_t) must stay off the stack (see
 * wlb_refresh_paths). */
#define WLB_MAX_PATHS         XQC_PATH_HARD_CAP
/* Flow table — open-addressing hash table for flow-to-path pinning */
#define WLB_FLOW_TABLE_SIZE   4096
#define WLB_FLOW_TABLE_MASK   (WLB_FLOW_TABLE_SIZE - 1)
#define WLB_MAX_PROBE         16      /* linear probe limit */
#define WLB_FLOW_EXPIRE_US    (60ULL * 1000000)  /* 60 s idle expiry */
#define WLB_LOSS_EVICT_THRESH 0.02  /* evict flows from paths with loss >= 2% (BBR2+ aligned) */
#define WLB_PTO_EVICT_THRESH  3    /* evict flows from paths with >= 3 consecutive PTOs (~500ms) */
#define WLB_RECOVERY_UNPIN_GRACE_US (1000ULL * 1000) /* 1s temporary unpin after path recovery */
#define WLB_NO_PATH_ID UINT64_MAX
#define WLB_WARMUP_ACK_BYTES  (1024ULL * 1024)
#define WLB_WARMUP_ACTIVE_US  (3ULL * 1000000)
#define WLB_ACTIVE_GAP_MAX_US (1000ULL * 1000)
#define WLB_WARMUP_FLOOR_PCT  20
#define WLB_STEADY_FLOOR_PCT  5
#define WLB_QUANTUM_TOTAL      100
/* An evicted (repeated-PTO) path receives no payload, so nothing can ever
 * ACK on it and ctl_pto_count can never reset: eviction would be permanent
 * even after the link heals. Send one real payload packet per interval as a
 * probe; a surviving probe's ACK clears the PTO count and the path re-enters
 * scheduling through a fresh warm-up. One datagram per half-second on a dead
 * path is a negligible loss (inner TCP retransmits; datagrams are best-
 * effort by contract). */
#define WLB_EVICTED_PROBE_INTERVAL_US (500ULL * 1000)
/* Minimum wall-clock span for one goodput sample. Sampling faster than this
 * measures the inside of an ACK burst rather than sustained rate. */
#define WLB_GOODPUT_SAMPLE_MIN_US (200ULL * 1000)

/*
 * Tombstone marker for deleted flow table entries.
 * Using 0xFFFFFFFF which equals WLB_FLOW_HASH_UNPINNED (defined next to
 * xqc_wlb_scheduler_get_path) — safe because unpinned packets never enter
 * the flow table (pin_flow == false).
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
    uint64_t    weight;     /* normalized payload quantum [1, 100] */
    int64_t     deficit;    /* WRR deficit counter */
    int64_t     pin_deficit;
    uint64_t    prior_delivered;
    uint64_t    prior_delivered_time_us;
    uint64_t    app_delivered;
    uint64_t    goodput_ewma_Bps;
    uint64_t    warmup_acked_bytes;
    uint64_t    warmup_active_us;
    uint64_t    last_payload_schedule_us;
    xqc_bool_t  warmup;
} wlb_path_weight_t;

/** Top-level scheduler state, allocated by xquic via xqc_wlb_scheduler_size(). */
typedef struct {
    wlb_path_weight_t   paths[WLB_MAX_PATHS];
    int                  n_paths;
    int                  round_remaining;
    wlb_flow_entry_t     flows[WLB_FLOW_TABLE_SIZE];
    uint64_t             last_expire_ts;  /* throttle expire scans to 1/sec */
    int                  last_healthy_paths; /* for recovery-triggered rebalance */
    uint64_t             last_healthy_path_ids[WLB_MAX_PATHS];
    int                  last_healthy_path_ids_n;
    int                  force_refresh_paths; /* path set changed: rebuild WRR cache */
    uint64_t             recovery_unpin_until_us; /* temporarily disable TCP pinning after recovery */
    uint64_t             recovery_prefer_path_id; /* newly recovered path to prefer for first re-pin */
    uint64_t             last_evicted_probe_us;
    uint64_t             next_evicted_probe_path; /* round-robin cursor */
    /* Set once a previously-healthy path has been observed as unhealthy. Gates
     * the "newly appeared path = recovery" heuristic so the heuristic does not
     * fire during initial multi-path setup (e.g. secondary path coming up
     * after handshake), which otherwise wipes the freshly-established pin and
     * re-pins all TCP flows to the just-added — possibly narrow — path. */
    xqc_bool_t           ever_lost_path;
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
 *
 * A tombstone is remembered but does NOT end the search: this flow's own
 * entry may sit further along the probe chain, behind an eviction that
 * happened after it was placed. Writing into the tombstone on sight would
 * leave two live entries for one hash. wlb_flow_expire and the fast-path
 * eviction both act on a single entry, so the copy they do not reach stays
 * behind and a later lookup — which stops at the first match — resurrects
 * whichever pin it names, possibly one already abandoned.
 */
static void
wlb_flow_insert(xqc_wlb_scheduler_t *s, uint32_t hash, uint64_t path_id, uint64_t now_us)
{
    if (hash == 0) {
        return;
    }
    uint32_t idx = hash & WLB_FLOW_TABLE_MASK;
    wlb_flow_entry_t *slot = NULL;
    for (int i = 0; i < WLB_MAX_PROBE; i++) {
        wlb_flow_entry_t *e = &s->flows[(idx + i) & WLB_FLOW_TABLE_MASK];
        if (e->hash == hash) {
            slot = e;               /* the live entry always wins */
            break;
        }
        if (e->hash == WLB_FLOW_TOMBSTONE) {
            if (slot == NULL) {
                slot = e;           /* remember the first, keep probing */
            }
            continue;
        }
        if (e->hash == 0) {
            if (slot == NULL) {
                slot = e;           /* end of chain, nothing to reuse */
            }
            break;                  /* lookup stops here too, so no entry is past it */
        }
    }
    if (slot == NULL) {
        /* Probe region full of other live hashes — overwrite first slot */
        slot = &s->flows[idx];
    }
    slot->hash    = hash;
    slot->path_id = path_id;
    slot->last_ts = now_us;
}

/**
 * Once-a-second housekeeping for pinned traffic: detect path loss and
 * recovery, then expire idle flow entries and evict flows from lossy or
 * unusable paths.
 *
 * Scans the full table at most once per second to amortize cost.
 * Uses tombstones (not zero) to preserve open-addressing probe chains.
 *
 * Recovery detection compares the healthy path set with the previous
 * sweep's.  It only raises flags (force_refresh_paths, the recovery grace
 * window and the preferred path); s->paths is rebuilt by the caller.
 *
 * Eviction triggers:
 *   0. A path returned after a loss (has_new_path): every entry is wiped so
 *      flows can re-pin onto the restored capacity
 *   1. Idle for > 60 seconds
 *   2. Pinned path is no longer schedulable: removed, not ACTIVE, frozen,
 *      socket error, or blackholed (>= WLB_PTO_EVICT_THRESH PTOs)
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

    /* Detect path loss: a previously-healthy path is missing from the current
     * active set. This latches ever_lost_path so the "newly appeared path =
     * recovery" heuristic below is enabled only after a real failover. Without
     * this gate the heuristic also fires for initial setup (e.g. secondary
     * path comes up some hundreds of ms after handshake) and wipes the
     * just-established pin onto the freshly-added — possibly narrow — path. */
    if (!s->ever_lost_path) {
        if (s->last_healthy_paths > 0
            && active_healthy_paths < s->last_healthy_paths)
        {
            s->ever_lost_path = XQC_TRUE;
        } else {
            for (int j = 0; j < s->last_healthy_path_ids_n; j++) {
                xqc_bool_t still = XQC_FALSE;
                for (int i = 0; i < active_healthy_ids_n; i++) {
                    if (s->last_healthy_path_ids[j] == active_healthy_ids[i]) {
                        still = XQC_TRUE;
                        break;
                    }
                }
                if (!still) {
                    s->ever_lost_path = XQC_TRUE;
                    break;
                }
            }
        }
    }

    /* Detect path-count increase independently of ever_lost_path. We always
     * want s->paths to reflect the current active set so wlb_pick_pin_path's
     * RR distribution can include newly-added paths. The wipe/grace behavior
     * (below) remains gated on ever_lost_path, so initial multi-path setup
     * never wipes freshly-established pins. */
    xqc_bool_t path_count_increased =
        (s->last_healthy_paths > 0 && active_healthy_paths > s->last_healthy_paths);

    xqc_bool_t has_new_path = XQC_FALSE;
    if (s->ever_lost_path) {
        if (path_count_increased) {
            has_new_path = XQC_TRUE; /* recovery/addition relative to previous sweep */
        }
        if (!has_new_path && newly_seen_path_id != WLB_NO_PATH_ID) {
            has_new_path = XQC_TRUE; /* path-id replacement with constant count */
        }
    }

    if (path_count_increased) {
        /* Always refresh s->paths on new-path detection, so wlb_pick_pin_path
         * sees the new path and the single-path fast path stops firing. NOT
         * gated on ever_lost_path. The per-packet
         * wlb_active_paths_match_cache check in xqc_wlb_scheduler_get_path
         * now catches the same change (and constant-count replacement,
         * which this count test cannot), so this is no longer what keeps
         * s->n_paths fresh; it stays as the explicit statement that a path
         * addition always refreshes. */
        s->force_refresh_paths = 1;
    }
    if (has_new_path) {
        /* Wipe + grace only on real recovery, i.e. once ever_lost_path is
         * set: a secondary path coming up during initial setup must not
         * wipe fresh pins. */
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
            /* Path gone or no longer schedulable (wlb_path_schedulable)
             * → evict immediately */
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

/* Transport liveness only: the path exists and its socket works. Says
 * nothing about whether it is currently delivering. Both the scheduling
 * predicate and the recovery-probe picker build on this, so a new
 * disqualifier added here cannot be missed by one of them. It CAN be missed
 * by wlb_flow_expire's healthy-path scan and by wlb_minrtt_fallback, which
 * still spell the same conditions out inline -- add it there as well. */
static xqc_bool_t
wlb_path_transport_ok(xqc_path_ctx_t *path)
{
    return path->path_state == XQC_PATH_STATE_ACTIVE
           && path->app_path_status != XQC_APP_PATH_STATUS_FROZEN
           && !(path->path_flag & XQC_PATH_FLAG_SOCKET_ERROR);
}

/* True once the path has stopped responding for WLB_PTO_EVICT_THRESH
 * consecutive PTOs — evicted from scheduling, eligible for probing. */
static xqc_bool_t
wlb_path_blackholed(xqc_path_ctx_t *path)
{
    return path->path_send_ctl != NULL
           && path->path_send_ctl->ctl_pto_count >= WLB_PTO_EVICT_THRESH;
}

static xqc_bool_t
wlb_path_schedulable(xqc_path_ctx_t *path)
{
    return wlb_path_transport_ok(path) && !wlb_path_blackholed(path);
}

/**
 * Find a schedulable path context by path_id; NULL if the path is gone or
 * not schedulable.
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
        if (path->path_id == path_id && wlb_path_schedulable(path)) {
            return path;
        }
    }
    return NULL;
}

static uint64_t
wlb_compute_goodput_weight(wlb_path_weight_t *entry, xqc_path_ctx_t *path,
                           uint64_t now_us)
{
    xqc_send_ctl_t *ctl = path->path_send_ctl;
    /* Sample sustained rate over wall clock, not over the span of the ACKs
     * themselves. Measuring ack-to-ack timed the inside of a burst: a path
     * delivering 100 KiB in a 10 ms burst once per second read as 10 MB/s
     * instead of 100 KB/s, and because a path with no delivery produced no
     * sample at all, the inflated average never decayed while the path sat
     * idle. A bursty high-latency link therefore out-weighted links that
     * were genuinely carrying more, and the aggregate fell below a single
     * path. Zero-delivery samples are included precisely so idle decays. */
    if (now_us >= entry->prior_delivered_time_us
        && now_us - entry->prior_delivered_time_us >= WLB_GOODPUT_SAMPLE_MIN_US)
    {
        uint64_t delivered = entry->app_delivered >= entry->prior_delivered
                             ? entry->app_delivered - entry->prior_delivered
                             : 0;
        uint64_t elapsed = now_us - entry->prior_delivered_time_us;
        uint64_t sample_Bps = (delivered * 1000000) / elapsed;

        entry->goodput_ewma_Bps =
            (7 * entry->goodput_ewma_Bps + sample_Bps) / 8;
        entry->warmup_acked_bytes += delivered;
        entry->prior_delivered = entry->app_delivered;
        entry->prior_delivered_time_us = now_us;
    }

    if (entry->warmup
        && (entry->warmup_active_us >= WLB_WARMUP_ACTIVE_US
            || entry->warmup_acked_bytes >= WLB_WARMUP_ACK_BYTES))
    {
        entry->warmup = XQC_FALSE;
    }

    uint64_t weight = entry->goodput_ewma_Bps;
    if (weight > 0) {
        /* Measured goodput is demand-limited, not a capacity reading: a
         * path only delivers what the scheduler hands it, so a path held
         * near the floor reports a low rate, which keeps it near the floor.
         * Observed live: Wi-Fi carried 256 MB against cellular's 4144 MB
         * over the same eight hours while both showed four healthy flows.
         *
         * Credit the congestion controller's bandwidth estimate — a
         * max-filtered delivery rate, i.e. what the link sustained when it
         * last had data — but only while the path is application-limited,
         * which is exactly the under-fed case: it ran out of packets to
         * send rather than out of room to send them. A path that is handed
         * work and fails to deliver it is not app-limited, so it keeps its
         * measured (low) weight, and the branch below still floors one
         * whose goodput has decayed to zero. That is what stops a stale
         * estimate from handing a 0 B/s path a majority share. */
        if (xqc_send_ctl_is_app_limited(ctl)) {
            uint64_t capacity_Bps = xqc_send_ctl_get_est_bw(ctl);
            if (capacity_Bps > weight) {
                weight = capacity_Bps;
            }
        }
        /* Measured acked goodput is already net of every lost packet, so
         * loss takes only a gentle linear haircut here — enough to shed
         * load from a degrading path before the EWMA catches up, without
         * the old 2/loss divisor that cut a lossy-but-delivering cellular
         * link to a third of its measured share. */
        double loss_percent = xqc_path_recent_loss_rate(path);
        if (loss_percent > 2.0) {
            if (loss_percent > 90.0) {
                loss_percent = 90.0;
            }
            weight = (uint64_t)((double)weight * (100.0 - loss_percent) / 100.0);
        }
        /* Bufferbloat haircut: srtt/min_rtt measures the standing queue in
         * units of the path's propagation delay. A path buffering multiples
         * of its base RTT still ACKs everything eventually -- measured
         * goodput looks healthy -- but its packets arrive so far behind the
         * other paths' that a resequencing peer times them out and inner
         * TCP books them as losses (observed live: a cellular attach at
         * ~3 s srtt over a 170 ms floor turned its whole sprayed share into
         * reorder-timeout drops). Scale the weight by 2*min_rtt/srtt beyond
         * a 2x operating point (BBR steady state sits at 1-1.5x min), which
         * closes the loop the plain goodput weight leaves open: less
         * traffic -> queue drains -> srtt recovers -> weight returns. The
         * steady floor keeps probing the path meanwhile. min_rtt == 0
         * (zeroed test fixtures) is excluded by the bloat_min > 0 guard and
         * the pre-first-sample XQC_MAX_UINT32_VALUE sentinel fails
         * srtt > 2*min_rtt, so both skip the haircut. */
        xqc_usec_t bloat_srtt = xqc_send_ctl_get_srtt(ctl);
        xqc_usec_t bloat_min = ctl->ctl_minrtt;
        if (bloat_min > 0 && bloat_srtt > 2 * bloat_min) {
            weight = weight * (2 * bloat_min) / bloat_srtt;
            if (weight == 0) {
                weight = 1;
            }
        }
    } else if (entry->warmup) {
        /* Bootstrap: the congestion controller's bandwidth estimate has not
         * paid for its losses yet, so discount it aggressively. */
        weight = xqc_send_ctl_get_est_bw(ctl);
        if (weight > 0) {
            double loss_percent = xqc_path_recent_loss_rate(path);
            if (loss_percent > 2.0) {
                weight = (uint64_t)((double)weight * 2.0 / loss_percent);
            }
        }
    } else {
        /* A warmed path whose measured goodput has decayed to zero delivers
         * nothing right now; trusting the controller's estimate here hands a
         * dead path a majority weight it never pays for (observed live: a
         * 0 B/s path holding 61% while the delivering path got 39%). Send it
         * to the steady floor, whose probe share is exactly how a recovered
         * path earns its weight back. */
        weight = 1;
    }
    if (weight == 0) {
        weight = 1;
    }

    return weight;
}

/* ================================================================
 *  WRR scheduling
 *
 *  Smooth deficit-counter WRR. Each opportunity adds the normalized
 *  quantum to every sendable path. The selected path subtracts the total
 *  sendable quantum. Goodput weights are refreshed at round boundaries --
 *  every max(WLB_QUANTUM_TOTAL, n_paths) payload opportunities, see
 *  wlb_start_round -- and whenever the schedulable path set changes.
 * ================================================================ */

/**
 * Compare the cached WRR path IDs with the active connection path list.
 * Refresh builds the cache in connection-list order, so an ordered comparison
 * detects both count changes and constant-count path replacement in O(paths).
 */
static xqc_bool_t
wlb_active_paths_match_cache(xqc_wlb_scheduler_t *s, xqc_connection_t *conn)
{
    int n = 0;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (!wlb_path_schedulable(path)) {
            continue;
        }
        if (n >= s->n_paths || s->paths[n].path_id != path->path_id) {
            return XQC_FALSE;
        }
        n++;
    }
    return n == s->n_paths ? XQC_TRUE : XQC_FALSE;
}

static void
wlb_normalize_weights(xqc_wlb_scheduler_t *s, uint64_t *raw_weights)
{
    uint64_t raw_total = 0;
    int floor_total = 0;
    int assigned = 0;
    int strongest = 0;

    for (int i = 0; i < s->n_paths; i++) {
        raw_total += raw_weights[i];
        floor_total += s->paths[i].warmup
                       ? WLB_WARMUP_FLOOR_PCT
                       : WLB_STEADY_FLOOR_PCT;
        if (raw_weights[i] > raw_weights[strongest]) {
            strongest = i;
        }
    }

    if (floor_total >= WLB_QUANTUM_TOTAL) {
        int base = WLB_QUANTUM_TOTAL / s->n_paths;
        int remainder = WLB_QUANTUM_TOTAL % s->n_paths;
        for (int i = 0; i < s->n_paths; i++) {
            uint64_t quantum = (uint64_t)base + (i < remainder ? 1 : 0);
            /* Past WLB_QUANTUM_TOTAL paths integer division hands out zero,
             * and a zero weight never accrues deficit: the path would be
             * excluded from payload and from pinning for the life of the
             * connection, so it could never leave warm-up either. Keep the
             * documented [1, WLB_QUANTUM_TOTAL] range instead. */
            s->paths[i].weight = quantum > 0 ? quantum : 1;
        }
        return;
    }

    int distributable = WLB_QUANTUM_TOTAL - floor_total;
    for (int i = 0; i < s->n_paths; i++) {
        int floor = s->paths[i].warmup
                    ? WLB_WARMUP_FLOOR_PCT
                    : WLB_STEADY_FLOOR_PCT;
        uint64_t proportional = raw_total > 0
                                ? ((uint64_t)distributable
                                   * raw_weights[i]) / raw_total
                                : (uint64_t)distributable / s->n_paths;
        uint64_t quantum = (uint64_t)floor + proportional;
        if (quantum < 1) {
            quantum = 1;
        }
        if (quantum > WLB_QUANTUM_TOTAL) {
            quantum = WLB_QUANTUM_TOTAL;
        }
        s->paths[i].weight = quantum;
        assigned += (int)quantum;
    }

    if (assigned < WLB_QUANTUM_TOTAL) {
        s->paths[strongest].weight += WLB_QUANTUM_TOTAL - assigned;
    }
}

static void
wlb_note_payload_activity(xqc_wlb_scheduler_t *s, uint64_t path_id,
                          uint64_t now_us, xqc_bool_t count_round)
{
    if (count_round && s->round_remaining > 0) {
        s->round_remaining--;
    }

    for (int i = 0; i < s->n_paths; i++) {
        wlb_path_weight_t *entry = &s->paths[i];
        if (entry->path_id != path_id || !entry->warmup) {
            continue;
        }
        if (entry->last_payload_schedule_us != 0
            && now_us >= entry->last_payload_schedule_us)
        {
            uint64_t elapsed = now_us - entry->last_payload_schedule_us;
            if (elapsed <= WLB_ACTIVE_GAP_MAX_US) {
                entry->warmup_active_us += elapsed;
            }
        }
        entry->last_payload_schedule_us = now_us;
        if (entry->warmup_active_us >= WLB_WARMUP_ACTIVE_US) {
            entry->warmup = XQC_FALSE;
        }
        break;
    }
}

/**
 * Refresh path list and acknowledged-goodput weights from real-time metrics.
 * Delivery learning is preserved by path ID; scheduling deficits are reset.
 */
static void
wlb_refresh_paths(xqc_wlb_scheduler_t *s, xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t  *path;

    /* Save old delivery and warm-up state for retained paths.
     * Heap-alloc the copy: at WLB_MAX_PATHS entries it is far too large for
     * a stack frame. */
    int old_n = s->n_paths;
    wlb_path_weight_t *old = NULL;
    if (old_n > 0) {
        old = xqc_malloc(sizeof(wlb_path_weight_t) * (size_t)old_n);
        if (old != NULL) {
            memcpy(old, s->paths, sizeof(wlb_path_weight_t) * (size_t)old_n);
        } else {
            old_n = 0;  /* fall through with no state preservation */
        }
    }

    uint64_t raw_weights[WLB_MAX_PATHS];
    uint64_t now_us = xqc_monotonic_timestamp();
    int n = 0;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (!wlb_path_schedulable(path)) {
            continue;
        }
        if (n >= WLB_MAX_PATHS) {
            break;
        }
        wlb_path_weight_t entry;
        memset(&entry, 0, sizeof(entry));
        entry.path_id = path->path_id;
        entry.warmup = XQC_TRUE;
        entry.prior_delivered_time_us = xqc_monotonic_timestamp();
        for (int j = 0; j < old_n; j++) {
            if (old[j].path_id == path->path_id) {
                entry = old[j];
                break;
            }
        }
        entry.deficit = 0;
        entry.pin_deficit = 0;
        s->paths[n] = entry;
        raw_weights[n] = wlb_compute_goodput_weight(&s->paths[n], path, now_us);
        n++;
    }
    s->n_paths = n;
    if (n > 0) {
        wlb_normalize_weights(s, raw_weights);
    }

    if (old != NULL) {
        xqc_free(old);
    }
}

/**
 * True once the round's payload opportunities are used up (see
 * wlb_start_round); the next hashed packet then refreshes the weights.
 */
static xqc_bool_t
wlb_needs_new_round(xqc_wlb_scheduler_t *s)
{
    return s->round_remaining <= 0 ? XQC_TRUE : XQC_FALSE;
}

static void
wlb_start_round(xqc_wlb_scheduler_t *s)
{
    if (s->n_paths == 0) {
        return;
    }
    /* Past WLB_QUANTUM_TOTAL paths the quantum split gives each of them
     * weight 1, so selection is round robin by index. A round fixed at
     * WLB_QUANTUM_TOTAL would then hand the turn back to wlb_refresh_paths,
     * which zeroes every deficit, and paths from index WLB_QUANTUM_TOTAL on
     * would never be reached, never carry payload, and never leave warm-up.
     * Sizing the round to the path count removes that for WRR traffic.
     *
     * It does NOT remove it in general: a pinned flow hit, a recovery-prefer
     * pin and the single-path fast path each spend one round_remaining in
     * wlb_note_payload_activity without advancing any deficit, so a workload
     * mixing pinned datagrams with unpinned ones can still end a round
     * early. Closing that means either not charging pinned hits to the
     * round, which changes how often weights refresh for every ordinary
     * 2-4 path connection, or letting deficits survive a routine refresh.
     * Neither is worth doing for a regime -- more than 100 live paths on one
     * connection -- that nothing here can reach or test. */
    s->round_remaining = s->n_paths > WLB_QUANTUM_TOTAL
                         ? s->n_paths : WLB_QUANTUM_TOTAL;
}

/**
 * Choose a PIN TARGET for a fresh TCP flow using smooth WRR, IGNORING
 * current cwnd state.
 *
 * Pinning is a long-lived routing decision; the actual packet that triggers
 * the pin is sent via wlb_wrr_select() which honours cwnd. Separating the two
 * avoids the failure mode where the wide path is momentarily cwnd-blocked at
 * pin time — wrr_select would otherwise skip it, return the narrow path, and
 * freeze the TCP flow there for the next 60s of idle expiry.
 *
 * Uses a separate smooth deficit so pin assignment does not perturb the
 * per-packet scheduler.
 */
static uint64_t
wlb_pick_pin_path(xqc_wlb_scheduler_t *s, xqc_connection_t *conn)
{
    /* Pick the path with the highest smooth pin deficit for
     * pin assignment, even if it is currently cwnd-blocked. wrr_select
     * (just before) already chose a sendable path for the current packet;
     * the pin is what subsequent packets of this flow will key off, and
     * it must reflect the long-term best path, not transient cwnd state.
     *
     * Equal weights alternate pin targets; asymmetric weights assign new
     * flows in the same normalized ratio as unpinned payload.
     */
    int best = -1;
    int64_t best_deficit = INT64_MIN;
    int64_t total_weight = 0;
    for (int i = 0; i < s->n_paths; i++) {
        xqc_path_ctx_t *path = wlb_find_path_ctx(conn, s->paths[i].path_id);
        if (path == NULL) {
            continue;
        }
        s->paths[i].pin_deficit += (int64_t)s->paths[i].weight;
        total_weight += (int64_t)s->paths[i].weight;
        if (s->paths[i].pin_deficit > best_deficit) {
            best_deficit = s->paths[i].pin_deficit;
            best = i;
        }
    }
    if (best >= 0) {
        s->paths[best].pin_deficit -= total_weight;
        return s->paths[best].path_id;
    }
    return WLB_NO_PATH_ID;
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
    int64_t total_weight = 0;

    for (int i = 0; i < s->n_paths; i++) {
        xqc_path_ctx_t *path = wlb_find_path_ctx(conn, s->paths[i].path_id);
        if (path == NULL) {
            continue;
        }
        if (check_cwnd && !xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }
        s->paths[i].deficit += (int64_t)s->paths[i].weight;
        total_weight += (int64_t)s->paths[i].weight;
        if (s->paths[i].deficit > best_deficit) {
            best_deficit = s->paths[i].deficit;
            best = i;
        }
    }

    if (best >= 0) {
        s->paths[best].deficit -= total_weight;
        if (s->round_remaining > 0) {
            s->round_remaining--;
        }
        return s->paths[best].path_id;
    }
    return UINT64_MAX;
}

/* ================================================================
 *  MinRTT fallback
 *
 *  Used for reinjected replicas (origin path excluded), for every packet
 *  without a flow hash -- STREAM data and control packets alike -- and when
 *  WRR has no schedulable paths. Selects the path with
 *  the lowest SRTT that has cwnd headroom, spilling to the next one as each
 *  fills its cwnd. See xqc_wlb_scheduler_get_path for why STREAM belongs
 *  here.
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

static void
xqc_wlb_scheduler_on_app_packet_acked(void *scheduler, uint64_t path_id,
                                      uint64_t payload_bytes)
{
    if (scheduler == NULL || payload_bytes == 0) {
        return;
    }

    xqc_wlb_scheduler_t *s = scheduler;
    for (int i = 0; i < s->n_paths; i++) {
        if (s->paths[i].path_id != path_id) {
            continue;
        }
        if (UINT64_MAX - s->paths[i].app_delivered < payload_bytes) {
            s->paths[i].app_delivered = UINT64_MAX;
        } else {
            s->paths[i].app_delivered += payload_bytes;
        }
        break;
    }
}

int
xqc_wlb_scheduler_copy_path_stats(void *scheduler, xqc_wlb_path_stats_t *out,
                                  size_t capacity, size_t *out_count)
{
    if (scheduler == NULL || out_count == NULL) {
        return -XQC_EPARAM;
    }
    if (capacity > 0 && out == NULL) {
        return -XQC_EPARAM;
    }

    xqc_wlb_scheduler_t *s = scheduler;
    *out_count = (size_t)s->n_paths;
    size_t n = (size_t)s->n_paths;
    if (n > capacity) {
        n = capacity;
    }
    for (size_t i = 0; i < n; i++) {
        out[i].path_id = s->paths[i].path_id;
        out[i].goodput_Bps = s->paths[i].goodput_ewma_Bps;
        out[i].weight_pct = (uint8_t)s->paths[i].weight;
        out[i].warmup = s->paths[i].warmup ? 1 : 0;
    }
    return XQC_OK;
}

/* Sentinel: per-packet WRR without flow pinning (UDP/QUIC datagrams) */
#define WLB_FLOW_HASH_UNPINNED  0xFFFFFFFFU

/* Pick an ACTIVE-but-evicted path for a single probe payload packet, at
 * most once per WLB_EVICTED_PROBE_INTERVAL_US across the connection.
 * Round-robins across multiple evicted paths so one permanently dead path
 * cannot starve another's recovery probe. Returns NULL when there is
 * nothing to probe, the interval has not elapsed, or the packet does not
 * fit the path's cwnd. */
static xqc_path_ctx_t *
wlb_pick_evicted_probe(xqc_wlb_scheduler_t *s, xqc_connection_t *conn,
                       xqc_packet_out_t *packet_out, int check_cwnd,
                       uint64_t now_us)
{
    if (s->last_evicted_probe_us == 0) {
        /* Arm the interval on first sight rather than probing immediately:
         * a path evicted at connection start still gets its probe one full
         * interval later, and a monotonic clock with an arbitrary epoch
         * cannot make the first payload packet a probe. */
        s->last_evicted_probe_us = now_us;
        return NULL;
    }
    if (now_us - s->last_evicted_probe_us < WLB_EVICTED_PROBE_INTERVAL_US) {
        return NULL;
    }

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t  *path;
    xqc_path_ctx_t  *candidates[WLB_MAX_PATHS];
    int n = 0;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (!wlb_path_transport_ok(path) || !wlb_path_blackholed(path)) {
            continue;
        }
        if (n < WLB_MAX_PATHS) {
            candidates[n++] = path;
        }
    }
    if (n == 0) {
        return NULL;
    }

    xqc_path_ctx_t *probe =
        candidates[(size_t)(s->next_evicted_probe_path % (uint64_t)n)];
    if (check_cwnd
        && !xqc_scheduler_check_path_can_send(probe, packet_out, check_cwnd))
    {
        /* Step the cursor anyway. A blackholed path still has everything it
         * sent in flight, so it is precisely the candidate that stays
         * cwnd-blocked; leaving the cursor parked on it would hold the
         * rotation forever and starve every other evicted path's probe --
         * the opposite of what the round-robin above promises. The interval
         * is deliberately not consumed: no probe was sent. */
        s->next_evicted_probe_path++;
        return NULL;
    }
    s->next_evicted_probe_path++;
    s->last_evicted_probe_us = now_us;
    xqc_log(s->log, XQC_LOG_INFO,
            "|wlb|evicted_probe|path:%ui|pto:%ud|",
            probe->path_id, probe->path_send_ctl->ctl_pto_count);
    return probe;
}

/**
 * Main scheduling entry point.
 *
 * 0. reinject (any flow hash)                  → MinRTT, origin path excluded.
 * 1. po_flow_hash == 0 (STREAM data, control) → MinRTT fallback.
 * 2. po_flow_hash == UNPINNED (UDP/QUIC)      → WRR without flow table.
 * 3. Otherwise (TCP datagrams)                → flow table lookup + WRR with pinning.
 */
static xqc_path_ctx_t *
xqc_wlb_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out,
    int check_cwnd, int reinject, xqc_bool_t *cc_blocked)
{
    xqc_wlb_scheduler_t *s = (xqc_wlb_scheduler_t *)scheduler;

    /* Replicas exist to ride a DIFFERENT path than their origin; flow
     * pinning (ordering protection) is meaningless for a duplicate. Route
     * every reinjection query through the fallback, which already excludes
     * the origin path and checks cwnd. */
    if (reinject) {
        return wlb_minrtt_fallback(conn, packet_out, check_cwnd, reinject, cc_blocked);
    }

    /* Everything without a flow hash -- STREAM data and control packets --
     * goes to MinRTT. For STREAM that is a deliberate choice, not an
     * unfinished case, so measure before changing it:
     *
     * A reliable stream is one ordered byte sequence, so the only question
     * left for a scheduler is how fast each path may be driven, and the cwnd
     * gate in xqc_scheduler_check_path_can_send already answers it exactly.
     * It counts bytes_in_flight PLUS path_schedule_bytes, so within a single
     * send pass MinRTT fills the lowest-SRTT path to its cwnd and then spills
     * to the next one; each path is then refilled at its own RTT, which is
     * its delivery capacity by construction. Measured on a 20ms/100Mbps +
     * 170ms/50Mbps pair: once both cwnds fill, MinRTT and weighted WRR place
     * *identical* per-path totals. Weights buy nothing there.
     *
     * Below saturation they diverge, and not in WRR's favour: WRR put 35% of
     * the stream on the 170ms path while the 20ms path still had cwnd to
     * spare, and it does not decay -- an under-fed path is app-limited, so
     * wlb_compute_goodput_weight credits it its est_bw and it keeps a
     * capacity-proportional share indefinitely (37% after six seconds).
     * Every one of those packets is a reassembly hole, and unlike a datagram
     * there is no deadline layer underneath: a tunnel-side reorder buffer can
     * give up and deliver, QUIC stream reassembly must wait for the
     * retransmission. Its only knob is the buffer bound in xqc_defs.h.
     *
     * Corollary for anyone reading a load split: aggregation is only expected
     * where one path cannot absorb the offered load. On an UNSHAPED pair,
     * 100%-on-one-path is correct behaviour. Shape the legs before calling it
     * a missed aggregation -- netem-shaped, the stream lane reaches ~96% of
     * the sum of its single-path legs on MinRTT. */
    if (packet_out->po_flow_hash == 0) {
        return wlb_minrtt_fallback(conn, packet_out, check_cwnd, reinject, cc_blocked);
    }

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    /* TCP flows are pinned to paths; UDP/QUIC use per-packet WRR */
    xqc_bool_t pin_flow = (packet_out->po_flow_hash != WLB_FLOW_HASH_UNPINNED);

    uint64_t now_us = xqc_monotonic_timestamp();

    /* Recovery probe for evicted paths — see wlb_pick_evicted_probe. Only an
     * unreliable DATAGRAM may be used here. Sending a unique reliable STREAM
     * packet down a known-blackholed path creates a receive-ordering hole;
     * the healthy paths can then deliver thousands of later frames behind it
     * and exhaust the peer's reassembly-node budget.
     *
     * As the code stands the test cannot be false: po_flow_hash is set only
     * by the datagram writer, and a packet without it already returned
     * through the MinRTT fallback above. It is kept as a statement of the
     * invariant this depends on, not as a live branch -- whoever gives a
     * STREAM packet a flow hash needs to see why that is unsafe here. */
    if (packet_out->po_frame_types & XQC_FRAME_BIT_DATAGRAM) {
        xqc_path_ctx_t *probe =
            wlb_pick_evicted_probe(s, conn, packet_out, check_cwnd, now_us);
        if (probe) {
            return probe;
        }
    }

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

    if (pin_flow) {
        wlb_flow_expire(s, now_us, conn);
    }

    /* Keep the WRR cache aligned before a pinned flow can take its fast path.
     * Pinned traffic is still a payload opportunity and must periodically
     * refresh acknowledged-delivery samples and topology state. */
    if (!wlb_active_paths_match_cache(s, conn)) {
        s->force_refresh_paths = 1;
    }

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

    /* Flow table lookup — reuse existing flow→path pinning (TCP only).
     * During recovery grace, skip flow-hit fast path so the flow can be
     * re-evaluated (and potentially steered to the recovered path). */
    if (pin_flow && !in_recovery_grace) {
        wlb_flow_entry_t *entry = wlb_flow_lookup(s, packet_out->po_flow_hash);
        if (entry) {
            xqc_path_ctx_t *path = wlb_find_path_ctx(conn, entry->path_id);

            /* Drop a pin whose path can no longer carry payload -- removed,
             * frozen, socket error, or unresponsive for several consecutive
             * PTOs (link down where sendto still succeeds but packets are
             * silently dropped). wlb_find_path_ctx already filters all four
             * through wlb_path_schedulable, so NULL is the signal; testing
             * ctl_pto_count on the returned path instead could never fire,
             * because a blackholed path never comes back from that lookup.
             * Tombstoning here rather than waiting for the once-a-second
             * wlb_flow_expire sweep matters when the failure leaves a single
             * usable path: that branch returns before reaching the re-pin
             * below, so the stale entry would otherwise survive, and a path
             * that heals within the same second would be pinned straight
             * back with no recovery grace. */
            if (path == NULL) {
                xqc_log(conn->log, XQC_LOG_INFO,
                        "|wlb|flow_evict|reason:unusable|flow:%ui|path:%ui|",
                        packet_out->po_flow_hash, entry->path_id);
                entry->hash = WLB_FLOW_TOMBSTONE;
            }

            if (path && xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
                entry->last_ts = now_us;
                xqc_log(conn->log, XQC_LOG_INFO,
                        "|wlb|flow_hit|flow:%ui|path:%ui|",
                        packet_out->po_flow_hash, path->path_id);
                wlb_note_payload_activity(s, path->path_id, now_us,
                                          XQC_TRUE);
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
            wlb_note_payload_activity(s, rpath->path_id, now_us, XQC_TRUE);
            return rpath;
        }
    }

    if (s->n_paths == 0) {
        return wlb_minrtt_fallback(conn, packet_out, check_cwnd, reinject, cc_blocked);
    }

    /* Single active path — skip WRR overhead */
    if (s->n_paths == 1) {
        xqc_path_ctx_t *path = wlb_find_path_ctx(conn, s->paths[0].path_id);
        if (path && xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            /* Single-path period: do NOT pin. Once the secondary path appears
             * in s->paths, the next packet of this flow misses the flow-table
             * lookup and goes through wlb_pick_pin_path for weighted
             * distribution. Pinning here would lock all early flows to
             * paths[0] permanently (the ever_lost_path gate withholds the
             * wipe that would otherwise rescue them). */
            wlb_note_payload_activity(s, path->path_id, now_us, XQC_TRUE);
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
            /* Choose the pin with smooth weighted allocation even if
             * it is currently cwnd-blocked. The wrr_select above already chose
             * a sendable path for this exact packet (sel_path_id); the pin is
             * what subsequent packets of this flow will key off, and it must
             * reflect the long-term best path, not transient cwnd state. */
            uint64_t pin_path_id = wlb_pick_pin_path(s, conn);
            if (pin_path_id == WLB_NO_PATH_ID) {
                pin_path_id = sel_path_id;
            }
            wlb_flow_insert(s, packet_out->po_flow_hash, pin_path_id, now_us);
            xqc_log(conn->log, XQC_LOG_INFO,
                    "|wlb|flow_pin|flow:%ui|pin:%ui|send:%ui|",
                    packet_out->po_flow_hash, pin_path_id, sel_path_id);
        }
        xqc_path_ctx_t *path = wlb_find_path_ctx(conn, sel_path_id);
        xqc_log(conn->log, XQC_LOG_INFO,
                 "|wlb|select|path_id:%ui|n_paths:%d|pinned:%d|",
                 sel_path_id, s->n_paths, (int)pin_flow);
        wlb_note_payload_activity(s, sel_path_id, now_us, XQC_FALSE);
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
    /* Weights are recomputed at round boundaries. PATH_NOT_FULL is emitted
     * for routine send batches, so treating it as a topology change would
     * continually reset deficits and make ratios batch-size dependent. */
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
    .xqc_scheduler_on_app_packet_acked = xqc_wlb_scheduler_on_app_packet_acked,
};
