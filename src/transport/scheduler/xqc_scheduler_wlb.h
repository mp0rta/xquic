/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WLB (Weighted Load Balancing) multipath scheduler for QUIC Datagrams.
 *
 * Flow-affinity WRR weighted by acknowledged-goodput learning.
 * Inner flows are pinned to paths via hash table to prevent TCP reordering.
 * See xqc_scheduler_wlb.c for the algorithm and its rationale.
 */

#ifndef _XQC_SCHEDULER_WLB_H_INCLUDED_
#define _XQC_SCHEDULER_WLB_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

extern const xqc_scheduler_callback_t xqc_wlb_scheduler_cb;

/* Per-path view of what the scheduler has learned. Internal: the unit tests
 * observe weight and goodput learning through it. Not public API -- no
 * consumer of this fork reads per-path scheduler stats, and exporting them
 * would pin the shape in the ABI. */
typedef struct {
    uint64_t path_id;
    uint64_t goodput_Bps;
    uint8_t  weight_pct;
    uint8_t  warmup;
} xqc_wlb_path_stats_t;

int xqc_wlb_scheduler_copy_path_stats(void *scheduler, xqc_wlb_path_stats_t *out,
                                      size_t capacity, size_t *out_count);

#endif /* _XQC_SCHEDULER_WLB_H_INCLUDED_ */
