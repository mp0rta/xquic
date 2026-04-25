/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WLB (Weighted Load Balancing) multipath scheduler for QUIC Datagrams.
 *
 * Flow-affinity WRR with LATE-based weight estimation.
 * Inner flows are pinned to paths via hash table to prevent TCP reordering.
 */

#ifndef _XQC_SCHEDULER_WLB_H_INCLUDED_
#define _XQC_SCHEDULER_WLB_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

extern const xqc_scheduler_callback_t xqc_wlb_scheduler_cb;

#endif /* _XQC_SCHEDULER_WLB_H_INCLUDED_ */
