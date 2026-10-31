#ifndef _XQC_SCHEDULER_COMMON_H_INCLUDED_
#define _XQC_SCHEDULER_COMMON_H_INCLUDED_

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>

xqc_bool_t xqc_scheduler_check_path_can_send(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, int check_cwnd);

/* PING a dead path (xqc_path_is_dead_with_alternative) at most once per
 * XQC_SCHED_DEAD_PROBE_INTERVAL_US, so its ACK clears the PTO count soon
 * after it is back. *last_probe is the caller's per-connection state. */
#define XQC_SCHED_DEAD_PROBE_INTERVAL_US (500 * 1000)
void xqc_scheduler_probe_dead_paths(xqc_connection_t *conn, xqc_usec_t *last_probe);

#endif