#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_time.h"

xqc_bool_t
xqc_scheduler_check_path_can_send(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, int check_cwnd)
{
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    uint32_t schedule_bytes = path->path_schedule_bytes;

    /* normal packets in send list will be blocked by cc */
    if (check_cwnd && (!xqc_send_packet_cwnd_allows(send_ctl, packet_out, schedule_bytes, 0)))
    {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|path:%ui|blocked by cwnd|", path->path_id);
        return XQC_FALSE;
    }

    return XQC_TRUE;
}

/* Does one full-size packet fit @path's congestion window? The probe list
 * is not held back by congestion control, so the probe checks it itself. */
static xqc_bool_t
xqc_scheduler_probe_fits_cwnd(xqc_path_ctx_t *path)
{
    xqc_packet_out_t probe;

    memset(&probe, 0, sizeof(probe));
    probe.po_used_size = path->curr_pkt_out_size;
    return xqc_send_ctl_can_send(path->path_send_ctl, &probe,
                                 path->path_schedule_bytes);
}

/* A dead path that a scheduler skips gets no data, so only its PTO probes
 * could be acknowledged when it comes back, and those are backed off to
 * seconds apart after a few PTOs. Send it a PING once per interval instead:
 * its ACK clears the PTO count, and the path is used again soon after it
 * returns. The interval is kept per connection, so PINGs cannot pile up on
 * the probe list while they wait to be sent. */
void
xqc_scheduler_probe_dead_paths(xqc_connection_t *conn, xqc_usec_t *last_probe)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_usec_t now, last_sent;

    if (conn->conn_state != XQC_CONN_STATE_ESTABED) {
        return;
    }

    now = xqc_monotonic_timestamp();
    if (now - *last_probe < XQC_SCHED_DEAD_PROBE_INTERVAL_US) {
        return;
    }

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE
            || path->app_path_status == XQC_APP_PATH_STATUS_FROZEN
            || !xqc_path_is_dead_with_alternative(path))
        {
            continue;
        }

        /* Not before the third PTO that fired, which moved the path's data
         * to the other paths (xqc_path_requeue_unacked_on_pto). The path
         * can count as dead earlier, from expiries hidden by sends, and a
         * PING re-arms the loss detection timer from its send time: with a
         * PTO above a quarter of the interval the third PTO would never
         * fire, and the data would wait for the path idle timeout. After
         * it, only the PTO probes are in flight, so the PING fits the
         * congestion window too, unless the window says otherwise. */
        if (path->path_send_ctl->ctl_pto_count < XQC_PATH_REQUEUE_PTO_THRESH
            || !xqc_scheduler_probe_fits_cwnd(path))
        {
            continue;
        }

        last_sent = path->path_send_ctl
                        ->ctl_time_of_last_sent_ack_eliciting_packet[XQC_PNS_APP_DATA];
        if (now - last_sent < XQC_SCHED_DEAD_PROBE_INTERVAL_US) {
            continue;
        }

        if (xqc_path_send_ping_to_probe(path, XQC_PNS_APP_DATA,
                                        XQC_PATH_SPECIFIED_BY_PQP) == XQC_OK)
        {
            *last_probe = now;
            xqc_log(conn->log, XQC_LOG_DEBUG,
                    "|path:%ui|pto:%ud|dead path probed|", path->path_id,
                    path->path_send_ctl->ctl_pto_count);
        }
    }
}
