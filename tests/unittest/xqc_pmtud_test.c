/**
 * @copyright Copyright (c) 2026, Abdul Wasey
 */

#include <CUnit/CUnit.h>
#include <string.h>

#include "xqc_pmtud_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_timer.h"
#include "src/transport/xqc_datagram.h"

/* not in a header: the loss detection timer callback */
void xqc_timer_loss_detection_timeout(xqc_timer_type_t type, xqc_usec_t now,
    void *user_data);

#define PMTUD_BASE 1298
#define PMTUD_CAP  1436
#define CURR(conn) ((conn)->conn_initial_path->curr_pkt_out_size)

/*
 * A connection with PMTUD on, the base size @base, and its only path at
 * @curr, enough loss state for xqc_send_ctl_detect_lost to declare packets
 * up to number 50 lost by the packet threshold.
 */
static xqc_connection_t *
xqc_test_pmtud_conn(size_t base, size_t curr)
{
    xqc_connection_t *conn = test_engine_connect();
    if (conn == NULL || conn->conn_initial_path == NULL) {
        return NULL;
    }

    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    conn->enable_pmtud = 1;
    conn->conn_settings.max_pkt_out_size = base;
    conn->conn_settings.probing_pkt_out_size = PMTUD_CAP;
    conn->pkt_out_size = curr;
    conn->max_pkt_out_size = PMTUD_CAP;
    CURR(conn) = curr;

    send_ctl->ctl_srtt = 10000;
    send_ctl->ctl_rttvar = 2000;
    send_ctl->ctl_minrtt = 8000;
    send_ctl->ctl_latest_rtt = 10000;
    send_ctl->ctl_first_rtt_sample_time = 1;
    send_ctl->ctl_largest_acked[XQC_PNS_APP_DATA] = 100;
    /* the packets acked after the probes were sent right after them */
    send_ctl->ctl_largest_acked_sent_time[XQC_PNS_APP_DATA] = 20;
    return conn;
}

/* an in-flight 1-RTT packet of @size bytes, PING only, sent at @sent */
static xqc_packet_out_t *
xqc_test_pmtud_unacked(xqc_connection_t *conn, xqc_packet_number_t pn,
    size_t size, xqc_usec_t sent, xqc_bool_t probe)
{
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_packet_out_t *po = xqc_packet_out_get(sq);
    if (po == NULL) {
        return NULL;
    }

    po->po_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    po->po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    po->po_pkt.pkt_num = pn;
    po->po_path_id = send_ctl->ctl_path->path_id;
    po->po_sent_time = sent;
    po->po_flag = XQC_POF_IN_FLIGHT | (probe ? XQC_POF_PMTUD_PROBING : 0);
    po->po_frame_types = XQC_FRAME_BIT_PING;
    po->po_buf_size = size;
    po->po_used_size = probe ? 1 : size;

    xqc_send_queue_insert_unacked(po,
        &sq->sndq_unacked_packets[XQC_PNS_APP_DATA], sq);
    return po;
}

static void
xqc_test_pmtud_detect(xqc_connection_t *conn)
{
    xqc_send_ctl_detect_lost(conn->conn_initial_path->path_send_ctl,
                             conn->conn_send_queue, XQC_PNS_APP_DATA, 1000000);
}

/* three probes at the current size, sent after the path became suspect */
static void
xqc_test_pmtud_lose_probes(xqc_connection_t *conn, size_t size)
{
    for (int i = 1; i <= 3; i++) {
        CU_ASSERT_FATAL(xqc_test_pmtud_unacked(conn, i, size, 10, XQC_TRUE)
                        != NULL);
    }
    xqc_test_pmtud_detect(conn);
}


/* RFC 8899 4.3: large packets keep getting lost while smaller ones are
 * acked, so the path becomes suspect. */
void
xqc_test_pmtud_big_losses_make_path_suspect(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1400);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    for (int i = 1; i <= XQC_PMTUD_BLACKHOLE_LOSSES; i++) {
        CU_ASSERT_FATAL(xqc_test_pmtud_unacked(conn, i, 1400, 10, XQC_FALSE)
                        != NULL);
    }
    xqc_test_pmtud_detect(conn);

    CU_ASSERT(send_ctl->ctl_bh_suspect_time != 0);
    /* suspect only: the probes decide */
    CU_ASSERT_EQUAL(CURR(conn), 1400);

    xqc_engine_destroy(conn->engine);
}

/* losses of packets that are not above the base size say nothing about
 * the path MTU */
void
xqc_test_pmtud_small_losses_do_not_make_path_suspect(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1400);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    for (int i = 1; i <= XQC_PMTUD_BLACKHOLE_LOSSES + 2; i++) {
        CU_ASSERT_FATAL(xqc_test_pmtud_unacked(conn, i, 1000, 10, XQC_FALSE)
                        != NULL);
    }
    xqc_test_pmtud_detect(conn);

    CU_ASSERT_EQUAL(send_ctl->ctl_bh_suspect_time, 0);

    xqc_engine_destroy(conn->engine);
}

/* a suspect path loses its probes at the current size: black hole, back to
 * the base size, search again below the size that failed */
void
xqc_test_pmtud_blackhole_confirmed_by_probes(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1400);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    send_ctl->ctl_bh_suspect_time = 1;

    xqc_test_pmtud_lose_probes(conn, 1400);

    CU_ASSERT_EQUAL(CURR(conn), PMTUD_BASE);
    CU_ASSERT_EQUAL(conn->pkt_out_size, PMTUD_BASE);
    CU_ASSERT_EQUAL(conn->max_pkt_out_size, 1399);
    CU_ASSERT_EQUAL(send_ctl->ctl_bh_suspect_time, 0);

    xqc_engine_destroy(conn->engine);
}

/* the same probes lost while the path is not suspect are search probes
 * that did not fit: no black hole */
void
xqc_test_pmtud_search_probe_loss_is_not_blackhole(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1400);
    CU_ASSERT_FATAL(conn != NULL);

    xqc_test_pmtud_lose_probes(conn, 1400);

    CU_ASSERT_EQUAL(CURR(conn), 1400);
    CU_ASSERT_EQUAL(conn->pkt_out_size, 1400);

    xqc_engine_destroy(conn->engine);
}

/* at the base size, a black hole confirmed while smaller packets still get
 * through means the path is smaller than the base: go down to the floor */
void
xqc_test_pmtud_blackhole_at_base_goes_to_floor(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE,
                                                 PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    send_ctl->ctl_bh_suspect_time = 1;

    xqc_test_pmtud_lose_probes(conn, PMTUD_BASE);

    CU_ASSERT_EQUAL(CURR(conn), XQC_PMTUD_FLOOR);
    CU_ASSERT_EQUAL(conn->pkt_out_size, XQC_PMTUD_FLOOR);
    CU_ASSERT_EQUAL(conn->max_pkt_out_size, PMTUD_BASE - 1);

    xqc_engine_destroy(conn->engine);
}

/* the probes were lost with everything sent around them, and only
 * packets sent long after got through: the path was down, not small, and
 * the size stays at the base */
void
xqc_test_pmtud_outage_at_base_keeps_base(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE,
                                                 PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    send_ctl->ctl_bh_suspect_time = 1;
    send_ctl->ctl_largest_acked_sent_time[XQC_PNS_APP_DATA] = 2000000;

    xqc_test_pmtud_lose_probes(conn, PMTUD_BASE);

    CU_ASSERT_EQUAL(CURR(conn), PMTUD_BASE);
    CU_ASSERT_EQUAL(conn->pkt_out_size, PMTUD_BASE);
    CU_ASSERT_EQUAL(send_ctl->ctl_bh_suspect_time, 0);

    xqc_engine_destroy(conn->engine);
}

/* a lost STREAM packet built at a larger size: its data goes into new
 * packets of the current size, none of it lost */
void
xqc_test_pmtud_split_lost_stream_packet(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE,
                                                 PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
        XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_FATAL(stream != NULL);

    unsigned char data[1350];
    memset(data, 'x', sizeof(data));
    xqc_packet_out_t *po = xqc_test_pmtud_unacked(conn, 1, 1400, 10,
                                                    XQC_FALSE);
    CU_ASSERT_FATAL(po != NULL);
    po->po_used_size = 0;
    po->po_frame_types = 0;
    size_t written = 0;
    int n = xqc_gen_stream_frame(po, stream->stream_id, 0, 0, data,
                                 sizeof(data), &written);
    CU_ASSERT_FATAL(n > 0 && written == sizeof(data));
    po->po_used_size += n;
    CU_ASSERT_FATAL(po->po_used_size > conn->pkt_out_size);
    xqc_conn_increase_unacked_stream_ref(conn, po);

    CU_ASSERT_EQUAL(xqc_conn_pmtud_split_lost(conn, po), XQC_OK);
    CU_ASSERT(po->po_acked);

    size_t total = 0;
    int count = 0;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->conn_send_queue->sndq_lost_packets) {
        xqc_packet_out_t *npo = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        CU_ASSERT(npo->po_used_size <= conn->pkt_out_size);
        CU_ASSERT(npo->po_stream_frames[0].ps_is_used);
        total += npo->po_stream_frames[0].ps_length;
        count++;
    }
    CU_ASSERT(count >= 2);
    CU_ASSERT_EQUAL(total, sizeof(data));

    xqc_engine_destroy(conn->engine);
}

/* only STREAM packets that no longer fit are split */
void
xqc_test_pmtud_split_lost_rejects_other_packets(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE,
                                                 PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);

    /* a DATAGRAM cannot be split */
    xqc_packet_out_t *dgram = xqc_test_pmtud_unacked(conn, 1, 1400, 10,
                                                    XQC_FALSE);
    CU_ASSERT_FATAL(dgram != NULL);
    dgram->po_frame_types = XQC_FRAME_BIT_DATAGRAM;
    CU_ASSERT_EQUAL(xqc_conn_pmtud_split_lost(conn, dgram), -XQC_EPARAM);

    /* a STREAM packet that still fits is retransmitted as it is */
    xqc_packet_out_t *fits = xqc_test_pmtud_unacked(conn, 2, 1400, 10,
                                                    XQC_FALSE);
    CU_ASSERT_FATAL(fits != NULL);
    fits->po_frame_types = XQC_FRAME_BIT_STREAM;
    fits->po_used_size = 1000;
    CU_ASSERT_EQUAL(xqc_conn_pmtud_split_lost(conn, fits), -XQC_EPARAM);
    CU_ASSERT(!fits->po_acked);

    xqc_engine_destroy(conn->engine);
}

/* a DATAGRAM packet built before the size went down is dropped instead of
 * sent into the black hole */
void
xqc_test_pmtud_drop_oversize_datagram(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE,
                                                 PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);

    xqc_packet_out_t *po = xqc_test_pmtud_unacked(conn, 1, 1400, 10,
                                                    XQC_FALSE);
    CU_ASSERT_FATAL(po != NULL);
    po->po_frame_types = XQC_FRAME_BIT_DATAGRAM;

    CU_ASSERT(xqc_conn_pmtud_drop_oversize(conn, po));

    xqc_engine_destroy(conn->engine);
}

/* probes are larger on purpose, and a packet that fits goes out */
void
xqc_test_pmtud_drop_oversize_keeps_probes_and_fitting(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE,
                                                 PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);

    xqc_packet_out_t *probe = xqc_test_pmtud_unacked(conn, 1, 1400, 10,
                                                    XQC_TRUE);
    CU_ASSERT_FATAL(probe != NULL);
    probe->po_used_size = 1400;
    CU_ASSERT(!xqc_conn_pmtud_drop_oversize(conn, probe));

    xqc_packet_out_t *fits = xqc_test_pmtud_unacked(conn, 2, 1200, 10,
                                                    XQC_FALSE);
    CU_ASSERT_FATAL(fits != NULL);
    fits->po_frame_types = XQC_FRAME_BIT_DATAGRAM;
    CU_ASSERT(!xqc_conn_pmtud_drop_oversize(conn, fits));

    xqc_engine_destroy(conn->engine);
}

/* the search stops once the size is known within the precision */
void
xqc_test_pmtud_search_stops_within_precision(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1300);
    CU_ASSERT_FATAL(conn != NULL);
    conn->max_pkt_out_size = 1300 + XQC_PMTUD_SEARCH_PRECISION - 1;
    conn->probing_pkt_out_size = 1301;
    conn->conn_flag |= XQC_CONN_FLAG_PMTUD_PROBING
                       | XQC_CONN_FLAG_CAN_SEND_1RTT;

    xqc_conn_ptmud_probing(conn);

    CU_ASSERT(!(conn->conn_flag & XQC_CONN_FLAG_PMTUD_PROBING));
    /* below the cap: a new search from the top later */
    CU_ASSERT_EQUAL(conn->max_pkt_out_size, PMTUD_CAP);
    CU_ASSERT(xqc_timer_is_set(&conn->conn_timer_manager,
                               XQC_TIMER_PMTUD_PROBING));

    xqc_engine_destroy(conn->engine);
}

/* a wider range is probed, and the probe is waited for about a PTO */
void
xqc_test_pmtud_search_probes_wide_range(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1300);
    CU_ASSERT_FATAL(conn != NULL);
    conn->max_pkt_out_size = 1400;
    conn->probing_pkt_out_size = 1350;
    conn->probing_cnt = 0;
    conn->conn_flag |= XQC_CONN_FLAG_PMTUD_PROBING
                       | XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn->conn_initial_path->path_state = XQC_PATH_STATE_ACTIVE;

    xqc_conn_ptmud_probing(conn);

    CU_ASSERT_EQUAL(conn->probing_cnt, 1);
    CU_ASSERT_EQUAL(conn->max_pkt_out_size, 1400);
    CU_ASSERT(xqc_timer_is_set(&conn->conn_timer_manager,
                               XQC_TIMER_PMTUD_PROBING));

    xqc_engine_destroy(conn->engine);
}

/* the same above the base size: an outage is not a black hole */
void
xqc_test_pmtud_outage_is_not_blackhole(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1400);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    send_ctl->ctl_bh_suspect_time = 1;
    send_ctl->ctl_largest_acked_sent_time[XQC_PNS_APP_DATA] = 2000000;

    xqc_test_pmtud_lose_probes(conn, 1400);

    CU_ASSERT_EQUAL(CURR(conn), 1400);
    CU_ASSERT_EQUAL(send_ctl->ctl_bh_suspect_time, 0);

    xqc_engine_destroy(conn->engine);
}

/* an acked packet above the base size, whatever it carries, clears a
 * suspicion: large packets do get through */
static void
xqc_test_pmtud_ack(xqc_connection_t *conn, size_t size,
    xqc_frame_type_bit_t frames)
{
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_packet_out_t *po = xqc_test_pmtud_unacked(conn, 60, size, 10,
                                                  XQC_FALSE);
    CU_ASSERT_FATAL(po != NULL);
    po->po_frame_types = frames;
    send_ctl->ctl_bh_suspect_time = 1;
    xqc_send_ctl_on_packet_acked(send_ctl, po, 1000000, 1);
}

void
xqc_test_pmtud_acked_large_data_clears_suspicion(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1400);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    xqc_test_pmtud_ack(conn, 1400, XQC_FRAME_BIT_DATAGRAM);

    CU_ASSERT_EQUAL(send_ctl->ctl_bh_suspect_time, 0);
    CU_ASSERT_EQUAL(send_ctl->ctl_largest_big_acked, 60);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_pmtud_acked_small_data_keeps_suspicion(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1400);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    xqc_test_pmtud_ack(conn, 1000, XQC_FRAME_BIT_DATAGRAM);

    CU_ASSERT_EQUAL(send_ctl->ctl_bh_suspect_time, 1);
    CU_ASSERT_EQUAL(send_ctl->ctl_largest_big_acked, 0);

    xqc_engine_destroy(conn->engine);
}

/* RFC 8899 s3 item 7: probes that skip the congestion window go at most
 * once per RTT */
void
xqc_test_pmtud_blackhole_probes_one_rtt_apart(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1400);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    send_ctl->ctl_bh_suspect_time = 1;
    send_ctl->ctl_bh_probe_time = 100000;
    send_ctl->ctl_bh_probes_sent = 1;

    xqc_send_ctl_pmtud_bh_maybe_probe(send_ctl,
                                      100000 + send_ctl->ctl_srtt - 1);
    CU_ASSERT_EQUAL(send_ctl->ctl_bh_probes_sent, 1);

    xqc_send_ctl_pmtud_bh_maybe_probe(send_ctl,
                                      100000 + send_ctl->ctl_srtt);
    CU_ASSERT_EQUAL(send_ctl->ctl_bh_probes_sent, 2);

    xqc_engine_destroy(conn->engine);
}

/* a suspect path with 1-RTT data in flight and nothing acked */
static void
xqc_test_pmtud_arm_pto(xqc_connection_t *conn)
{
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;

    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT
                       | XQC_CONN_FLAG_HANDSHAKE_COMPLETED
                       | XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    send_ctl->ctl_bytes_in_flight = 1400;
    send_ctl->ctl_bytes_ack_eliciting_inflight[XQC_PNS_APP_DATA] = 1400;
    send_ctl->ctl_bh_suspect_time = 1;
    send_ctl->ctl_bh_probe_time = 1;
    send_ctl->ctl_bh_probes_sent = 1;
}

/* a suspect path where nothing is acked any more: the PTO sends the next
 * probe, or nothing would */
void
xqc_test_pmtud_pto_on_suspect_path_sends_probe(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1400);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_test_pmtud_arm_pto(conn);

    xqc_timer_loss_detection_timeout(XQC_TIMER_LOSS_DETECTION, 1000000,
                                     send_ctl);

    CU_ASSERT_EQUAL(send_ctl->ctl_bh_probes_sent, 2);

    xqc_engine_destroy(conn->engine);
}

/* RFC 9000 s14.3: QUIC declaring a search probe lost brings the next
 * attempt one RTT later, well before the 1 s probe timer */
void
xqc_test_pmtud_lost_search_probe_retries_soon(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1300);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    conn->probing_pkt_out_size = 1350;

    CU_ASSERT_FATAL(xqc_test_pmtud_unacked(conn, 1, 1350, 10, XQC_TRUE)
                    != NULL);
    xqc_test_pmtud_detect(conn);

    xqc_timer_t *timer =
        &conn->conn_timer_manager.timer[XQC_TIMER_PMTUD_PROBING];
    CU_ASSERT(timer->timer_is_set);
    CU_ASSERT_EQUAL(timer->expire_time, 1000000 + send_ctl->ctl_srtt);

    xqc_engine_destroy(conn->engine);
}

/* a lost probe of an older size says nothing about the current attempt */
void
xqc_test_pmtud_stale_probe_loss_does_not_retry(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1300);
    CU_ASSERT_FATAL(conn != NULL);
    conn->probing_pkt_out_size = 1350;

    CU_ASSERT_FATAL(xqc_test_pmtud_unacked(conn, 1, 1400, 10, XQC_TRUE)
                    != NULL);
    xqc_test_pmtud_detect(conn);

    CU_ASSERT(!xqc_timer_is_set(&conn->conn_timer_manager,
                                XQC_TIMER_PMTUD_PROBING));

    xqc_engine_destroy(conn->engine);
}

static int g_pmtud_dgram_lost;

static xqc_int_t
xqc_test_pmtud_dgram_lost_cb(xqc_connection_t *conn, uint64_t dgram_id,
    void *user_data)
{
    (void)conn;
    (void)dgram_id;
    (void)user_data;
    g_pmtud_dgram_lost++;
    return 0;
}

/* a DATAGRAM with a copy, both too large: reported lost once, not once
 * per copy */
void
xqc_test_pmtud_dgram_with_copy_lost_once(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);
    conn->app_proto_cbs.dgram_cbs.datagram_lost_notify =
        xqc_test_pmtud_dgram_lost_cb;
    conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
    g_pmtud_dgram_lost = 0;

    xqc_packet_out_t *origin = xqc_test_pmtud_unacked(conn, 1, 1400, 10,
                                                      XQC_FALSE);
    xqc_packet_out_t *copy = xqc_test_pmtud_unacked(conn, 2, 1400, 10,
                                                    XQC_FALSE);
    CU_ASSERT_FATAL(origin != NULL && copy != NULL);
    origin->po_frame_types = XQC_FRAME_BIT_DATAGRAM;
    copy->po_frame_types = XQC_FRAME_BIT_DATAGRAM;
    copy->po_origin = origin;
    origin->po_origin_ref_cnt = 1;

    CU_ASSERT(xqc_conn_pmtud_drop_oversize(conn, copy));
    CU_ASSERT(xqc_conn_pmtud_drop_oversize(conn, origin));
    CU_ASSERT_EQUAL(g_pmtud_dgram_lost, 1);

    xqc_engine_destroy(conn->engine);
}

/* RFC 9000 s8.2.1: PATH_CHALLENGE is expanded to 1200 bytes, not to the
 * size found on another path */
void
xqc_test_pmtud_path_challenge_padded_to_1200(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1400);
    CU_ASSERT_FATAL(conn != NULL);

    xqc_packet_out_t *po = xqc_test_pmtud_unacked(conn, 1, 1400, 10,
                                                  XQC_FALSE);
    CU_ASSERT_FATAL(po != NULL);
    po->po_frame_types = XQC_FRAME_BIT_PATH_CHALLENGE;
    po->po_used_size = 30;

    xqc_gen_padding_frame(conn, po);
    CU_ASSERT_EQUAL(po->po_used_size,
                    XQC_PACKET_INITIAL_MIN_LENGTH - XQC_TLS_AEAD_OVERHEAD_MAX_LEN);

    xqc_engine_destroy(conn->engine);
}

/* a PMTUD probe still takes the size it probes */
void
xqc_test_pmtud_probe_padded_to_probed_size(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1300);
    CU_ASSERT_FATAL(conn != NULL);

    xqc_packet_out_t *po = xqc_test_pmtud_unacked(conn, 1, 1400, 10,
                                                  XQC_TRUE);
    CU_ASSERT_FATAL(po != NULL);
    po->po_used_size = 30;

    xqc_gen_padding_frame(conn, po);
    CU_ASSERT_EQUAL(po->po_used_size, 1400 + XQC_ACK_SPACE);

    xqc_engine_destroy(conn->engine);
}

/* a validated new path at the base size brings the connection down to it
 * and starts a new search over the whole range */
void
xqc_test_pmtud_new_path_lowers_connection_size(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1400);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_path_ctx_t path;
    memset(&path, 0, sizeof(path));
    path.path_id = 1;
    path.curr_pkt_out_size = PMTUD_BASE;

    xqc_conn_pmtud_on_new_path(conn, &path);

    CU_ASSERT_EQUAL(conn->pkt_out_size, PMTUD_BASE);
    CU_ASSERT_EQUAL(conn->max_pkt_out_size, PMTUD_CAP);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_PMTUD_PROBING) != 0);

    xqc_engine_destroy(conn->engine);
}

/* a new path already as large as the connection size changes nothing */
void
xqc_test_pmtud_new_path_not_smaller_keeps_size(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);
    conn->max_pkt_out_size = 1350;
    xqc_path_ctx_t path;
    memset(&path, 0, sizeof(path));
    path.path_id = 1;
    path.curr_pkt_out_size = PMTUD_BASE;

    xqc_conn_pmtud_on_new_path(conn, &path);

    CU_ASSERT_EQUAL(conn->pkt_out_size, PMTUD_BASE);
    CU_ASSERT_EQUAL(conn->max_pkt_out_size, 1350);

    xqc_engine_destroy(conn->engine);
}

/* without 1-RTT keys, a PTO sends no PMTUD probe, which is a 1-RTT packet */
void
xqc_test_pmtud_pto_before_1rtt_sends_no_probe(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, 1400);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    xqc_test_pmtud_arm_pto(conn);
    conn->conn_flag &= ~XQC_CONN_FLAG_CAN_SEND_1RTT;

    xqc_timer_loss_detection_timeout(XQC_TIMER_LOSS_DETECTION, 1000000,
                                     send_ctl);

    CU_ASSERT_EQUAL(send_ctl->ctl_bh_probes_sent, 1);

    xqc_engine_destroy(conn->engine);
}

/* the lost packets in the lost list: each fits, and the frames they carry */
static void
xqc_test_pmtud_lost_list(xqc_connection_t *conn, size_t *stream_bytes,
    int *rest_count, int *rest_with_stream)
{
    xqc_list_head_t *pos;

    *stream_bytes = 0;
    *rest_count = 0;
    *rest_with_stream = 0;
    xqc_list_for_each(pos, &conn->conn_send_queue->sndq_lost_packets) {
        xqc_packet_out_t *npo = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        CU_ASSERT(npo->po_used_size <= conn->pkt_out_size);
        if (npo->po_frame_types & XQC_FRAME_BIT_MAX_DATA) {
            (*rest_count)++;
            CU_ASSERT(npo->po_origin == NULL);
            if (npo->po_frame_types & XQC_FRAME_BIT_STREAM) {
                (*rest_with_stream)++;
            }

        } else if (npo->po_stream_frames[0].ps_is_used) {
            *stream_bytes += npo->po_stream_frames[0].ps_length;
        }
    }
}

/* a lost STREAM packet that also carries MAX_DATA: the stream data is
 * split, and MAX_DATA goes in a packet of its own, not lost with the rest */
void
xqc_test_pmtud_split_keeps_control_frames(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE,
                                                 PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_stream_t *stream = xqc_create_stream_with_conn(conn,
        XQC_UNDEFINE_STREAM_ID, XQC_CLI_BID, NULL, NULL);
    CU_ASSERT_FATAL(stream != NULL);

    unsigned char data[1340];
    memset(data, 'y', sizeof(data));
    xqc_packet_out_t *po = xqc_test_pmtud_unacked(conn, 1, 1400, 10,
                                                  XQC_FALSE);
    CU_ASSERT_FATAL(po != NULL);
    po->po_used_size = 0;
    po->po_frame_types = 0;
    size_t written = 0;
    int n = xqc_gen_stream_frame(po, stream->stream_id, 0, 0, data,
                                 sizeof(data), &written);
    CU_ASSERT_FATAL(n > 0 && written == sizeof(data));
    po->po_used_size += n;
    po->po_used_size += xqc_gen_max_data_frame(po, 1 << 20);
    CU_ASSERT_FATAL(po->po_used_size > conn->pkt_out_size);
    xqc_conn_increase_unacked_stream_ref(conn, po);

    CU_ASSERT_EQUAL(xqc_conn_pmtud_split_lost(conn, po), XQC_OK);

    size_t total;
    int rest, rest_stream;
    xqc_test_pmtud_lost_list(conn, &total, &rest, &rest_stream);
    CU_ASSERT_EQUAL(total, sizeof(data));
    CU_ASSERT_EQUAL(rest, 1);
    CU_ASSERT_EQUAL(rest_stream, 0);

    xqc_engine_destroy(conn->engine);
}

/* a lost packet of control frames only, padded beyond the current size:
 * resent without the padding */
void
xqc_test_pmtud_split_control_only_packet(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE,
                                                 PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);

    xqc_packet_out_t *po = xqc_test_pmtud_unacked(conn, 1, 1400, 10,
                                                  XQC_FALSE);
    CU_ASSERT_FATAL(po != NULL);
    po->po_used_size = 0;
    po->po_frame_types = 0;
    po->po_used_size += xqc_gen_max_data_frame(po, 1 << 20);
    po->po_padding = po->po_buf + po->po_used_size;
    memset(po->po_padding, 0, 1390 - po->po_used_size);
    po->po_used_size = 1390;
    po->po_frame_types |= XQC_FRAME_BIT_PADDING;

    CU_ASSERT_EQUAL(xqc_conn_pmtud_split_lost(conn, po), XQC_OK);

    size_t total;
    int rest, rest_stream;
    xqc_test_pmtud_lost_list(conn, &total, &rest, &rest_stream);
    CU_ASSERT_EQUAL(rest, 1);

    xqc_engine_destroy(conn->engine);
}

/* a DATAGRAM sharing a packet with other frames is neither dropped nor
 * split: the datagram frame cannot be cut out */
void
xqc_test_pmtud_mixed_datagram_not_dropped(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE,
                                                 PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);

    xqc_packet_out_t *po = xqc_test_pmtud_unacked(conn, 1, 1400, 10,
                                                  XQC_FALSE);
    CU_ASSERT_FATAL(po != NULL);
    po->po_frame_types = XQC_FRAME_BIT_DATAGRAM | XQC_FRAME_BIT_NEW_TOKEN;

    CU_ASSERT(!xqc_conn_pmtud_drop_oversize(conn, po));
    CU_ASSERT_EQUAL(xqc_conn_pmtud_split_lost(conn, po), -XQC_EPARAM);

    xqc_engine_destroy(conn->engine);
}

/* a DATAGRAM packet waiting in the send queue, with room left */
static xqc_packet_out_t *
xqc_test_pmtud_queued_dgram(xqc_connection_t *conn)
{
    xqc_packet_out_t *po = xqc_packet_out_get_and_insert_send(
        conn->conn_send_queue, XQC_PTYPE_SHORT_HEADER);
    if (po != NULL) {
        po->po_frame_types = XQC_FRAME_BIT_DATAGRAM;
        po->po_used_size = 100;
    }
    return po;
}

/* with PMTUD, a control frame never goes into a packet with a DATAGRAM:
 * such a packet is dropped whole after a black hole */
void
xqc_test_pmtud_control_frame_not_added_to_datagram(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_packet_out_t *dgram = xqc_test_pmtud_queued_dgram(conn);
    CU_ASSERT_FATAL(dgram != NULL);

    xqc_packet_out_t *po = xqc_send_queue_get_packet_out(
        conn->conn_send_queue, 20, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(po != NULL && po != dgram);

    xqc_engine_destroy(conn->engine);
}

/* without PMTUD, packets are filled as before */
void
xqc_test_pmtud_off_control_frame_shares_datagram(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);
    conn->enable_pmtud = 0;
    xqc_packet_out_t *dgram = xqc_test_pmtud_queued_dgram(conn);
    CU_ASSERT_FATAL(dgram != NULL);

    xqc_packet_out_t *po = xqc_send_queue_get_packet_out(
        conn->conn_send_queue, 20, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(po == dgram);

    xqc_engine_destroy(conn->engine);
}

/* a lost oversize STREAM packet built at 1400 bytes, @extra frame bits
 * added, on a fresh stream */
static xqc_packet_out_t *
xqc_test_pmtud_stream_packet(xqc_connection_t *conn, xqc_stream_t **stream)
{
    *stream = xqc_create_stream_with_conn(conn, XQC_UNDEFINE_STREAM_ID,
                                          XQC_CLI_BID, NULL, NULL);
    if (*stream == NULL) {
        return NULL;
    }
    unsigned char data[1340];
    memset(data, 'z', sizeof(data));
    xqc_packet_out_t *po = xqc_test_pmtud_unacked(conn, 1, 1400, 10,
                                                  XQC_FALSE);
    if (po == NULL) {
        return NULL;
    }
    po->po_used_size = 0;
    po->po_frame_types = 0;
    size_t written = 0;
    int n = xqc_gen_stream_frame(po, (*stream)->stream_id, 0, 0, data,
                                 sizeof(data), &written);
    if (n < 0) {
        return NULL;
    }
    po->po_used_size += n;
    return po;
}

/* a RESET_STREAM entry is not split as stream data: it goes with the
 * rest packet, and no empty STREAM frame is made from it */
void
xqc_test_pmtud_split_skips_reset_stream(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_stream_t *stream;
    xqc_packet_out_t *po = xqc_test_pmtud_stream_packet(conn, &stream);
    CU_ASSERT_FATAL(po != NULL);
    /* a RESET_STREAM entry after the STREAM frame */
    po->po_stream_frames[1].ps_stream_id = stream->stream_id;
    po->po_stream_frames[1].ps_is_reset = 1;
    po->po_stream_frames[1].ps_is_used = 1;
    po->po_frame_types |= XQC_FRAME_BIT_RESET_STREAM;
    xqc_conn_increase_unacked_stream_ref(conn, po);

    CU_ASSERT_EQUAL(xqc_conn_pmtud_split_lost(conn, po), XQC_OK);

    int empty = 0, resets = 0;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &conn->conn_send_queue->sndq_lost_packets) {
        xqc_packet_out_t *npo = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        if (npo->po_frame_types & XQC_FRAME_BIT_RESET_STREAM) {
            resets++;
            CU_ASSERT(npo->po_stream_frames[0].ps_is_reset);
        } else if (npo->po_stream_frames[0].ps_is_used
                   && npo->po_stream_frames[0].ps_length == 0)
        {
            empty++;
        }
    }
    CU_ASSERT_EQUAL(resets, 1);
    CU_ASSERT_EQUAL(empty, 0);

    xqc_engine_destroy(conn->engine);
}

/* a rest packet with nothing to resend goes back to the free list without
 * unbalancing the count of packets in use */
void
xqc_test_pmtud_unneeded_rest_keeps_packet_count(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE, PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_stream_t *stream;
    xqc_packet_out_t *po = xqc_test_pmtud_stream_packet(conn, &stream);
    CU_ASSERT_FATAL(po != NULL);
    /* a frame outside the split set that needs no repair */
    po->po_frame_types |= XQC_FRAME_BIT_CONNECTION_CLOSE;
    xqc_conn_increase_unacked_stream_ref(conn, po);
    xqc_send_queue_t *sq = conn->conn_send_queue;
    uint64_t used = sq->sndq_packets_used;

    CU_ASSERT_EQUAL(xqc_conn_pmtud_split_lost(conn, po), XQC_OK);

    uint64_t added = 0;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &sq->sndq_lost_packets) {
        added++;
    }
    CU_ASSERT(added >= 2);
    CU_ASSERT_EQUAL(sq->sndq_packets_used, used + added);

    xqc_engine_destroy(conn->engine);
}
