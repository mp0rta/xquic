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
    send_ctl->ctl_bh_small_acked = 1;

    xqc_test_pmtud_lose_probes(conn, PMTUD_BASE);

    CU_ASSERT_EQUAL(CURR(conn), XQC_PMTUD_FLOOR);
    CU_ASSERT_EQUAL(conn->pkt_out_size, XQC_PMTUD_FLOOR);
    CU_ASSERT_EQUAL(conn->max_pkt_out_size, PMTUD_BASE - 1);

    xqc_engine_destroy(conn->engine);
}

/* nothing acked since the path became suspect: it is down, not small, and
 * the size stays at the base */
void
xqc_test_pmtud_outage_at_base_keeps_base(void)
{
    xqc_connection_t *conn = xqc_test_pmtud_conn(PMTUD_BASE,
                                                 PMTUD_BASE);
    CU_ASSERT_FATAL(conn != NULL);
    xqc_send_ctl_t *send_ctl = conn->conn_initial_path->path_send_ctl;
    send_ctl->ctl_bh_suspect_time = 1;

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
