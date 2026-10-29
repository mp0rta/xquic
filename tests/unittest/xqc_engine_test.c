/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xquic/xquic.h"
#include "src/transport/xqc_packet.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_priority_q.h"
#include "src/common/xqc_time.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_cid.h"
#include "xquic/xquic_typedef.h"
#include "src/common/xqc_str.h"
#include "src/transport/xqc_conn.h"
#include "src/congestion_control/xqc_new_reno.h"
#include "src/transport/xqc_packet_parser.h"
#include "xqc_common_test.h"


void
xqc_test_engine_create()
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT(engine != NULL);
    xqc_engine_destroy(engine);
    engine = NULL;
}


#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_LONG_HEADER_PACKET_B                                                  \
    "\xC0\xFF\x00\x00\x1D\x08\xAB\x3f\x12\x0a\xcd\xef\x00\x89\x08\xAB\x3f\x12\x0a\xcd" \
    "\xef\x00\x89"

#define XQC_TEST_CHECK_CID "ab3f120acdef0089"


void
xqc_test_engine_packet_process()
{
    struct sockaddr local_addr;
    socklen_t local_addrlen = 0;
    struct sockaddr peer_addr;
    socklen_t peer_addrlen = 0;

    xqc_engine_t *engine = test_create_engine_server();
    CU_ASSERT(engine != NULL);
    if (engine == NULL) {
        return;
    }

    xqc_msec_t recv_time = xqc_monotonic_timestamp();

    xqc_int_t rc = xqc_engine_packet_process(
        engine, XQC_TEST_LONG_HEADER_PACKET_B, sizeof(XQC_TEST_LONG_HEADER_PACKET_B) - 1,
        (struct sockaddr *)(&local_addr), local_addrlen, (struct sockaddr *)(&peer_addr),
        peer_addrlen, recv_time, NULL);
    // CU_ASSERT(rc == XQC_OK);

    /* get connection */
    xqc_cid_t dcid, scid;
    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);

    rc = xqc_packet_parse_cid(&scid, &dcid, engine->config->cid_len,
                              XQC_TEST_LONG_HEADER_PACKET_B,
                              sizeof(XQC_TEST_LONG_HEADER_PACKET_B) - 1);
    CU_ASSERT(rc == XQC_OK);

    /*
     * This packet is synthetic and does not complete a TLS handshake.  Do not
     * force 1-RTT short-header processing without installed packet keys.
     */
    xqc_engine_destroy(engine);
}


static void *
xqc_test_engine_no_growth(void *opaque, size_t size)
{
    return NULL;
}

/*
 * A client engine whose active queue holds one connection, with two
 * connections, a and b, waiting in its wakeup queue.
 */
static xqc_engine_t *
xqc_test_engine_two_waiting(xqc_connection_t **a, xqc_connection_t **b)
{
    xqc_config_t        config;
    xqc_engine_t       *engine;
    const xqc_cid_t    *cid;

    CU_ASSERT_FATAL(xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT)
                    == XQC_OK);
    config.conns_active_pq_capacity = 1;
    engine = test_create_engine_with_config(&config);
    CU_ASSERT_FATAL(engine != NULL);

    cid = test_cid_connect(engine);
    CU_ASSERT_FATAL(cid != NULL);
    *a = xqc_engine_conns_hash_find(engine, cid, 's');
    cid = test_cid_connect(engine);
    CU_ASSERT_FATAL(cid != NULL);
    *b = xqc_engine_conns_hash_find(engine, cid, 's');
    CU_ASSERT_FATAL(*a != NULL && *b != NULL);

    CU_ASSERT((*a)->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP);
    CU_ASSERT((*b)->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP);
    return engine;
}

/*
 * An API call such as xqc_conn_close() moves its connection from the
 * wakeup queue to the active queue, for the engine to process it. When the
 * active queue cannot grow, the connection must not be left in neither
 * queue, where nothing would process or destroy it again: it waits in the
 * wakeup queue, due at once, and the next run processes it.
 */
void
xqc_test_engine_active_queue_full(void)
{
    uint32_t            sent;
    xqc_engine_t       *engine;
    xqc_connection_t   *a, *b;
    xqc_malloc_wrap_t   pq_malloc;

    engine = xqc_test_engine_two_waiting(&a, &b);

    /* as from a callback of the engine, which processes the connections of
     * its active queue once the callback returns */
    engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    CU_ASSERT(xqc_conn_close(engine, &a->scid_set.user_scid) == XQC_OK);
    CU_ASSERT(a->conn_flag & XQC_CONN_FLAG_TICKING);

    pq_malloc = engine->conns_active_pq->a.malloc;
    engine->conns_active_pq->a.malloc = xqc_test_engine_no_growth;
    CU_ASSERT(xqc_conn_close(engine, &b->scid_set.user_scid) == XQC_OK);
    engine->conns_active_pq->a.malloc = pq_malloc;
    engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;

    CU_ASSERT(!(b->conn_flag & XQC_CONN_FLAG_TICKING));
    CU_ASSERT(b->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP);
    CU_ASSERT(b->next_tick_time <= xqc_monotonic_timestamp());

    /* the next run sends the CONNECTION_CLOSE of b too */
    sent = b->snd_pkt_stats.conn_sent_pkts;
    xqc_engine_main_logic(engine);
    CU_ASSERT(b->conn_state == XQC_CONN_STATE_CLOSING);
    CU_ASSERT(b->snd_pkt_stats.conn_sent_pkts > sent);

    xqc_engine_destroy(engine);
}

/*
 * xqc_engine_main_logic() moves the connections due from the wakeup queue
 * to the active queue. One that the active queue cannot take waits in the
 * wakeup queue, with no error, and the next run processes it.
 */
void
xqc_test_engine_main_logic_active_queue_full(void)
{
    xqc_usec_t          ticked;
    xqc_engine_t       *engine;
    xqc_connection_t   *a, *b;
    xqc_malloc_wrap_t   pq_malloc;

    engine = xqc_test_engine_two_waiting(&a, &b);

    /* both due, a first */
    xqc_engine_remove_wakeup_queue(engine, a);
    xqc_engine_remove_wakeup_queue(engine, b);
    a->next_tick_time = 1;
    b->next_tick_time = 2;
    CU_ASSERT(xqc_engine_add_wakeup_queue(engine, a) == XQC_OK);
    CU_ASSERT(xqc_engine_add_wakeup_queue(engine, b) == XQC_OK);
    ticked = b->last_ticked_time;

    pq_malloc = engine->conns_active_pq->a.malloc;
    engine->conns_active_pq->a.malloc = xqc_test_engine_no_growth;
    xqc_engine_main_logic(engine);
    engine->conns_active_pq->a.malloc = pq_malloc;

    CU_ASSERT(b->conn_err == 0);
    CU_ASSERT(b->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP);
    CU_ASSERT(b->last_ticked_time == ticked);
    CU_ASSERT(b->next_tick_time <= xqc_monotonic_timestamp());

    xqc_engine_main_logic(engine);
    CU_ASSERT(b->last_ticked_time > ticked);
    CU_ASSERT(b->conn_err == 0);

    xqc_engine_destroy(engine);
}
