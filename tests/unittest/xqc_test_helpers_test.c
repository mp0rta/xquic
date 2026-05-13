/**
 * @copyright Copyright (c) 2026, mqvpn project
 *
 * Smoke tests for xqc_test_helpers — confirm the helpers compile and
 * behave trivially. Real coverage comes from the PR3 Chunk tests that
 * consume these helpers.
 */

#include <CUnit/CUnit.h>
#include <string.h>

#include "xqc_test_helpers.h"
#include "src/transport/xqc_cid.h"


static void
test_engine_create_destroy(void)
{
    xqc_engine_t *engine = xqc_test_helper_engine_create();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    xqc_test_helper_engine_destroy(engine);
}

static void
test_conn_create_destroy(void)
{
    xqc_connection_t *conn = xqc_test_helper_conn_create(NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    CU_ASSERT_EQUAL(conn->conn_settings.multipath_version, XQC_MULTIPATH_3E);
    CU_ASSERT_EQUAL(conn->local_max_path_id, 8);
    xqc_test_helper_conn_destroy(conn);
}

static void
test_seed_cids_basic(void)
{
    xqc_connection_t *conn = xqc_test_helper_conn_create(NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    xqc_int_t rc = xqc_test_seed_cids(conn, 5);
    CU_ASSERT_EQUAL(rc, XQC_OK);

    /* Each path 0..4 should have exactly one UNUSED scid + one UNUSED dcid. */
    for (uint64_t path_id = 0; path_id < 5; path_id++) {
        CU_ASSERT_EQUAL(xqc_cid_set_get_unused_cnt(&conn->scid_set, path_id), 1);
        CU_ASSERT_EQUAL(xqc_cid_set_get_unused_cnt(&conn->dcid_set, path_id), 1);
    }

    xqc_test_helper_conn_destroy(conn);
}

static void
test_alloc_counter_monotonic(void)
{
    uint64_t before = xqc_test_alloc_counter();
    void *p1 = xqc_test_calloc(1, 1);
    void *p2 = xqc_test_calloc(1, 1);
    uint64_t after = xqc_test_alloc_counter();
    CU_ASSERT_PTR_NOT_NULL(p1);
    CU_ASSERT_PTR_NOT_NULL(p2);
    CU_ASSERT(after - before >= 2);
    free(p1);
    free(p2);
}

static void
test_simulate_handshake_done_state(void)
{
    xqc_connection_t *conn = xqc_test_helper_conn_create(NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    CU_ASSERT_NOT_EQUAL(conn->conn_state, XQC_CONN_STATE_ESTABED);
    CU_ASSERT_EQUAL(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED, 0);

    xqc_test_simulate_handshake_done(conn);

    CU_ASSERT_EQUAL(conn->conn_state, XQC_CONN_STATE_ESTABED);
    CU_ASSERT(conn->conn_flag & XQC_CONN_FLAG_HANDSHAKE_COMPLETED);

    xqc_test_helper_conn_destroy(conn);
}

void
xqc_test_helpers_smoke(void)
{
    test_engine_create_destroy();
    test_conn_create_destroy();
    test_seed_cids_basic();
    test_alloc_counter_monotonic();
    test_simulate_handshake_done_state();
}
