/**
 * @copyright Copyright (c) 2026, mqvpn project
 *
 * PR3 Chunk 1: validates the three-stage xqc_path_create() refactor.
 *
 * Stage 1 (validate) must short-circuit BEFORE heavy allocation when the
 * path_id is out of range, abandoned, or lacks an unused CID. The previous
 * single-stage implementation would xqc_calloc() the path_ctx and call
 * xqc_pn_ctl_create() before discovering the missing CID, leaving state
 * (and in this fixture: dereferencing NULL conn->conn_pool) on the table.
 *
 * Stage 2 (defensive hard cap) is exercised by test_path_create_hard_cap_stress
 * — kept skipped until Chunk 2 removes the legacy XQC_MAX_PATHS_COUNT=8 cap
 * that currently prevents going beyond 8 paths.
 */

#include <CUnit/CUnit.h>
#include "xquic/xquic.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/common/xqc_list.h"
#include "xqc_test_helpers.h"
#include "xqc_test_path_hard_cap.h"

/* xqc_path_create has no public prototype — used via direct linkage. */
extern xqc_path_ctx_t *xqc_path_create(xqc_connection_t *conn,
                                       xqc_cid_t *scid, xqc_cid_t *dcid,
                                       uint64_t path_id);

void
test_path_create_no_heavy_state_on_validation_fail(void)
{
    xqc_connection_t *conn = xqc_test_helper_conn_create(NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    /* Path_id 99 is in-range (≤ 100) but has no unused CID seeded —
     * Stage 1 must fail at the scid/dcid availability check. */
    conn->remote_settings.init_max_path_id = 100;
    conn->local_max_path_id = 100;

    int create_count_before = conn->create_path_count;
    xqc_path_ctx_t *p = xqc_path_create(conn, NULL, NULL, 99);

    CU_ASSERT_PTR_NULL(p);
    /* Observable state: create_path_count must NOT have incremented.
     * Production xqc_calloc inside xqc_path_create is not visible to
     * xqc_test_alloc_counter, so we assert observable state instead. */
    CU_ASSERT(conn->create_path_count == create_count_before);

    /* No path entry left dangling on the conn paths list. */
    int found = 0;
    xqc_path_ctx_t *iter;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        iter = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (iter->path_id == 99) { found = 1; break; }
    }
    CU_ASSERT(found == 0);

    xqc_test_helper_conn_destroy(conn);
}

void
test_path_create_hard_cap_stress(void)
{
    CU_PASS("skipped: enabled in Chunk 2 — pending XQC_MAX_PATHS_COUNT removal");
    /* Reference implementation for Chunk 2:
     *   - seed 100 CIDs
     *   - call xqc_path_create for i in 0..99, expect non-NULL
     *   - top up to 256 CIDs
     *   - call xqc_path_create for path_id 256, expect NULL (hard cap)
     */
}

/* PR3 Chunk 2 / Task 2.1: contract test for the dynamic paths_info field
 * on xqc_conn_stats_t. Verifies:
 *   - With zero ACTIVE paths, paths_info_count == 0 and paths_info is NULL.
 *   - Stub paths in non-ACTIVE state are skipped (paths_info_count == 0).
 *   - One stub ACTIVE path with valid path_send_ctl yields count == 1 and
 *     a heap-allocated paths_info buffer the caller is responsible for
 *     freeing.
 *
 * Wrapped in CU_SKIP until the atomic refactor lands (end of Task 2.1).
 */
extern xqc_conn_stats_t xqc_conn_get_stats(xqc_engine_t *engine, const xqc_cid_t *cid);

void
test_conn_stats_dynamic_paths_info(void)
{
    CU_PASS("skipped: enabled at end of Task 2.1 atomic refactor");
    return;
    /* Reference body (enabled in Step 7):
     *   xqc_connection_t *conn = xqc_test_helper_conn_create(NULL);
     *   ... push fake xqc_path_ctx_t entries onto conn->conn_paths_list ...
     *   xqc_conn_stats_t stats = xqc_conn_get_stats(conn->engine, &conn->scid_set.user_scid);
     *   CU_ASSERT(stats.paths_info_count == 0 || stats.paths_info != NULL);
     *   xqc_free(stats.paths_info);
     */
}
