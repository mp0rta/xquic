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

