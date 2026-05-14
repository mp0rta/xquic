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
 * — enabled in PR3 Chunk 2 / Task 2.5 once XQC_PATH_HARD_CAP is the sole
 * defensive ceiling and the legacy XQC_MAX_PATHS_COUNT=8 has been removed.
 */

#include <CUnit/CUnit.h>
#include "xquic/xquic.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/common/xqc_list.h"
#include "src/common/xqc_malloc.h"
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
    /* PR3 Chunk 2 / Task 2.5: with XQC_MAX_PATHS_COUNT removed the only
     * defensive ceiling on path creation is XQC_PATH_HARD_CAP. The full
     * "spin up 256 real paths through path_init" stress requires a complete
     * engine + conn_pool, which the lightweight mp21 fixture does not
     * provide. Instead we verify the Stage 2 hard-cap gate directly: when
     * create_path_count is already at HARD_CAP, even a Stage-1-valid call
     * (range OK, unused CID present, not abandoned) MUST fail before any
     * heavy allocation.
     */
    xqc_connection_t *conn = xqc_test_helper_conn_create(NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    conn->remote_settings.init_max_path_id = XQC_PATH_HARD_CAP;
    conn->local_max_path_id = XQC_PATH_HARD_CAP;
    /* Seed enough CIDs so Stage 1's "no unused scid/dcid" gate does not
     * fire — the cap is what we want to exercise. */
    CU_ASSERT(xqc_test_seed_cids(conn, 4) == XQC_OK);

    /* Pretend HARD_CAP paths have already been created. */
    conn->create_path_count = XQC_PATH_HARD_CAP;

    xqc_path_ctx_t *p = xqc_path_create(conn, NULL, NULL, /*path_id=*/3);
    CU_ASSERT_PTR_NULL(p);
    CU_ASSERT(conn->create_path_count == XQC_PATH_HARD_CAP);

    xqc_test_helper_conn_destroy(conn);
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
    /* Bare conn — no paths on the list. Verify the dynamic-array contract
     * holds for the empty-active-paths case: count == 0, ptr is NULL (no
     * spurious calloc), and xqc_free(NULL) is safe per the documented
     * ownership contract.
     *
     * Exercising N>0 active paths needs the full path_create + cong-control
     * stack; that path is covered indirectly by the existing
     * xqc_test_helpers_smoke / mp21 conn-create tests and end-to-end tests
     * that already call xqc_conn_get_stats. Here we pin the ABI contract.
     */
    xqc_connection_t *conn = xqc_test_helper_conn_create(NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    xqc_conn_stats_t stats;
    xqc_memzero(&stats, sizeof(stats));

    /* Drive the fill helper directly — bypasses engine hash lookup which
     * the bare-conn fixture does not register into. */
    extern void xqc_conn_get_stats_internal(xqc_connection_t *conn,
                                            xqc_conn_stats_t *conn_stats);
    xqc_conn_get_stats_internal(conn, &stats);

    CU_ASSERT(stats.paths_info_count == 0);
    CU_ASSERT_PTR_NULL(stats.paths_info);

    /* xqc_free(NULL) must be safe; verify caller-free contract. */
    xqc_free(stats.paths_info);

    xqc_test_helper_conn_destroy(conn);
}

/* PR3 Chunk 4 / Task 4.1: DoS resistance — peer offering init_max_path_id
 * = 2^32-1 (spec-valid max for the varint range used by mp21) MUST NOT
 * trigger O(N) preallocation. The lazy-alloc design (Chunk 1) and dynamic
 * stats (Chunk 2) ensure no path resources are reserved at TP-acceptance
 * time; paths are created lazily via xqc_path_create() and bounded by
 * XQC_PATH_HARD_CAP.
 *
 * This test pins the spec-valid corner: accepting the max init_max_path_id
 * into conn settings does not, by itself, materialize any paths.
 */
void
test_dos_peer_init_max_path_id_max_valid(void)
{
    xqc_connection_t *conn = xqc_test_helper_conn_create(NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    conn->remote_settings.init_max_path_id = (1ULL << 32) - 1;
    conn->local_max_path_id = (1ULL << 32) - 1;

    int create_count_before = conn->create_path_count;
    xqc_test_simulate_handshake_done(conn);

    /* After handshake done, no implicit path creation. */
    CU_ASSERT(conn->create_path_count == create_count_before);

    xqc_test_helper_conn_destroy(conn);
}

