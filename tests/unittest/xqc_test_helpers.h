/**
 * @copyright Copyright (c) 2026, mqvpn project
 *
 * Shared test-harness helpers for PR3 (dynamic path cap) and later
 * Chunk-based multipath tests. The goal is to give Chunk 1-4 callers
 * one canonical place for fixture creation, CID seeding, allocation
 * accounting and handshake-state simulation, instead of each test
 * file open-coding its own setup.
 */

#ifndef XQC_TEST_HELPERS_H
#define XQC_TEST_HELPERS_H

#include <stddef.h>
#include <stdint.h>
#include "xquic/xquic.h"
#include "xquic/xquic_typedef.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"

/* Engine fixture — wraps the long-standing test_create_engine() in
 * xqc_common_test.c so PR3 callers do not need to include that header. */
xqc_engine_t *xqc_test_helper_engine_create(void);
void          xqc_test_helper_engine_destroy(xqc_engine_t *engine);

/* Lightweight calloc-zeroed xqc_connection_t fixture, multipath_version
 * pinned to XQC_MULTIPATH_3E. Defaults: local/remote max_path_id = 8,
 * scid_len = dcid_len = 8. The 'engine' argument is currently unused
 * (the fixture does not touch engine state) but is accepted so PR3 call
 * sites can pass the engine they just created without an awkward
 * (void)engine cast.
 *
 * Internally a thin wrapper over xqc_test_mp21_make_conn() — kept as a
 * separate symbol so the PR3 Chunks have a stable name even if the mp21
 * fixture is later renamed.
 */
xqc_connection_t *xqc_test_helper_conn_create(xqc_engine_t *engine);
void              xqc_test_helper_conn_destroy(xqc_connection_t *conn);

/* Populate conn->scid_set and conn->dcid_set with `n` UNUSED CIDs, one
 * per path_id 0..n-1. Each CID is XQC_DEFAULT_CID_LEN bytes of
 * deterministic content (path_id encoded in the first byte, sequence
 * in the second, side marker 's'/'d' in the third) so different runs
 * produce identical inputs.
 *
 * Returns XQC_OK on success or a negative xquic error code.
 */
xqc_int_t xqc_test_seed_cids(xqc_connection_t *conn, size_t n);

/* Monotonically-increasing counter of allocations performed via the
 * harness wrapper xqc_test_calloc(). The wrapper exists because the
 * production xqc_calloc is a static-inline in a header and therefore
 * cannot be intercepted via weak symbols / LD_PRELOAD without touching
 * src/. Tests that want to assert "this helper performs >=1 alloc"
 * should call xqc_test_calloc explicitly in the helper path; tests
 * comparing snapshots use xqc_test_alloc_counter() to read the
 * monotonic count.
 */
uint64_t xqc_test_alloc_counter(void);
void    *xqc_test_calloc(size_t count, size_t size);

/* Mark the connection as fully established for harness purposes: sets
 * conn_state to XQC_CONN_STATE_ESTABED and OR's in the
 * XQC_CONN_FLAG_HANDSHAKE_COMPLETED flag. This is enough for the PR3
 * guards under test which only inspect those two fields; tests that
 * need TLS/key state must do the full handshake themselves.
 */
void xqc_test_simulate_handshake_done(xqc_connection_t *conn);

/* Smoke test runner (registered from main.c). */
void xqc_test_helpers_smoke(void);

#endif /* XQC_TEST_HELPERS_H */
