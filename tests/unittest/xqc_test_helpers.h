/**
 * @copyright Copyright (c) 2026, mqvpn project
 *
 * Shared test-harness helpers for PR3 (dynamic path cap) and later
 * Chunk-based multipath tests. Provides a stable name for fixture
 * creation, CID seeding and handshake-state simulation so Chunk 1-4
 * tests do not each open-code their own setup.
 */

#ifndef XQC_TEST_HELPERS_H
#define XQC_TEST_HELPERS_H

#include <stddef.h>
#include <stdint.h>
#include "xquic/xquic.h"
#include "xquic/xquic_typedef.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"

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

/* Mark the connection as fully established for harness purposes: sets
 * conn_state to XQC_CONN_STATE_ESTABED and OR's in the
 * XQC_CONN_FLAG_HANDSHAKE_COMPLETED flag. This is enough for the PR3
 * guards under test which only inspect those two fields; tests that
 * need TLS/key state must do the full handshake themselves.
 */
void xqc_test_simulate_handshake_done(xqc_connection_t *conn);

#endif /* XQC_TEST_HELPERS_H */
