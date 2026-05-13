/**
 * @copyright Copyright (c) 2026, mqvpn project
 */

#include "xqc_test_helpers.h"

#include <stdlib.h>
#include <string.h>

#include "xqc_common_test.h"
#include "xqc_mp21_compliance_test.h"
#include "src/transport/xqc_cid.h"
#include "src/common/xqc_list.h"
#include "src/common/xqc_malloc.h"

/* ------------------------------------------------------------------ */
/* Engine fixture — thin wrappers around the long-standing common test
 * helpers so PR3 callers do not need to pull in xqc_common_test.h.
 * ------------------------------------------------------------------ */
xqc_engine_t *
xqc_test_helper_engine_create(void)
{
    return test_create_engine();
}

void
xqc_test_helper_engine_destroy(xqc_engine_t *engine)
{
    if (engine != NULL) {
        xqc_engine_destroy(engine);
    }
}

/* ------------------------------------------------------------------ */
/* Connection fixture — alias over the existing mp21 fixture so PR3
 * Chunks have a stable name to call.
 * ------------------------------------------------------------------ */
xqc_connection_t *
xqc_test_helper_conn_create(xqc_engine_t *engine)
{
    (void)engine;  /* mp21 fixture is engine-less; accepted for API symmetry */
    xqc_test_mp21_conn_params_t p = {
        .local_max_path_id  = 8,
        .remote_max_path_id = 8,
        .scid_len           = 8,
        .dcid_len           = 8,
    };
    return xqc_test_mp21_make_conn(&p);
}

void
xqc_test_helper_conn_destroy(xqc_connection_t *conn)
{
    xqc_test_mp21_free_conn(conn);
}

/* ------------------------------------------------------------------ */
/* CID seeding — populates scid_set and dcid_set with n UNUSED CIDs,
 * one per path_id 0..n-1. The mp21 fixture only inits scid_set's
 * cid_set_list, so we lazily init dcid_set here.
 *
 * Each CID is XQC_DEFAULT_CID_LEN bytes encoded as:
 *   byte 0 = path_id (low 8 bits)
 *   byte 1 = side marker ('s' for scid, 'd' for dcid)
 *   byte 2..  = deterministic padding (path_id * 0x11 etc.)
 *
 * Limit passed to xqc_cid_set_insert_cid is `n` which lets all n CIDs
 * fit (the limit is an inclusive upper-bound on unused+used count).
 * ------------------------------------------------------------------ */
static void
xqc_test_fill_cid(xqc_cid_t *cid, uint64_t path_id, char side_marker)
{
    cid->cid_len = XQC_DEFAULT_CID_LEN;
    cid->path_id = path_id;
    cid->cid_seq_num = 0;
    memset(cid->cid_buf, 0, sizeof(cid->cid_buf));
    cid->cid_buf[0] = (unsigned char)(path_id & 0xff);
    cid->cid_buf[1] = (unsigned char)side_marker;
    for (size_t i = 2; i < XQC_DEFAULT_CID_LEN; i++) {
        cid->cid_buf[i] = (unsigned char)((path_id * 0x11u + i) & 0xff);
    }
}

xqc_int_t
xqc_test_seed_cids(xqc_connection_t *conn, size_t n)
{
    if (conn == NULL) {
        return -XQC_EPARAM;
    }

    /* mp21 fixture initialises scid_set.cid_set_list but not dcid_set's;
     * make sure both are valid heads before we add per-path inner sets. */
    if (conn->dcid_set.cid_set_list.next == NULL) {
        xqc_init_list_head(&conn->dcid_set.cid_set_list);
    }
    if (conn->scid_set.cid_set_list.next == NULL) {
        xqc_init_list_head(&conn->scid_set.cid_set_list);
    }

    for (size_t i = 0; i < n; i++) {
        uint64_t  path_id = (uint64_t)i;
        xqc_int_t rc;

        rc = xqc_cid_set_add_path(&conn->scid_set, path_id);
        if (rc != XQC_OK) {
            return rc;
        }
        rc = xqc_cid_set_add_path(&conn->dcid_set, path_id);
        if (rc != XQC_OK) {
            return rc;
        }

        xqc_cid_t scid;
        xqc_test_fill_cid(&scid, path_id, 's');
        rc = xqc_cid_set_insert_cid(&conn->scid_set, &scid,
                                    XQC_CID_UNUSED, (uint64_t)n, path_id);
        if (rc != XQC_OK) {
            return rc;
        }

        xqc_cid_t dcid;
        xqc_test_fill_cid(&dcid, path_id, 'd');
        rc = xqc_cid_set_insert_cid(&conn->dcid_set, &dcid,
                                    XQC_CID_UNUSED, (uint64_t)n, path_id);
        if (rc != XQC_OK) {
            return rc;
        }
    }

    return XQC_OK;
}

/* ------------------------------------------------------------------ */
/* Allocation counter — production xqc_calloc is a static inline in a
 * header, so we cannot intercept it without touching src/. Instead we
 * expose an xqc_test_calloc wrapper that increments a static counter
 * and forwards to xqc_calloc. Helpers that want their alloc activity
 * tracked must route through xqc_test_calloc; other code paths are
 * deliberately invisible to the counter.
 * ------------------------------------------------------------------ */
static uint64_t s_alloc_counter = 0;

uint64_t
xqc_test_alloc_counter(void)
{
    return s_alloc_counter;
}

void *
xqc_test_calloc(size_t count, size_t size)
{
    s_alloc_counter++;
    return xqc_calloc(count, size);
}

/* ------------------------------------------------------------------ */
/* Handshake-done simulation. */
void
xqc_test_simulate_handshake_done(xqc_connection_t *conn)
{
    if (conn == NULL) {
        return;
    }
    conn->conn_state = XQC_CONN_STATE_ESTABED;
    conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED;
}
