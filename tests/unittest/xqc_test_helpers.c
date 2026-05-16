/**
 * @copyright Copyright (c) 2026, mqvpn project
 */

#include "xqc_test_helpers.h"

#include <stdlib.h>
#include <string.h>

#include "xqc_common_test.h"
#include "xqc_mp21_compliance_test.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_multipath.h"
#include "src/common/xqc_list.h"

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

/* ------------------------------------------------------------------ */
/* TEST FIXTURE ONLY — bypasses xqc_path_create + leaves send_ctl /
 * pn_ctl / CIDs NULL. Use only for state-machine assertions where the
 * missing infrastructure is not exercised. For tests that need real
 * path resources, use xqc_test_helper_conn_create + xqc_path_create.
 * ------------------------------------------------------------------ */
struct xqc_path_ctx_s *
xqc_test_helper_path_synthesize(xqc_connection_t *conn, uint64_t path_id,
                                int initial_state)
{
    if (conn == NULL) {
        return NULL;
    }
    xqc_path_ctx_t *path = calloc(1, sizeof(xqc_path_ctx_t));
    if (path == NULL) {
        return NULL;
    }
    path->parent_conn = conn;
    path->path_id     = path_id;
    path->path_state  = (xqc_path_state_t)initial_state;
    path->app_path_status = XQC_APP_PATH_STATUS_AVAILABLE;

    for (xqc_send_type_t t = 0; t < XQC_SEND_TYPE_N; t++) {
        xqc_init_list_head(&path->path_schedule_buf[t]);
    }
    xqc_init_list_head(&path->path_reinj_tmp_buf);

    xqc_list_add_tail(&path->path_list, &conn->conn_paths_list);
    conn->create_path_count++;

    if (initial_state == XQC_PATH_STATE_ACTIVE) {
        conn->active_path_count++;
    }
    return path;
}

void
xqc_test_helper_path_destroy(struct xqc_path_ctx_s *path)
{
    if (path == NULL) {
        return;
    }
    /* path was added to conn_paths_list during synthesize; unlink. */
    if (path->path_list.next != NULL && path->path_list.prev != NULL) {
        xqc_list_del(&path->path_list);
    }
    free(path);
}
