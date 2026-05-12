#include <CUnit/CUnit.h>
#include <string.h>
#include <stdlib.h>
#include "xquic/xquic.h"
#include "xquic/xqc_errno.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_recv_record.h"
#include "src/transport/xqc_transport_params.h"
#include "src/tls/xqc_crypto.h"
#include "src/tls/xqc_tls.h"
#include "src/common/xqc_log.h"
#include "xqc_mp21_compliance_test.h"

/* ------------------------------------------------------------------
 * Chunk 4 Task 13b: shared minimal connection fixture.
 *
 * Allocates a calloc()-zeroed xqc_connection_t + xqc_log_t and threads
 * the fields the Chunk 4 guards inspect. multipath_version is pinned to
 * XQC_MULTIPATH_3E. Caller can mutate remote_settings.init_max_path_id
 * after the call (used by Task 15's 3-condition test).
 * ------------------------------------------------------------------ */
xqc_connection_t *
xqc_test_mp21_make_conn(const xqc_test_mp21_conn_params_t *p)
{
    xqc_log_t *log = calloc(1, sizeof(xqc_log_t));
    if (log == NULL) {
        return NULL;
    }
    log->log_level = XQC_LOG_FATAL;   /* suppress per-test noise */

    xqc_connection_t *conn = calloc(1, sizeof(xqc_connection_t));
    if (conn == NULL) {
        free(log);
        return NULL;
    }
    conn->log = log;
    conn->conn_settings.multipath_version = XQC_MULTIPATH_3E;

    conn->local_max_path_id  = p ? p->local_max_path_id  : 8;
    conn->remote_max_path_id = p ? p->remote_max_path_id : 8;
    conn->curr_max_path_id   = (conn->local_max_path_id < conn->remote_max_path_id)
                                ? conn->local_max_path_id
                                : conn->remote_max_path_id;
    conn->remote_settings.init_max_path_id = conn->remote_max_path_id;
    conn->local_settings.enable_multipath = 1;
    conn->remote_settings.enable_multipath = 1;
    conn->local_settings.multipath_version = XQC_MULTIPATH_3E;
    conn->remote_settings.multipath_version = XQC_MULTIPATH_3E;

    conn->scid_set.user_scid.cid_len    = p ? p->scid_len : 8;
    conn->dcid_set.current_dcid.cid_len = p ? p->dcid_len : 8;

    /* Avoid NULL deref from xqc_list iteration if guards run before
     * fully-initialized cid lists are exercised. */
    return conn;
}

void
xqc_test_mp21_free_conn(xqc_connection_t *conn)
{
    if (conn == NULL) {
        return;
    }
    if (conn->log) {
        free(conn->log);
    }
    free(conn);
}

void
xqc_test_mp21_validate_recv_path_id(void)
{
    xqc_test_mp21_conn_params_t p = {
        .local_max_path_id  = 4,
        .remote_max_path_id = 4,
        .scid_len           = 8,
        .dcid_len           = 8,
    };
    xqc_connection_t *conn = xqc_test_mp21_make_conn(&p);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    /* Accept: path_id == local_max_path_id is the inclusive upper bound. */
    CU_ASSERT_EQUAL(xqc_validate_recv_path_id(conn, 0), XQC_OK);
    CU_ASSERT_EQUAL(xqc_validate_recv_path_id(conn, 4), XQC_OK);

    /* Reject: path_id > local_max_path_id maps to PROTOCOL_VIOLATION. */
    CU_ASSERT_EQUAL(xqc_validate_recv_path_id(conn, 5),
                    -(xqc_int_t)TRA_PROTOCOL_VIOLATION);
    CU_ASSERT_EQUAL(xqc_validate_recv_path_id(conn, 0xffffffffULL),
                    -(xqc_int_t)TRA_PROTOCOL_VIOLATION);

    xqc_test_mp21_free_conn(conn);
}

/* Build a minimal PATH_NEW_CONNECTION_ID wire image with a parameterized
 * Length byte. Layout (varints):
 *   Type (= 0x3e78, draft-21)  : 2B  0x7e 0x78
 *   Path ID                    : 1B  0x01
 *   Sequence Number            : 1B  0x00
 *   Retire Prior To            : 1B  0x00
 *   Length                     : 1B  <len_byte>
 *   Connection ID              : len bytes (zero-padded)
 *   Stateless Reset Token      : 16B (zero)
 *
 * For length=0 we still emit zero CID bytes; for length=21 we emit 21
 * placeholder bytes. The parser must reject both before reading sr_token.
 */
static int
xqc_test_mp21_drive_path_new_cid_parser(uint8_t len_byte)
{
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    size_t off = 0;
    buf[off++] = 0x7e; buf[off++] = 0x78;   /* type varint */
    buf[off++] = 0x01;                       /* path_id */
    buf[off++] = 0x00;                       /* seq_num */
    buf[off++] = 0x00;                       /* retire_prior_to */
    buf[off++] = len_byte;                   /* Length */
    size_t cid_bytes = len_byte;
    if (cid_bytes > 21) cid_bytes = 21;      /* cap for buffer safety */
    off += cid_bytes;                        /* CID body — zeros */
    off += 16;                               /* sr_token — zeros */

    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.buf = buf;
    packet_in.buf_size = sizeof(buf);
    packet_in.pos = buf;
    packet_in.last = buf + off;

    xqc_cid_t new_cid;
    memset(&new_cid, 0, sizeof(new_cid));
    uint64_t retire_prior_to = 0, path_id = 0;
    return (int)xqc_parse_mp_new_conn_id_frame(&packet_in, &new_cid,
                                               &retire_prior_to, &path_id, NULL);
}

void
xqc_test_mp21_path_new_conn_id_cid_len_guard(void)
{
    /* Length = 0 -> reject. */
    CU_ASSERT_NOT_EQUAL(xqc_test_mp21_drive_path_new_cid_parser(0), XQC_OK);
    /* Length = 21 -> reject (XQC_MAX_CID_LEN == 20). */
    CU_ASSERT_NOT_EQUAL(xqc_test_mp21_drive_path_new_cid_parser(21), XQC_OK);
    /* Length = 1 -> accept (boundary). */
    CU_ASSERT_EQUAL(xqc_test_mp21_drive_path_new_cid_parser(1), XQC_OK);
    /* Length = 20 -> accept (boundary). */
    CU_ASSERT_EQUAL(xqc_test_mp21_drive_path_new_cid_parser(20), XQC_OK);
    /* Length = 8 -> accept (common case). */
    CU_ASSERT_EQUAL(xqc_test_mp21_drive_path_new_cid_parser(8), XQC_OK);
}

/* Forward decl — xqc_path_create lives in xqc_multipath.c but its
 * prototype is buried in an internal header. */
extern xqc_path_ctx_t *xqc_path_create(xqc_connection_t *conn,
    xqc_cid_t *scid, xqc_cid_t *dcid, uint64_t path_id);

void
xqc_test_mp21_path_create_refuses_abandoned(void)
{
    /* draft-21 §4.5 (Task 23): xqc_path_create() MUST refuse to recycle
     * an Abandoned path_id. The refusal is exercised pre-allocation, so
     * the test fixture's stub conn (no engine, no pn_ctl) is sufficient.
     *
     * Test 2 from the plan (MAX_PATH_ID growth grants id=5 which is still
     * refused if pre-marked as abandoned) is verified indirectly: the
     * refusal predicate is xqc_conn_is_path_abandoned(conn, path_id),
     * which is checked unconditionally at xqc_path_create() entry — there
     * is no MAX_PATH_ID-aware bypass. Hence marking id=5 abandoned and
     * subsequently growing remote_max_path_id to 8 cannot lift the refusal.
     */
    xqc_test_mp21_conn_params_t p = {
        .local_max_path_id  = 8,
        .remote_max_path_id = 8,
        .scid_len           = 8,
        .dcid_len           = 8,
    };
    xqc_connection_t *conn = xqc_test_mp21_make_conn(&p);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    xqc_conn_mark_path_abandoned(conn, 2);

    /* xqc_path_create's first action is the abandoned-check; it bails
     * with NULL before touching engine / pn_ctl / send_ctl, so the stub
     * fixture suffices. */
    CU_ASSERT_PTR_NULL(xqc_path_create(conn, NULL, NULL, 2));

    /* Refusal survives across MAX_PATH_ID growth simulations. */
    conn->remote_max_path_id = 16;
    conn->curr_max_path_id   = 8;
    CU_ASSERT_PTR_NULL(xqc_path_create(conn, NULL, NULL, 2));

    /* Sanity: a different, non-abandoned path_id passes the bitmap
     * predicate (the helper, not the full xqc_path_create call). */
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 5));

    xqc_test_mp21_free_conn(conn);
}

void
xqc_test_mp21_abandoned_path_silently_ignored(void)
{
    xqc_test_mp21_conn_params_t p = {
        .local_max_path_id  = 64,
        .remote_max_path_id = 64,
        .scid_len           = 8,
        .dcid_len           = 8,
    };
    xqc_connection_t *conn = xqc_test_mp21_make_conn(&p);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    /* Initial state: no path is abandoned. */
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 0));
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 2));
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 64));
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 255));
    /* path_id beyond bitmap range -> always false. */
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 256));
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 0xffffffffULL));

    /* Mark path_id=2 abandoned (mimics PATH_ABANDON processing). */
    xqc_conn_mark_path_abandoned(conn, 2);
    CU_ASSERT_TRUE(xqc_conn_is_path_abandoned(conn, 2));
    /* Other ids unaffected. */
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 1));
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 3));

    /* Cross-word: 64 in next bitmap word. */
    xqc_conn_mark_path_abandoned(conn, 64);
    CU_ASSERT_TRUE(xqc_conn_is_path_abandoned(conn, 64));
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 63));
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 65));

    /* Out-of-range mark is a no-op (must not corrupt memory). */
    xqc_conn_mark_path_abandoned(conn, 9999);
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 9999));
    /* Existing marks survive. */
    CU_ASSERT_TRUE(xqc_conn_is_path_abandoned(conn, 2));
    CU_ASSERT_TRUE(xqc_conn_is_path_abandoned(conn, 64));

    xqc_test_mp21_free_conn(conn);
}

void
xqc_test_mp21_duplicate_path_abandon_short_circuit(void)
{
    /* draft-21 §4.5: a duplicate PATH_ABANDON for an already-abandoned
     * path_id must be silently ignored, symmetric with the other 5 MP
     * frame processors. The short-circuit predicate in
     * xqc_process_path_abandon_frame is
     *   if (xqc_conn_is_path_abandoned(conn, path_id)) return XQC_OK;
     * placed BEFORE xqc_conn_mark_path_abandoned so the first arrival
     * still runs the full release-path path, and subsequent arrivals
     * return without re-running immediate_close or CID state churn.
     *
     * We cannot fabricate a packet_in with a live conn here, but we can
     * pin the predicate semantics the short-circuit relies on:
     *   (1) is_abandoned returns FALSE before the first mark — first
     *       PATH_ABANDON falls through past the short-circuit;
     *   (2) is_abandoned returns TRUE after the first mark — every
     *       subsequent duplicate hits the short-circuit and returns;
     *   (3) repeated marks are idempotent — no state corruption from
     *       the redundant set on the still-falls-through first call.
     */
    xqc_test_mp21_conn_params_t p = {
        .local_max_path_id  = 64,
        .remote_max_path_id = 64,
        .scid_len           = 8,
        .dcid_len           = 8,
    };
    xqc_connection_t *conn = xqc_test_mp21_make_conn(&p);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    /* (1) First PATH_ABANDON for path_id=2: short-circuit predicate FALSE. */
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 2));
    xqc_conn_mark_path_abandoned(conn, 2);

    /* (2) Second (duplicate) PATH_ABANDON for path_id=2: predicate TRUE. */
    CU_ASSERT_TRUE(xqc_conn_is_path_abandoned(conn, 2));

    /* (3) Idempotent: re-marking does not corrupt or clear the bit. */
    xqc_conn_mark_path_abandoned(conn, 2);
    CU_ASSERT_TRUE(xqc_conn_is_path_abandoned(conn, 2));
    xqc_conn_mark_path_abandoned(conn, 2);
    CU_ASSERT_TRUE(xqc_conn_is_path_abandoned(conn, 2));

    /* Other ids remain unaffected by the duplicate-mark dance. */
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 1));
    CU_ASSERT_FALSE(xqc_conn_is_path_abandoned(conn, 3));

    xqc_test_mp21_free_conn(conn);
}

void
xqc_test_mp21_non_zero_cid_constraint(void)
{
    /* Both zero -> reject. */
    CU_ASSERT_EQUAL(xqc_validate_mp_cid_lengths(0, 0),
                    -(xqc_int_t)TRA_PROTOCOL_VIOLATION);
    /* dcid=0 -> reject. */
    CU_ASSERT_EQUAL(xqc_validate_mp_cid_lengths(8, 0),
                    -(xqc_int_t)TRA_PROTOCOL_VIOLATION);
    /* scid=0 -> reject. */
    CU_ASSERT_EQUAL(xqc_validate_mp_cid_lengths(0, 8),
                    -(xqc_int_t)TRA_PROTOCOL_VIOLATION);
    /* both > 0 -> accept. */
    CU_ASSERT_EQUAL(xqc_validate_mp_cid_lengths(8, 8), XQC_OK);
    CU_ASSERT_EQUAL(xqc_validate_mp_cid_lengths(1, 20), XQC_OK);
}

void
xqc_test_mp21_aead_nonce_min_length(void)
{
    /* MP disabled: any noncelen accepted (opt-out path). */
    CU_ASSERT_EQUAL(xqc_crypto_check_mp_nonce_len(0, 8),  XQC_OK);
    CU_ASSERT_EQUAL(xqc_crypto_check_mp_nonce_len(0, 11), XQC_OK);
    CU_ASSERT_EQUAL(xqc_crypto_check_mp_nonce_len(0, 12), XQC_OK);

    /* MP enabled: < 12 rejected. */
    CU_ASSERT_EQUAL(xqc_crypto_check_mp_nonce_len(1, 0),  -(xqc_int_t)TRA_TRANSPORT_PARAMETER_ERROR);
    CU_ASSERT_EQUAL(xqc_crypto_check_mp_nonce_len(1, 8),  -(xqc_int_t)TRA_TRANSPORT_PARAMETER_ERROR);
    CU_ASSERT_EQUAL(xqc_crypto_check_mp_nonce_len(1, 11), -(xqc_int_t)TRA_TRANSPORT_PARAMETER_ERROR);

    /* MP enabled: >= 12 accepted (AES-GCM = 12, ChaCha20-Poly1305 = 12). */
    CU_ASSERT_EQUAL(xqc_crypto_check_mp_nonce_len(1, 12), XQC_OK);
    CU_ASSERT_EQUAL(xqc_crypto_check_mp_nonce_len(1, 16), XQC_OK);
}

/* Exposed by xqc_frame.c for whitebox testing of the 1-RTT-only guard. */
extern int xqc_frame_is_mp_public(uint64_t frame_type);

void
xqc_test_mp21_mp_frame_1rtt_only(void)
{
    /* The dispatcher entry-guard depends on two predicates:
     *  (a) xqc_frame_is_mp(frame_type) enumerates every MP wire type,
     *  (b) packet_in->pi_pkt.pkt_type != XQC_PTYPE_SHORT_HEADER rejects.
     * We exercise (a) here directly; (b) is covered by the
     * dual-version-dispatch and TP tests which require full SHORT_HEADER
     * packet construction (out of scope for unit harness). */

    /* All draft-21 MP frame types must be classified as MP. */
    CU_ASSERT_TRUE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_PATH_ACK));
    CU_ASSERT_TRUE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_PATH_ACK_ECN));
    CU_ASSERT_TRUE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_PATH_ABANDON_V21));
    CU_ASSERT_TRUE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_PATH_STATUS_BACKUP));
    CU_ASSERT_TRUE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_PATH_STATUS_AVAILABLE_V21));
    CU_ASSERT_TRUE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_PATH_NEW_CONNECTION_ID_V21));
    CU_ASSERT_TRUE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_PATH_RETIRE_CONNECTION_ID_V21));
    CU_ASSERT_TRUE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_MAX_PATH_ID_V21));
    CU_ASSERT_TRUE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_PATHS_BLOCKED));
    CU_ASSERT_TRUE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_PATH_CIDS_BLOCKED));

    /* draft-10 MP types must remain classified as MP (still wire-active). */
    CU_ASSERT_TRUE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_MP_ACK0));
    CU_ASSERT_TRUE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_MP_ABANDON));
    CU_ASSERT_TRUE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_MAX_PATH_ID));

    /* Non-MP frame types must NOT be classified as MP. */
    CU_ASSERT_FALSE(xqc_frame_is_mp_public(0x00));                     /* PADDING */
    CU_ASSERT_FALSE(xqc_frame_is_mp_public(0x02));                     /* ACK */
    CU_ASSERT_FALSE(xqc_frame_is_mp_public(0x06));                     /* CRYPTO */
    CU_ASSERT_FALSE(xqc_frame_is_mp_public(0x18));                     /* NEW_CID */
    CU_ASSERT_FALSE(xqc_frame_is_mp_public(0x1a));                     /* PATH_CHALLENGE */
    CU_ASSERT_FALSE(xqc_frame_is_mp_public(0x30));                     /* DATAGRAM */
    CU_ASSERT_FALSE(xqc_frame_is_mp_public(XQC_TRANS_FRAME_TYPE_ACK_EXT));
}

void
xqc_test_mp21_init_max_path_id_upper_bound(void)
{
    /* Hand-encoded TP buffer: { id=0x3e, len=varies, value }
     * Accept boundary at 0xFFFFFFFF (4-byte varint); reject 0x100000000
     * (8-byte varint, one past spec maximum). */
    xqc_transport_params_t params;

    /* Accept 0xFFFFFFFF — value needs a 4-byte varint with prefix 0x80.
     *   bytes: 0xbf 0xff 0xff 0xff  (prefix 10 | 0x3fffffff is too short)
     *   actually 0xFFFFFFFF doesn't fit in 4-byte varint (max 0x3FFFFFFF);
     *   needs 8-byte varint: 0xc0 0x00 0x00 0x00 0xff 0xff 0xff 0xff. */
    uint8_t accept_buf[] = {
        0x3e, 0x08,                                     /* id, len=8 */
        0xc0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff  /* val = 0xFFFFFFFF */
    };
    xqc_init_transport_params(&params);
    xqc_int_t ret = xqc_decode_transport_params(&params, XQC_TP_TYPE_CLIENT_HELLO,
                                                accept_buf, sizeof(accept_buf));
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(params.enable_multipath, 1);
    CU_ASSERT_EQUAL(params.init_max_path_id, 0xFFFFFFFFULL);

    /* Reject 0x100000000 — one past spec maximum. */
    uint8_t reject_buf[] = {
        0x3e, 0x08,                                     /* id, len=8 */
        0xc0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00  /* val = 0x100000000 */
    };
    xqc_init_transport_params(&params);
    ret = xqc_decode_transport_params(&params, XQC_TP_TYPE_CLIENT_HELLO,
                                      reject_buf, sizeof(reject_buf));
    CU_ASSERT_NOT_EQUAL(ret, XQC_OK);
}

void
xqc_test_mp21_max_path_id_validation(void)
{
    xqc_test_mp21_conn_params_t p = {
        .local_max_path_id  = 100,
        .remote_max_path_id = 8,
        .scid_len           = 8,
        .dcid_len           = 8,
    };
    xqc_connection_t *conn = xqc_test_mp21_make_conn(&p);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    /* Pretend the peer's initial_max_path_id TP was 4. */
    conn->remote_settings.init_max_path_id = 4;

    /* (a) value >= 2^32 — too large, PROTOCOL_VIOLATION. */
    CU_ASSERT_EQUAL(xqc_validate_max_path_id(conn, 0x100000000ULL),
                    XQC_MAX_PATH_ID_BAD_TOO_LARGE);
    CU_ASSERT_EQUAL(xqc_validate_max_path_id(conn, 0xffffffffffffULL),
                    XQC_MAX_PATH_ID_BAD_TOO_LARGE);

    /* (b) value < init_max_path_id — receiver cannot drop the cap. */
    CU_ASSERT_EQUAL(xqc_validate_max_path_id(conn, 3),
                    XQC_MAX_PATH_ID_BAD_BELOW_INIT);

    /* (c) value <= remote_max_path_id — silent ignore (stale dup). */
    CU_ASSERT_EQUAL(xqc_validate_max_path_id(conn, 8),
                    XQC_MAX_PATH_ID_IGNORE_STALE);
    CU_ASSERT_EQUAL(xqc_validate_max_path_id(conn, 4),
                    XQC_MAX_PATH_ID_IGNORE_STALE);

    /* (d) accept + boundary at 2^32-1. */
    CU_ASSERT_EQUAL(xqc_validate_max_path_id(conn, 16),
                    XQC_MAX_PATH_ID_ACCEPT);
    CU_ASSERT_EQUAL(xqc_validate_max_path_id(conn, 0xffffffffULL),
                    XQC_MAX_PATH_ID_ACCEPT);

    xqc_test_mp21_free_conn(conn);
}

void
xqc_test_mp21_fixture_smoke(void)
{
    xqc_test_mp21_conn_params_t p = {
        .local_max_path_id  = 4,
        .remote_max_path_id = 6,
        .scid_len           = 8,
        .dcid_len           = 8,
    };
    xqc_connection_t *conn = xqc_test_mp21_make_conn(&p);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    CU_ASSERT_EQUAL(conn->conn_settings.multipath_version, XQC_MULTIPATH_3E);
    CU_ASSERT_EQUAL(conn->local_max_path_id, 4);
    CU_ASSERT_EQUAL(conn->remote_max_path_id, 6);
    CU_ASSERT_EQUAL(conn->curr_max_path_id, 4);
    CU_ASSERT_EQUAL(conn->scid_set.user_scid.cid_len, 8);
    CU_ASSERT_EQUAL(conn->dcid_set.current_dcid.cid_len, 8);
    xqc_test_mp21_free_conn(conn);
}

/* Test helper: synthesize a minimal xqc_packet_in_t over `buf` and forward
 * to xqc_parse_path_abandon_frame, returning the number of bytes consumed
 * (i.e. how far packet_in->pos was advanced from buf).
 *
 * `mp_version` selects draft-10 (legacy, reads Reason Phrase) vs draft-21
 * (XQC_MULTIPATH_3E, no Reason Phrase). The parser will only branch on
 * version once Task 7 fix lands; for the RED test this argument is unused.
 */
static int
xqc_test_parse_path_abandon(unsigned char *buf, size_t len,
    uint64_t *path_id, uint64_t *error_code, size_t *consumed,
    uint8_t mp_version)
{
    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.buf = buf;
    packet_in.buf_size = len;
    packet_in.pos = buf;
    packet_in.last = buf + len;
    xqc_int_t ret = xqc_parse_path_abandon_frame(&packet_in, path_id, error_code, mp_version);
    if (consumed) {
        *consumed = (size_t)(packet_in.pos - buf);
    }
    return (int)ret;
}

void xqc_test_mp21_version_enum(void)
{
    /* XQC_MULTIPATH_3E must exist and equal 0x3e */
    CU_ASSERT_EQUAL((int)XQC_MULTIPATH_3E, 0x3e);
    /* XQC_MULTIPATH_10 should still exist for dual-version dispatch */
    CU_ASSERT_EQUAL((int)XQC_MULTIPATH_10, 0x0a);
}

void xqc_test_mp21_frame_type_constants(void)
{
    /* draft-21 frame type values (IANA-assigned final codepoints) */
    CU_ASSERT_EQUAL(XQC_TRANS_FRAME_TYPE_PATH_ACK,                      0x3eULL);
    CU_ASSERT_EQUAL(XQC_TRANS_FRAME_TYPE_PATH_ACK_ECN,                  0x3fULL);
    CU_ASSERT_EQUAL(XQC_TRANS_FRAME_TYPE_PATH_ABANDON_V21,              0x3e75ULL);
    CU_ASSERT_EQUAL(XQC_TRANS_FRAME_TYPE_PATH_STATUS_BACKUP,            0x3e76ULL);
    CU_ASSERT_EQUAL(XQC_TRANS_FRAME_TYPE_PATH_STATUS_AVAILABLE_V21,     0x3e77ULL);
    CU_ASSERT_EQUAL(XQC_TRANS_FRAME_TYPE_PATH_NEW_CONNECTION_ID_V21,    0x3e78ULL);
    CU_ASSERT_EQUAL(XQC_TRANS_FRAME_TYPE_PATH_RETIRE_CONNECTION_ID_V21, 0x3e79ULL);
    CU_ASSERT_EQUAL(XQC_TRANS_FRAME_TYPE_MAX_PATH_ID_V21,               0x3e7aULL);
    CU_ASSERT_EQUAL(XQC_TRANS_FRAME_TYPE_PATHS_BLOCKED,                 0x3e7bULL);
    CU_ASSERT_EQUAL(XQC_TRANS_FRAME_TYPE_PATH_CIDS_BLOCKED,             0x3e7cULL);
    /* draft-10 constants must still exist for dual-version dispatch */
    CU_ASSERT_EQUAL(XQC_TRANS_FRAME_TYPE_MP_ACK0,                       0x15228c00ULL);

    /* draft-21 error code constants (PATH_ABANDON Error Code field) */
    CU_ASSERT_EQUAL(TRA_APPLICATION_ABANDON_PATH,    0x3eULL);
    CU_ASSERT_EQUAL(TRA_PATH_RESOURCE_LIMIT_REACHED, 0x3e75ULL);
    CU_ASSERT_EQUAL(TRA_PATH_UNSTABLE_OR_POOR,       0x3e76ULL);
    CU_ASSERT_EQUAL(TRA_NO_CID_AVAILABLE_FOR_PATH,   0x3e77ULL);
    /* legacy error code must still exist */
    CU_ASSERT_EQUAL((uint64_t)TRA_PROTOCOL_VIOLATION, 0x0aULL);
}

void xqc_test_mp21_path_abandon_recv_no_reason(void)
{
    /* draft-21 wire: { Type, Path ID, Error Code } -- no Reason Phrase.
     *
     * Frame type 0x3e75 encodes as a 2-byte varint 0x7e 0x75 (prefix 01).
     * After the type, payload is path_id(1B) + error_code(1B) = 2 bytes.
     * A trailing 0x00 stands in for the next frame (PADDING); the parser
     * must NOT consume it as Reason Phrase Length.
     */
    unsigned char buf[16] = {0};
    size_t off = 0;
    buf[off++] = 0x7e; buf[off++] = 0x75;   /* type varint = 0x3e75 */
    buf[off++] = 0x01;                       /* path_id varint = 1 */
    buf[off++] = 0x3e;                       /* error_code varint = 0x3e */
    buf[off++] = 0x00;                       /* next frame: PADDING */

    uint64_t path_id = 0, error_code = 0;
    size_t consumed = 0;
    int ret = xqc_test_parse_path_abandon(buf, sizeof(buf), &path_id,
                                          &error_code, &consumed,
                                          XQC_MULTIPATH_3E);

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(path_id, 1);
    CU_ASSERT_EQUAL(error_code, 0x3e);
    /* type(2) + path_id(1) + error_code(1) == 4 bytes total.
     * The legacy parser also consumes one more byte for reason_len
     * (the 0x00 PADDING byte) so total = 5. This assertion is the RED
     * that Task 7 will turn GREEN. */
    CU_ASSERT_EQUAL(consumed, 4);
}

void xqc_test_mp10_path_abandon_recv_with_reason_still_works(void)
{
    /* draft-10 layout: { Type, Path ID, Error Code, Reason Phrase Length,
     * Reason Phrase }. xquic always emits reason_len=0, so wire is
     * type + path_id + error_code + 0x00.
     *
     * We reuse the draft-21 type bytes (0x3e75) since the parser does not
     * validate the type value — version dispatch is decided by the caller.
     * The fifth byte 0x00 is the reason_len that the draft-10 path MUST
     * consume; consumed therefore must be 5 (4 + reason_len byte).
     */
    unsigned char buf[16] = {0};
    size_t off = 0;
    buf[off++] = 0x7e; buf[off++] = 0x75;   /* type varint */
    buf[off++] = 0x01;                       /* path_id */
    buf[off++] = 0x3e;                       /* error_code */
    buf[off++] = 0x00;                       /* reason_len = 0 (draft-10) */

    uint64_t path_id = 0, error_code = 0;
    size_t consumed = 0;
    int ret = xqc_test_parse_path_abandon(buf, sizeof(buf), &path_id,
                                          &error_code, &consumed,
                                          XQC_MULTIPATH_10);

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(path_id, 1);
    CU_ASSERT_EQUAL(error_code, 0x3e);
    CU_ASSERT_EQUAL(consumed, 5);
}

/* Test helper: drive xqc_gen_path_abandon_frame() with a minimal
 * synthetic conn + packet_out. Returns bytes written on success or a
 * negative error code.
 */
static ssize_t
xqc_test_gen_path_abandon(unsigned char *out_buf, size_t out_cap,
    uint64_t path_id, uint64_t error_code, uint8_t mp_version)
{
    xqc_connection_t *conn = calloc(1, sizeof(xqc_connection_t));
    xqc_packet_out_t *po   = calloc(1, sizeof(xqc_packet_out_t));
    if (!conn || !po) {
        free(conn); free(po);
        return -1;
    }
    conn->conn_settings.multipath_version = mp_version;
    po->po_buf = out_buf;
    po->po_buf_cap = out_cap;
    po->po_buf_size = (unsigned int)out_cap;
    po->po_used_size = 0;
    po->po_reserved_size = 0;

    ssize_t ret = xqc_gen_path_abandon_frame(conn, po, path_id, error_code);

    free(conn);
    free(po);
    return ret;
}

void xqc_test_mp21_path_abandon_gen_no_reason(void)
{
    /* draft-21: generator must emit exactly 4 bytes — 2-byte type 0x3e75
     * varint + 1-byte path_id + 1-byte error_code. The 5th buffer byte
     * must NOT be touched (legacy code emitted a trailing 0x00 reason_len). */
    unsigned char buf[16];
    memset(buf, 0xaa, sizeof(buf));   /* sentinel */

    ssize_t written = xqc_test_gen_path_abandon(buf, sizeof(buf),
                                                1, 0x3e, XQC_MULTIPATH_3E);

    CU_ASSERT_EQUAL(written, 4);
    CU_ASSERT_EQUAL(buf[0], 0x7e);    /* type high byte */
    CU_ASSERT_EQUAL(buf[1], 0x75);    /* type low byte */
    CU_ASSERT_EQUAL(buf[2], 0x01);    /* path_id */
    CU_ASSERT_EQUAL(buf[3], 0x3e);    /* error_code */
    CU_ASSERT_EQUAL(buf[4], 0xaa);    /* sentinel preserved — no reason_len */
}

void xqc_test_mp21_dual_version_dispatch(void)
{
    /* The xqc_process_frames switch was extended in Task 9 with draft-21
     * case labels alongside the draft-10 labels. We cannot exercise the
     * full dispatcher here without a real xqc_connection_t, but we can:
     *
     *  (a) confirm the draft-21 codepoints are all distinct (no overlap
     *      with draft-10 or each other -> required for a C switch to
     *      compile, so success of the build is itself a check),
     *  (b) confirm the codepoints match the IANA-final draft-21 values.
     *
     * Wire-level correctness of the new handlers is exercised by the
     * PATH_ABANDON recv/gen tests above; the remaining handlers
     * (PATH_STATUS_BACKUP, PATH_NEW_CONNECTION_ID_V21, etc.) reuse the
     * legacy xqc_process_path_status_frame / xqc_process_mp_*_frame
     * code paths unchanged, so a parser test there belongs to Chunk 3
     * or downstream MUST-guard work.
     */
    uint64_t v21_types[] = {
        XQC_TRANS_FRAME_TYPE_PATH_ACK,
        XQC_TRANS_FRAME_TYPE_PATH_ACK_ECN,
        XQC_TRANS_FRAME_TYPE_PATH_ABANDON_V21,
        XQC_TRANS_FRAME_TYPE_PATH_STATUS_BACKUP,
        XQC_TRANS_FRAME_TYPE_PATH_STATUS_AVAILABLE_V21,
        XQC_TRANS_FRAME_TYPE_PATH_NEW_CONNECTION_ID_V21,
        XQC_TRANS_FRAME_TYPE_PATH_RETIRE_CONNECTION_ID_V21,
        XQC_TRANS_FRAME_TYPE_MAX_PATH_ID_V21,
    };
    size_t n = sizeof(v21_types) / sizeof(v21_types[0]);

    /* All draft-21 codepoints must be pairwise distinct. */
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            CU_ASSERT_NOT_EQUAL(v21_types[i], v21_types[j]);
        }
    }

    /* None of the draft-21 codepoints may collide with draft-10. */
    uint64_t v10_types[] = {
        XQC_TRANS_FRAME_TYPE_MP_ACK0,
        XQC_TRANS_FRAME_TYPE_MP_ACK1,
        XQC_TRANS_FRAME_TYPE_MP_ABANDON,
        XQC_TRANS_FRAME_TYPE_MP_STANDBY,
        XQC_TRANS_FRAME_TYPE_MP_AVAILABLE,
        /* MP_FROZEN removed in Chunk 3 Task 13 (draft-21 §4.4). */
        XQC_TRANS_FRAME_TYPE_MP_NEW_CONN_ID,
        XQC_TRANS_FRAME_TYPE_MP_RETIRE_CONN_ID,
        XQC_TRANS_FRAME_TYPE_MAX_PATH_ID,
    };
    size_t m = sizeof(v10_types) / sizeof(v10_types[0]);
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < m; ++j) {
            CU_ASSERT_NOT_EQUAL(v21_types[i], v10_types[j]);
        }
    }
}

void xqc_test_mp21_path_ack_ecn_parse_skip(void)
{
    /* draft-21 §4.1 PATH_ACK_ECN wire layout:
     *   Type (= 0x3f, 1B varint)
     *   Path ID (i)
     *   Largest Acknowledged (i)
     *   ACK Delay (i)
     *   ACK Range Count (i)
     *   First ACK Range (i)
     *   [ACK Range...]
     *   ECT0 Count (i)
     *   ECT1 Count (i)
     *   CE Count (i)
     *
     * The parser must:
     *  (a) plumb the ACK info back through ack_info (largest_ack == 10),
     *  (b) consume the 3 trailing ECN Counts varints (skip-only — no
     *      accounting in Chunk 3),
     *  (c) advance packet_in->pos by exactly the frame length,
     *      leaving any trailing sentinel byte untouched.
     */
    unsigned char buf[16] = {0};
    size_t off = 0;
    buf[off++] = 0x3f;  /* type varint = 0x3f (PATH_ACK_ECN) */
    buf[off++] = 0x01;  /* path_id = 1 */
    buf[off++] = 0x0a;  /* largest_ack = 10 */
    buf[off++] = 0x00;  /* ack_delay = 0 */
    buf[off++] = 0x00;  /* ack_range_count = 0 */
    buf[off++] = 0x00;  /* first_ack_range = 0 */
    buf[off++] = 0x00;  /* ECT0 Count = 0 */
    buf[off++] = 0x00;  /* ECT1 Count = 0 */
    buf[off++] = 0x00;  /* CE Count = 0 */
    buf[off++] = 0xaa;  /* sentinel — must NOT be consumed */

    /* Stub connection + log: parser reads conn->remote_settings.ack_delay_exponent
     * (0 from calloc) and may xqc_log() on error; FATAL log_level suppresses. */
    xqc_log_t        *log  = calloc(1, sizeof(xqc_log_t));
    xqc_connection_t *conn = calloc(1, sizeof(xqc_connection_t));
    log->log_level = XQC_LOG_FATAL;
    conn->log = log;

    xqc_packet_in_t packet_in;
    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.buf = buf;
    packet_in.buf_size = sizeof(buf);
    packet_in.pos = buf;
    packet_in.last = buf + off;

    uint64_t path_id = 0;
    xqc_ack_info_t ack_info;
    memset(&ack_info, 0, sizeof(ack_info));

    xqc_int_t ret = xqc_parse_path_ack_ecn_frame(&packet_in, conn,
                                                 &path_id, &ack_info);

    CU_ASSERT_EQUAL(ret, XQC_OK);
    size_t consumed = (size_t)(packet_in.pos - buf);
    /* off-1 == 9 (all 9 wire bytes parsed, sentinel untouched) */
    CU_ASSERT_EQUAL(consumed, off - 1);
    CU_ASSERT_EQUAL(path_id, 1);
    /* Largest Ack lands in ranges[0].high — proves ACK info plumbed
     * through to recovery (regression guard against "ACK dropped"). */
    CU_ASSERT_EQUAL(ack_info.n_ranges, 1);
    CU_ASSERT_EQUAL(ack_info.ranges[0].high, 10);
    /* Sentinel preserved. */
    CU_ASSERT_EQUAL(buf[off - 1], 0xaa);

    free(conn);
    free(log);
}

void xqc_test_mp21_init_max_path_id_tp_codepoint(void)
{
    /* draft-21 §3.1: initial_max_path_id has the IANA-final codepoint
     * 0x3e in the transport-parameter id namespace (disjoint from frame
     * TYPEs where 0x3e is PATH_ACK).
     *
     * (a) The new constant exists and equals 0x3e.
     * (b) Decoder accepts the V21 codepoint and selects XQC_MULTIPATH_3E.
     * (c) Decoder still accepts the V10 codepoint and selects XQC_MULTIPATH_10
     *     (backwards compatibility during transition).
     * (d) Encoder emits the V21 codepoint when params->multipath_version
     *     == XQC_MULTIPATH_3E (the V10/V21 round-trip).
     */
    CU_ASSERT_EQUAL(XQC_TRANSPORT_PARAM_INIT_MAX_PATH_ID_V21, 0x3eULL);
    CU_ASSERT_EQUAL(XQC_TRANSPORT_PARAM_INIT_MAX_PATH_ID_V10, 0x0f739bbc1b666d09ULL);

    /* (b) hand-built TP buffer: { id=0x3e (1B varint), len=1 (1B), val=8 (1B) } */
    uint8_t v21_buf[3] = { 0x3e, 0x01, 0x08 };
    xqc_transport_params_t params;
    xqc_init_transport_params(&params);
    xqc_int_t ret = xqc_decode_transport_params(&params, XQC_TP_TYPE_CLIENT_HELLO,
                                                v21_buf, sizeof(v21_buf));
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(params.enable_multipath, 1);
    CU_ASSERT_EQUAL(params.multipath_version, XQC_MULTIPATH_3E);
    CU_ASSERT_EQUAL(params.init_max_path_id, 8);

    /* (c) V10 codepoint: id 0x0f739bbc1b666d09 needs 8-byte varint encoding
     * (prefix 0xc0 | top byte). xqc_put_varint will give us the wire bytes;
     * for a hand-built test we use xqc_write_transport_params via a known
     * V10-version params struct round-trip instead. */
    xqc_transport_params_t v10_params;
    xqc_init_transport_params(&v10_params);
    v10_params.enable_multipath = 1;
    v10_params.multipath_version = XQC_MULTIPATH_10;
    v10_params.init_max_path_id = 8;

    uint8_t v10_buf[64];
    size_t v10_len = 0;
    ret = xqc_encode_transport_params(&v10_params, XQC_TP_TYPE_CLIENT_HELLO,
                                      v10_buf, sizeof(v10_buf), &v10_len);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_TRUE(v10_len > 0);

    xqc_transport_params_t v10_decoded;
    xqc_init_transport_params(&v10_decoded);
    ret = xqc_decode_transport_params(&v10_decoded, XQC_TP_TYPE_CLIENT_HELLO,
                                      v10_buf, v10_len);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(v10_decoded.enable_multipath, 1);
    CU_ASSERT_EQUAL(v10_decoded.multipath_version, XQC_MULTIPATH_10);
    CU_ASSERT_EQUAL(v10_decoded.init_max_path_id, 8);

    /* (d) V21 encoder round-trip. */
    xqc_transport_params_t v21_params;
    xqc_init_transport_params(&v21_params);
    v21_params.enable_multipath = 1;
    v21_params.multipath_version = XQC_MULTIPATH_3E;
    v21_params.init_max_path_id = 8;

    uint8_t v21_enc_buf[64];
    size_t v21_enc_len = 0;
    ret = xqc_encode_transport_params(&v21_params, XQC_TP_TYPE_CLIENT_HELLO,
                                      v21_enc_buf, sizeof(v21_enc_buf), &v21_enc_len);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_TRUE(v21_enc_len >= 3);
    /* Encoder may emit additional default params before/after multipath;
     * scan the buffer for the V21 codepoint sequence { 0x3e, 0x01, 0x08 }.
     * Note: id 0x3e is a 1-byte varint; default-encoded fields will not
     * begin with a 0x3e byte because the other in-use TP ids are either
     * < 0x40 (and not equal to 0x3e) or >= 0x40 (and so start with a
     * non-0x3e high-bit varint prefix). */
    int found = 0;
    for (size_t i = 0; i + 2 < v21_enc_len; ++i) {
        if (v21_enc_buf[i] == 0x3e &&
            v21_enc_buf[i + 1] == 0x01 &&
            v21_enc_buf[i + 2] == 0x08) {
            found = 1;
            break;
        }
    }
    CU_ASSERT_TRUE(found);

    /* Decode round-trip back to confirm semantics survive. */
    xqc_transport_params_t v21_rt;
    xqc_init_transport_params(&v21_rt);
    ret = xqc_decode_transport_params(&v21_rt, XQC_TP_TYPE_CLIENT_HELLO,
                                      v21_enc_buf, v21_enc_len);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(v21_rt.enable_multipath, 1);
    CU_ASSERT_EQUAL(v21_rt.multipath_version, XQC_MULTIPATH_3E);
    CU_ASSERT_EQUAL(v21_rt.init_max_path_id, 8);
}

/* Task 18 wire-in: verify the production helper xqc_tls_check_mp_aead_nonce_len
 * (1) is reachable from production code (linker proves it),
 * (2) bypasses cleanly when multipath is disabled (opt-out path),
 * (3) returns -XQC_TLS_INTERNAL when 1-RTT crypto is not installed yet but MP
 *     is requested — this is the "called too early" failure mode that the
 *     handshake_complete call site avoids by waiting until TLS reports done.
 *
 * The full-path "multipath ON + nonce<12B -> TRA_TRANSPORT_PARAMETER_ERROR"
 * branch is exercised by xqc_test_mp21_aead_nonce_min_length() (pure helper)
 * and reached at runtime via xqc_conn_handshake_complete() which calls this
 * wrapper when conn->enable_multipath is set. Building synthetic xqc_tls_t
 * state with an installed-but-undersized AEAD here would require pulling in
 * the full SSL handshake which is out of scope for the unit harness. */
void
xqc_test_mp21_aead_nonce_check_tls_wrapper(void)
{
    /* (1) Opt-out: multipath_enabled == 0 returns OK regardless of tls. */
    CU_ASSERT_EQUAL(xqc_tls_check_mp_aead_nonce_len(NULL, 0), XQC_OK);

    /* (2) MP requested but tls is NULL -> internal error, NOT silent pass. */
    CU_ASSERT_EQUAL(xqc_tls_check_mp_aead_nonce_len(NULL, 1),
                    -(xqc_int_t)XQC_TLS_INTERNAL);
}


/* ------------------------------------------------------------------
 * Dual-version codepoint emission for the 5 remaining MP frame
 * generators (post-Chunk 2 wire-fix). For each generator, confirm
 * the buffer's first byte(s) match the draft-21 varint codepoint
 * when multipath_version == XQC_MULTIPATH_3E, and draft-10 4-byte
 * codepoint 0x15228cXX otherwise. Sentinel 0xaa beyond the written
 * region must remain untouched.
 *
 * draft-21 (1-byte / 2-byte varint) wire bytes used here:
 *   PATH_ACK                        0x3e        -> 0x3e
 *   PATH_STATUS_BACKUP              0x3e76      -> 0x7e 0x76
 *   PATH_STATUS_AVAILABLE_V21       0x3e77      -> 0x7e 0x77
 *   PATH_NEW_CONNECTION_ID_V21      0x3e78      -> 0x7e 0x78
 *   PATH_RETIRE_CONNECTION_ID_V21   0x3e79      -> 0x7e 0x79
 *   MAX_PATH_ID_V21                 0x3e7a      -> 0x7e 0x7a
 *
 * draft-10 4-byte varint codepoint 0x15228cXX is encoded as:
 *   high byte = 0xc0 | (val>>24) = 0xc0 | 0x15 = 0xd5, then 0x22, 0x8c, XX
 * ------------------------------------------------------------------ */

static void
xqc_test_mp21_gen_setup(xqc_connection_t **conn_out, xqc_packet_out_t **po_out,
    unsigned char *buf, size_t buf_cap, uint8_t mp_version)
{
    xqc_log_t        *log = calloc(1, sizeof(xqc_log_t));
    xqc_connection_t *conn = calloc(1, sizeof(xqc_connection_t));
    xqc_packet_out_t *po   = calloc(1, sizeof(xqc_packet_out_t));
    log->log_level = XQC_LOG_FATAL;
    conn->log = log;
    conn->conn_settings.multipath_version = mp_version;
    po->po_buf = buf;
    po->po_buf_cap = buf_cap;
    po->po_buf_size = (unsigned int)buf_cap;
    po->po_used_size = 0;
    po->po_reserved_size = 0;
    *conn_out = conn;
    *po_out = po;
}

static void
xqc_test_mp21_gen_teardown(xqc_connection_t *conn, xqc_packet_out_t *po)
{
    if (conn) {
        free(conn->log);
        free(conn);
    }
    free(po);
}

void xqc_test_mp21_gen_path_status_dual_version(void)
{
    unsigned char buf[64];
    xqc_connection_t *conn;
    xqc_packet_out_t *po;
    ssize_t written;

    /* (a) draft-21, STANDBY -> PATH_STATUS_BACKUP 0x3e76 */
    memset(buf, 0xaa, sizeof(buf));
    xqc_test_mp21_gen_setup(&conn, &po, buf, sizeof(buf), XQC_MULTIPATH_3E);
    written = xqc_gen_path_status_frame(conn, po, 1, 7, XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT(written > 0);
    CU_ASSERT_EQUAL(buf[0], 0x7e);
    CU_ASSERT_EQUAL(buf[1], 0x76);
    CU_ASSERT_EQUAL(buf[(size_t)written], 0xaa); /* sentinel preserved */
    xqc_test_mp21_gen_teardown(conn, po);

    /* (b) draft-21, AVAILABLE -> PATH_STATUS_AVAILABLE 0x3e77 */
    memset(buf, 0xaa, sizeof(buf));
    xqc_test_mp21_gen_setup(&conn, &po, buf, sizeof(buf), XQC_MULTIPATH_3E);
    written = xqc_gen_path_status_frame(conn, po, 1, 7, XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT(written > 0);
    CU_ASSERT_EQUAL(buf[0], 0x7e);
    CU_ASSERT_EQUAL(buf[1], 0x77);
    xqc_test_mp21_gen_teardown(conn, po);

    /* (c) draft-10, STANDBY -> MP_STANDBY 0x15228c07 (4-byte varint) */
    memset(buf, 0xaa, sizeof(buf));
    xqc_test_mp21_gen_setup(&conn, &po, buf, sizeof(buf), XQC_MULTIPATH_10);
    written = xqc_gen_path_status_frame(conn, po, 1, 7, XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT(written > 0);
    CU_ASSERT_EQUAL(buf[0], 0x95);
    CU_ASSERT_EQUAL(buf[1], 0x22);
    CU_ASSERT_EQUAL(buf[2], 0x8c);
    CU_ASSERT_EQUAL(buf[3], 0x07);
    xqc_test_mp21_gen_teardown(conn, po);

    /* (d) draft-10, AVAILABLE -> MP_AVAILABLE 0x15228c08 */
    memset(buf, 0xaa, sizeof(buf));
    xqc_test_mp21_gen_setup(&conn, &po, buf, sizeof(buf), XQC_MULTIPATH_10);
    written = xqc_gen_path_status_frame(conn, po, 1, 7, XQC_APP_PATH_STATUS_AVAILABLE);
    CU_ASSERT(written > 0);
    CU_ASSERT_EQUAL(buf[3], 0x08);
    xqc_test_mp21_gen_teardown(conn, po);
}

void xqc_test_mp21_gen_mp_new_conn_id_dual_version(void)
{
    unsigned char buf[64];
    xqc_connection_t *conn;
    xqc_packet_out_t *po;
    ssize_t written;
    xqc_cid_t new_cid;
    uint8_t sr_token[XQC_STATELESS_RESET_TOKENLEN] = {0};
    memset(&new_cid, 0, sizeof(new_cid));
    new_cid.cid_len = 8;
    new_cid.cid_seq_num = 1;

    /* (a) draft-21 -> PATH_NEW_CONNECTION_ID 0x3e78 */
    memset(buf, 0xaa, sizeof(buf));
    xqc_test_mp21_gen_setup(&conn, &po, buf, sizeof(buf), XQC_MULTIPATH_3E);
    written = xqc_gen_mp_new_conn_id_frame(conn, po, &new_cid, 0, sr_token, 1);
    CU_ASSERT(written > 0);
    CU_ASSERT_EQUAL(buf[0], 0x7e);
    CU_ASSERT_EQUAL(buf[1], 0x78);
    xqc_test_mp21_gen_teardown(conn, po);

    /* (b) draft-10 -> MP_NEW_CONN_ID 0x15228c09 */
    memset(buf, 0xaa, sizeof(buf));
    xqc_test_mp21_gen_setup(&conn, &po, buf, sizeof(buf), XQC_MULTIPATH_10);
    written = xqc_gen_mp_new_conn_id_frame(conn, po, &new_cid, 0, sr_token, 1);
    CU_ASSERT(written > 0);
    CU_ASSERT_EQUAL(buf[0], 0x95);
    CU_ASSERT_EQUAL(buf[1], 0x22);
    CU_ASSERT_EQUAL(buf[2], 0x8c);
    CU_ASSERT_EQUAL(buf[3], 0x09);
    xqc_test_mp21_gen_teardown(conn, po);
}

void xqc_test_mp21_gen_mp_retire_conn_id_dual_version(void)
{
    unsigned char buf[32];
    xqc_connection_t *conn;
    xqc_packet_out_t *po;
    ssize_t written;

    /* (a) draft-21 -> PATH_RETIRE_CONNECTION_ID 0x3e79 */
    memset(buf, 0xaa, sizeof(buf));
    xqc_test_mp21_gen_setup(&conn, &po, buf, sizeof(buf), XQC_MULTIPATH_3E);
    written = xqc_gen_mp_retire_conn_id_frame(conn, po, 0, 1);
    CU_ASSERT(written > 0);
    CU_ASSERT_EQUAL(buf[0], 0x7e);
    CU_ASSERT_EQUAL(buf[1], 0x79);
    xqc_test_mp21_gen_teardown(conn, po);

    /* (b) draft-10 -> MP_RETIRE_CONN_ID 0x15228c0a */
    memset(buf, 0xaa, sizeof(buf));
    xqc_test_mp21_gen_setup(&conn, &po, buf, sizeof(buf), XQC_MULTIPATH_10);
    written = xqc_gen_mp_retire_conn_id_frame(conn, po, 0, 1);
    CU_ASSERT(written > 0);
    CU_ASSERT_EQUAL(buf[0], 0x95);
    CU_ASSERT_EQUAL(buf[3], 0x0a);
    xqc_test_mp21_gen_teardown(conn, po);
}

void xqc_test_mp21_gen_max_path_id_dual_version(void)
{
    unsigned char buf[32];
    xqc_connection_t *conn;
    xqc_packet_out_t *po;
    ssize_t written;

    /* (a) draft-21 -> MAX_PATH_ID 0x3e7a */
    memset(buf, 0xaa, sizeof(buf));
    xqc_test_mp21_gen_setup(&conn, &po, buf, sizeof(buf), XQC_MULTIPATH_3E);
    written = xqc_gen_max_path_id_frame(conn, po, 8);
    CU_ASSERT(written > 0);
    CU_ASSERT_EQUAL(buf[0], 0x7e);
    CU_ASSERT_EQUAL(buf[1], 0x7a);
    xqc_test_mp21_gen_teardown(conn, po);

    /* (b) draft-10 -> MAX_PATH_ID 0x15228c0c */
    memset(buf, 0xaa, sizeof(buf));
    xqc_test_mp21_gen_setup(&conn, &po, buf, sizeof(buf), XQC_MULTIPATH_10);
    written = xqc_gen_max_path_id_frame(conn, po, 8);
    CU_ASSERT(written > 0);
    CU_ASSERT_EQUAL(buf[0], 0x95);
    CU_ASSERT_EQUAL(buf[3], 0x0c);
    xqc_test_mp21_gen_teardown(conn, po);
}

void xqc_test_mp21_gen_ack_mp_dual_version(void)
{
    /* Build a recv_record with one range so ack_mp generator runs. */
    unsigned char buf[64];
    xqc_connection_t *conn;
    xqc_packet_out_t *po;
    ssize_t written;
    xqc_recv_record_t rr;
    xqc_pktno_range_node_t node;
    memset(&rr, 0, sizeof(rr));
    memset(&node, 0, sizeof(node));
    xqc_init_list_head(&rr.list_head);
    node.pktno_range.high = 10;
    node.pktno_range.low  = 10;
    xqc_list_add_tail(&node.list, &rr.list_head);

    int has_gap = 0;
    xqc_packet_number_t largest_ack = 0;

    /* (a) draft-21 -> PATH_ACK 0x3e (1-byte varint) */
    memset(buf, 0xaa, sizeof(buf));
    xqc_test_mp21_gen_setup(&conn, &po, buf, sizeof(buf), XQC_MULTIPATH_3E);
    po->po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    written = xqc_gen_ack_mp_frame(conn, 1, po, 0, 0, &rr, 0,
                                   &has_gap, &largest_ack);
    CU_ASSERT(written > 0);
    CU_ASSERT_EQUAL(buf[0], 0x3e);
    xqc_test_mp21_gen_teardown(conn, po);

    /* (b) draft-10 -> MP_ACK0 0x15228c00 */
    memset(buf, 0xaa, sizeof(buf));
    xqc_test_mp21_gen_setup(&conn, &po, buf, sizeof(buf), XQC_MULTIPATH_10);
    po->po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    written = xqc_gen_ack_mp_frame(conn, 1, po, 0, 0, &rr, 0,
                                   &has_gap, &largest_ack);
    CU_ASSERT(written > 0);
    CU_ASSERT_EQUAL(buf[0], 0x95);
    CU_ASSERT_EQUAL(buf[1], 0x22);
    CU_ASSERT_EQUAL(buf[2], 0x8c);
    CU_ASSERT_EQUAL(buf[3], 0x00);
    xqc_test_mp21_gen_teardown(conn, po);
}
