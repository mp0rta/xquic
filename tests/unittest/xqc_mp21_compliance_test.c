#include <CUnit/CUnit.h>
#include <string.h>
#include "xquic/xquic.h"
#include "xquic/xqc_errno.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_conn.h"
#include "xqc_mp21_compliance_test.h"

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
