#include <CUnit/CUnit.h>
#include "xquic/xquic.h"
#include "xquic/xqc_errno.h"
#include "src/transport/xqc_frame_parser.h"
#include "xqc_mp21_compliance_test.h"

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
