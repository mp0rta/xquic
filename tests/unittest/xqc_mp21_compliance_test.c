#include <CUnit/CUnit.h>
#include "xquic/xquic.h"
#include "xqc_mp21_compliance_test.h"

void xqc_test_mp21_version_enum(void)
{
    /* XQC_MULTIPATH_3E must exist and equal 0x3e */
    CU_ASSERT_EQUAL((int)XQC_MULTIPATH_3E, 0x3e);
    /* XQC_MULTIPATH_10 should still exist for dual-version dispatch */
    CU_ASSERT_EQUAL((int)XQC_MULTIPATH_10, 0x0a);
}
