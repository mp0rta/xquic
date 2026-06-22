/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * Standalone CUnit driver for the WLB scheduler tests, used while the
 * upstream run_tests target has unrelated build issues (FEC symbol
 * mismatch when XQC_ENABLE_PKM is off, masque test uninitialized vars).
 * Lets the WLB suite be exercised in isolation against the same
 * libxquic-static.a the production build links.
 */
#include <stdio.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "xqc_wlb_test.h"

static int wlb_suite_init(void) { return 0; }
static int wlb_suite_clean(void) { return 0; }

int
main(void)
{
    if (CU_initialize_registry() != CUE_SUCCESS) {
        return (int)CU_get_error();
    }

    CU_pSuite s = CU_add_suite("wlb", wlb_suite_init, wlb_suite_clean);
    if (s == NULL) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (NULL == CU_add_test(s, "asym_p1_pin_to_wide",
                            xqc_test_wlb_asym_p1_pin_to_wide)
        || NULL == CU_add_test(s, "asym_p1_pin_to_wide_when_wide_blocked",
                               xqc_test_wlb_asym_p1_pin_to_wide_when_wide_blocked)
        || NULL == CU_add_test(s, "soft_pin_no_repin_on_block",
                               xqc_test_wlb_soft_pin_no_repin_on_block)
        || NULL == CU_add_test(s, "sym_multiflow_distributes",
                               xqc_test_wlb_sym_multiflow_distributes)
        || NULL == CU_add_test(s, "recovery_prefer_skips_initial_path_addition",
                               xqc_test_wlb_recovery_prefer_skips_initial_path_addition)
        || NULL == CU_add_test(s, "recovery_prefer_fires_after_real_failover",
                               xqc_test_wlb_recovery_prefer_fires_after_real_failover)
        || NULL == CU_add_test(s, "single_path_does_not_pin",
                               xqc_test_wlb_single_path_does_not_pin)
        || NULL == CU_add_test(s, "new_path_detected_without_expire_throttle",
                               xqc_test_wlb_new_path_detected_without_expire_throttle))
    {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    unsigned failed = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    return (int)failed;
}
