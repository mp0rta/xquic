/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * Tests for xqc_conn_reapply_settings().
 */
#ifndef XQC_CONN_REAPPLY_TEST_H_INCLUDED
#define XQC_CONN_REAPPLY_TEST_H_INCLUDED

void xqc_test_reapply_minrtt_to_wlb(void);
void xqc_test_reapply_same_vtable_keeps_state(void);
void xqc_test_reapply_refuses_two_paths(void);
void xqc_test_reapply_rejects_bad_args(void);
void xqc_test_reapply_params_zero_keeps_current(void);
void xqc_test_reapply_params_override(void);

#endif /* XQC_CONN_REAPPLY_TEST_H_INCLUDED */
