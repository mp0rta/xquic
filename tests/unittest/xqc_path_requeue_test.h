/**
 * @copyright Copyright (c) 2026, Abdul Wasey
 */

#ifndef XQC_PATH_REQUEUE_TEST_H_INCLUDED
#define XQC_PATH_REQUEUE_TEST_H_INCLUDED

void xqc_test_path_requeue_unacked_on_pto(void);
void xqc_test_path_requeue_needs_a_working_path(void);
void xqc_test_minrtt_skips_dead_path(void);
void xqc_test_minrtt_keeps_path_without_alternative(void);
void xqc_test_minrtt_probes_dead_path(void);

#endif /* XQC_PATH_REQUEUE_TEST_H_INCLUDED */
