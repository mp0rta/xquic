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
void xqc_test_backup_failover(void);
void xqc_test_backup_probes_dead_path(void);
void xqc_test_dead_probe_waits_for_fired_ptos(void);
void xqc_test_backup_skips_dead_primary(void);
void xqc_test_quiet_standby_rule(void);
void xqc_test_two_backups_not_quiet_without_primary(void);
void xqc_test_quiet_standby_woken_once(void);
void xqc_test_keepalive_skips_quiet_standby(void);
void xqc_test_idle_timer_keeps_quiet_standby(void);

#endif /* XQC_PATH_REQUEUE_TEST_H_INCLUDED */
