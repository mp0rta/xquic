/**
 * @copyright Copyright (c) 2026, mp0rta
 */

#ifndef XQUIC_XQC_H3_BODY_BUF_TEST_H
#define XQUIC_XQC_H3_BODY_BUF_TEST_H

void xqc_test_h3bb_settings_propagate(void);
void xqc_test_h3bb_limit_zero_reads_all(void);
void xqc_test_h3bb_fixture_engine_turn(void);
void xqc_test_h3bb_pause_at_limit(void);
void xqc_test_h3bb_paused_notify_reads_nothing(void);
void xqc_test_h3bb_tiny_data_coalesced(void);
void xqc_test_h3bb_no_pause_after_fin(void);
void xqc_test_h3bb_no_pause_after_reset(void);
void xqc_test_h3bb_no_pause_reliable_prefix_read(void);
void xqc_test_h3bb_body_bytes_accounting(void);
void xqc_test_h3bb_resume_in_body_notify(void);
void xqc_test_h3bb_resume_in_engine_elsewhere(void);
void xqc_test_h3bb_resume_outside_engine(void);
void xqc_test_h3bb_resume_loop_stops_on_conn_close(void);
void xqc_test_h3bb_resume_during_destroy_not_queued(void);
void xqc_test_h3bb_resume_loop_no_empty_notify(void);
void xqc_test_h3bb_resume_loop_no_notify_after_close(void);
void xqc_test_h3bb_resume_loop_final_empty_data_fin(void);
void xqc_test_h3bb_qpack_blocked_pause(void);
void xqc_test_h3bb_tiny_data_coalesced_replay(void);
void xqc_test_h3bb_qpack_blocked_replay_resumes(void);

#endif
