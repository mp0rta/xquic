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

#endif
