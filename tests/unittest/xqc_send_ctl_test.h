/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_SEND_CTL_TEST_H
#define XQC_SEND_CTL_TEST_H

/*
 * Regression tests for issue #599 (RFC 9002 6.2.1):
 * xqc_send_ctl_calc_pto must use peer-reported max_ack_delay
 * (remote_settings), not local_settings.
 */
void xqc_test_pto_uses_remote_max_ack_delay(void);
void xqc_test_pto_remote_default_when_unset(void);

/* RFC 9000 Section 8.2.4 path-validation timeout behavior. */
void xqc_test_path_validation_timeout_current_pto_dominates(void);
void xqc_test_path_validation_timeout_new_path_pto_dominates(void);
void xqc_test_path_validation_timer_not_extended_by_packet(void);

/*
 * RFC 9002 5.3: xqc_send_ctl_update_rtt caps ack_delay by the peer's
 * max_ack_delay once the handshake is confirmed, judged by when the ACK
 * arrived. Before that it subtracts ack_delay in full, and ignores a
 * sample that ack_delay would take below min_rtt.
 */
void xqc_test_send_ctl_update_rtt_ack_delay_cap(void);

/*
 * RFC 9002 Section 5.3 permits subtracting ack_delay when the result is
 * exactly min_rtt, but forbids subtraction when the result is smaller.
 */
void xqc_test_send_ctl_update_rtt_subtracts_at_min_rtt(void);
void xqc_test_send_ctl_update_rtt_rejects_below_min_rtt(void);

/*
 * RFC 9002 Section 6.1.2 recommends a 1 ms timer granularity. Verify that
 * time-threshold loss detection fires at that boundary, but not before it.
 */
void xqc_test_send_ctl_granularity_marks_at_boundary(void);
void xqc_test_send_ctl_granularity_defers_before_boundary(void);

/*
 * Regression tests for issue #739 (RFC 9002 5.2):
 * After persistent congestion is detected the RTT estimator on the
 * affected path must be reset, and the next RTT sample must re-seed
 * the estimator via the first-sample branch of update_rtt.
 *
 * - resets_rtt: persistent congestion clears min_rtt/srtt/rttvar
 *   and first_rtt_sample_time, and resets cwnd.
 * - rtt_reseeds_from_new_sample: after reset, the very next sample
 *   becomes the new srtt/min_rtt directly (not smoothed with the
 *   stale srtt that triggered the reset).
 * - single_loss_does_not_reset_rtt: a single lost packet, which cannot
 *   establish persistent congestion, must leave RTT state untouched.
 * - no_rtt_sample_early_return: when no RTT sample has been taken
 *   yet, detect_lost returns before the persistent-congestion check
 *   and must not mutate RTT state.
 */
void xqc_test_send_ctl_persistent_congestion_resets_rtt(void);
void xqc_test_send_ctl_persistent_congestion_rtt_reseeds_from_new_sample(void);
void xqc_test_send_ctl_key_phase_acked_by_sent_packet_only(void);
void xqc_test_send_ctl_single_loss_does_not_reset_rtt(void);
void xqc_test_send_ctl_persistent_congestion_no_rtt_sample_early_return(void);

/*
 * RFC 9002 7.6.2: persistent congestion takes two lost ack-eliciting
 * packets sent after an RTT sample, and after the handshake is confirmed,
 * with no packet acknowledged in between, over longer than the duration
 * of 7.6.1; not the time since the last lost packet was sent, nor PTOs.
 * Per path with multipath.
 */
void xqc_test_send_ctl_pc_rfc9002_example(void);
void xqc_test_send_ctl_pc_acked_in_between(void);
void xqc_test_send_ctl_pc_needs_sample_and_confirmation(void);
void xqc_test_send_ctl_pc_lost_close_together(void);
void xqc_test_send_ctl_pc_loss_timer(void);
void xqc_test_send_ctl_pc_lost_pmtud_probe(void);
void xqc_test_send_ctl_pc_per_path(void);
void xqc_test_send_ctl_pc_pto_copies(void);
void xqc_test_send_ctl_pc_pto_spurious(void);

/*
 * RFC 9000 14.4: a lost PMTU probe is dropped without a congestion
 * reaction or a loss sample, while an ordinary lost packet still gets
 * both.
 */
void xqc_test_send_ctl_lost_pmtud_probe_no_cc_reaction(void);
void xqc_test_send_ctl_lost_packet_cc_reaction(void);

/*
 * A path that silently stops delivering while packets keep being sent on
 * it never gets a PTO (RFC 9002 6.2.1): xqc_send_ctl_get_effective_pto_count
 * counts the PTO expiries those sends hid, from the last progress on the
 * path to its last send, and the path class drops to LOW until an ACK
 * acknowledges a packet sent on it.
 */
void xqc_test_effective_pto_count_silent_path(void);
void xqc_test_effective_pto_count_bounds(void);

#endif
