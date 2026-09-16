/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WLB scheduler invariant tests.
 *
 * Tests the documented contract of the WLB Datagram scheduler
 * (xqc_scheduler_wlb.c header comment + commit log) under controlled
 * path-state fixtures. The scheduler is exercised through its public
 * callback table; per-path cwnd / SRTT / loss are driven via mocked
 * congestion-control callbacks so each test isolates one invariant.
 */
#ifndef XQC_WLB_TEST_H_INCLUDED
#define XQC_WLB_TEST_H_INCLUDED

/* I1 Asymmetric P=1: a freshly opened TCP flow pins to the wide path. */
void xqc_test_wlb_asym_p1_pin_to_wide(void);

/* I1+I3 Asymmetric P=1 with wide cwnd-blocked at first packet:
 *      pin still lands on the wide path; only this packet spills over. */
void xqc_test_wlb_asym_p1_pin_to_wide_when_wide_blocked(void);

/* I3 Soft-pin spillover: while the pinned path is cwnd-blocked the next
 *    packet uses another path WITHOUT updating the flow table; once the
 *    pin path is sendable again the flow returns to it. */
void xqc_test_wlb_soft_pin_no_repin_on_block(void);

/* I2 Symmetric multi-flow: flows distribute across paths (no convergence
 *    to paths[0]). */
void xqc_test_wlb_sym_multiflow_distributes(void);

/* Recovery-prefer must NOT fire when the secondary path simply appears for
 * the first time (initial 2nd-path setup is not a recovery event). */
void xqc_test_wlb_recovery_prefer_skips_initial_path_addition(void);

/* Recovery-prefer DOES fire after a real path-down → path-up cycle: the
 * recovered path is preferred for the first re-pin of an active flow. */
void xqc_test_wlb_recovery_prefer_fires_after_real_failover(void);

/* rev6: the n_paths==1 single-path fast path must NOT pin the flow.
 * Otherwise when a secondary path appears later, early flows stay
 * locked on paths[0] forever (Fix A prevents the wipe that would
 * otherwise rescue them). After the secondary path joins, NEW flows
 * must reach wlb_pick_pin_path and distribute via max-deficit
 * alternation. */
void xqc_test_wlb_single_path_does_not_pin(void);

/* A secondary path that becomes active must be picked up by the scheduler
 * PROMPTLY — without waiting for the 1/sec wlb_flow_expire throttle window
 * to elapse. Otherwise the secondary's inclusion in s->paths is delayed up
 * to ~1s, during which the primary warms its cwnd and then captures ALL
 * flow pins (the sym P=16 aggregation collapse confirmed via WLB_INSTR).
 * After the path appears, new flows must distribute across both paths even
 * though the expire throttle has NOT yet unblocked. */
void xqc_test_wlb_new_path_detected_without_expire_throttle(void);

/* Reinjection queries (reinject=1) must bypass flow pinning and route
 * through the origin-excluding MinRTT fallback, even for an already-pinned
 * flow whose replica's po_path_id equals the pinned path. */
void xqc_test_wlb_reinject_bypasses_pin(void);

/* Hybrid TCP lane bytes are QUIC STREAM data with po_flow_hash == 0, and
 * they take the MinRTT fallback, not WRR. One ordered byte sequence has
 * nothing to gain from a second estimator on top of cwnd, and every packet
 * placed on a higher-RTT path is a reassembly hole with no deadline layer
 * under it. MinRTT still aggregates: the cwnd gate spills once the near path
 * is full. See xqc_wlb_scheduler_get_path for the measurements. */
void xqc_test_wlb_stream_data_prefers_lowest_srtt(void);
void xqc_test_wlb_stream_data_spills_when_primary_is_full(void);
void xqc_test_wlb_path_replacement_refreshes_cache(void);
void xqc_test_wlb_control_packets_use_minrtt(void);
void xqc_test_wlb_evicted_path_gets_recovery_probe(void);
void xqc_test_wlb_evicted_probe_rotates_past_blocked_path(void);
void xqc_test_wlb_stream_data_never_rides_a_blackholed_path(void);
void xqc_test_wlb_blackholed_path_does_not_stall_rounds(void);
void xqc_test_wlb_unpinned_blackhole_refreshes_topology(void);
void xqc_test_wlb_routine_path_event_preserves_round(void);
void xqc_test_wlb_measured_goodput_ignores_loss_penalty(void);
void xqc_test_wlb_idle_path_goodput_decays(void);
void xqc_test_wlb_warmed_zero_goodput_ignores_stale_estimate(void);
void xqc_test_wlb_equal_goodput_is_balanced(void);
void xqc_test_wlb_bloated_path_sheds_weight(void);
void xqc_test_wlb_four_to_one_goodput_after_acked_warmup(void);
void xqc_test_wlb_new_path_gets_warmup_floor(void);
void xqc_test_wlb_steady_path_gets_exploration_floor(void);
void xqc_test_wlb_active_time_ends_warmup(void);
void xqc_test_wlb_idle_time_does_not_end_warmup(void);
void xqc_test_wlb_app_limited_path_is_weighted_by_capacity(void);
void xqc_test_wlb_goodput_sample_ignores_sub_interval_burst(void);
void xqc_test_wlb_path_stats_snapshot(void);
void xqc_test_wlb_pinned_flow_refreshes_delivery_sample(void);
void xqc_test_wlb_warmup_time_only_credits_selected_path(void);
void xqc_test_wlb_topology_refresh_clears_packet_deficit(void);
void xqc_test_wlb_topology_refresh_clears_pin_deficit(void);
void xqc_test_wlb_ewma_uses_exact_seven_eighths_history(void);
void xqc_test_wlb_loss_above_two_percent_downweights_path(void);
void xqc_test_wlb_control_delivery_does_not_advance_learning(void);
void xqc_test_wlb_application_delivery_advances_learning(void);
void xqc_test_wlb_rejected_0rtt_does_not_advance_learning(void);
void xqc_test_wlb_duplicate_ack_counts_application_once(void);

#endif /* XQC_WLB_TEST_H_INCLUDED */
