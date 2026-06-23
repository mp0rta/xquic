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

#endif /* XQC_WLB_TEST_H_INCLUDED */
