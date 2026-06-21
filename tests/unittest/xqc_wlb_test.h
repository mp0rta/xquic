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

#endif /* XQC_WLB_TEST_H_INCLUDED */
