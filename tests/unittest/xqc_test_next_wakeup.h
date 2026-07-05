/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * B3: xqc_conn_next_wakeup_time must include timers of INIT/VALIDATING
 * paths so PATH_CHALLENGE retransmission is driven by the PTO timer.
 */

#ifndef XQC_TEST_NEXT_WAKEUP_H
#define XQC_TEST_NEXT_WAKEUP_H

void test_next_wakeup_includes_validating_path_timer(void);

#endif /* XQC_TEST_NEXT_WAKEUP_H */
