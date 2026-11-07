/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_TEST_FLOW_CTL_H_INCLUDED_
#define _XQC_TEST_FLOW_CTL_H_INCLUDED_

void xqc_test_flow_ctl_clamp_boundary(void);
void xqc_test_stream_flow_ctl_clamp(void);
void xqc_test_conn_flow_ctl_clamp(void);
void xqc_test_flow_ctl_normal_no_clamp(void);
void xqc_test_conn_credit_reset_extends(void);
void xqc_test_conn_credit_parked_bytes(void);
void xqc_test_conn_credit_reset_at_final_size_extends(void);
void xqc_test_conn_credit_reset_checks_once(void);
void xqc_test_conn_window_monotone(void);
void xqc_test_conn_window_resized_by_reads_not_arrivals(void);
void xqc_test_conn_window_doubling_from_last_resize(void);
void xqc_test_conn_window_resized_at_half_window_read_without_credit_due(void);
void xqc_test_conn_credit_reset_over_limit_is_flow_control_error(void);
void xqc_test_conn_window_resize_boundary_is_strictly_more_than_half(void);
void xqc_test_conn_window_not_resized_by_reads_with_receive_rate(void);

#endif /* _XQC_TEST_FLOW_CTL_H_INCLUDED_ */
