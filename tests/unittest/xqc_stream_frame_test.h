/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_STREAM_FRAME_TEST_H_INCLUDED_
#define _XQC_STREAM_FRAME_TEST_H_INCLUDED_

void  xqc_test_stream_frame();
void  xqc_test_stream_frame_buffered_limit();
void  xqc_test_stream_frame_cap_liveness();
void  xqc_test_stream_frame_fin_only_no_accumulation();
void  xqc_test_stream_frame_cap_tolerant_drop();
void  xqc_test_stream_frame_fc_before_cap();
void  xqc_test_stream_frame_fin_rejected_then_retransmitted();
void  xqc_test_stream_frame_cap_liveness_real();
void  xqc_test_stream_frame_dense_buffer_budget();
void  xqc_test_stream_frame_dense_prefix_liveness();
void  xqc_test_stream_frame_prefix_respects_hard_cap();
void  xqc_test_stream_frame_fin_repair_skips_discarded();
void  xqc_test_stream_frame_cap_setting();
void  xqc_test_stream_implicit_cap_sparse(void);
void  xqc_test_stream_implicit_cap_dense(void);
#ifdef XQC_ENABLE_TEST_HOOKS
void  xqc_test_stream_create_with_id(void);
#endif

#endif /* _XQC_STREAM_FRAME_TEST_H_INCLUDED_ */
