#ifndef _XQC_MP21_COMPLIANCE_TEST_H
#define _XQC_MP21_COMPLIANCE_TEST_H

void xqc_test_mp21_version_enum(void);
void xqc_test_mp21_frame_type_constants(void);
void xqc_test_mp21_path_abandon_recv_no_reason(void);
void xqc_test_mp10_path_abandon_recv_with_reason_still_works(void);
void xqc_test_mp21_path_abandon_gen_no_reason(void);
void xqc_test_mp21_dual_version_dispatch(void);
void xqc_test_mp21_path_ack_ecn_parse_skip(void);

#endif /* _XQC_MP21_COMPLIANCE_TEST_H */
