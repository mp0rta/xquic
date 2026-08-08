/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <string.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "xqc_random_test.h"
#include "xqc_pq_test.h"
#include "xqc_conn_test.h"
#include "xqc_engine_test.h"
#include "xqc_common_test.h"
#include "xqc_vint_test.h"
#include "xqc_recv_record_test.h"
#include "xqc_reno_test.h"
#include "xqc_cubic_test.h"
#include "xqc_packet_test.h"
#include "xqc_stream_frame_test.h"
#include "xqc_process_frame_test.h"
#include "xqc_tp_test.h"
#include "xqc_tls_test.h"
#include "xqc_crypto_test.h"
#include "xqc_h3_test.h"
#include "xqc_stable_test.h"
#include "xqc_dtable_test.h"
#include "utils/xqc_2d_hash_table_test.h"
#include "utils/xqc_ring_array_test.h"
#include "utils/xqc_ring_mem_test.h"
#include "utils/xqc_huffman_test.h"
#include "xqc_encoder_test.h"
#include "xqc_qpack_test.h"
#include "xqc_prefixed_str_test.h"
#include "xqc_cid_test.h"
#include "xqc_id_hash_test.h"
#include "xqc_retry_test.h"
#include "xqc_datagram_test.h"
#include "xqc_h3_ext_test.h"
#include "xqc_galois_test.h"
#include "xqc_fec_scheme_test.h"
#include "xqc_fec_test.h"
#include "xqc_ack_with_timestamp_test.h"
#include "xqc_masque_test.h"
#include "xqc_mp21_compliance_test.h"
#include "xqc_test_helpers.h"
#include "xqc_test_path_hard_cap.h"
#include "xqc_test_next_wakeup.h"
#include "xqc_set_conn_settings_test.h"
#include "xqc_crypto_frame_test.h"
#include "xqc_dos_e2e_test.h"
#include "xqc_wlb_test.h"
#include "xqc_send_ctl_test.h"
#include "xqc_vn_test.h"
#include "xqc_frame_type_bit_test.h"

static int
xqc_init_suite(void)
{
    return 0;
}
static int
xqc_clean_suite(void)
{
    return 0;
}

int
main(int argc, char *argv[])
{
    CU_pSuite pSuite = NULL;
    CU_pTest pTest = NULL;
    unsigned int failed_tests_count;

    if (argc > 2) {
        fprintf(stderr, "usage: %s [test-name]\n", argv[0]);
        return 2;
    }

    if (CU_initialize_registry() != CUE_SUCCESS) {
        printf("CU_initialize error\n");
        return (int)CU_get_error();
    }

    pSuite = CU_add_suite("libxquic_TestSuite", xqc_init_suite, xqc_clean_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (!CU_add_test(pSuite, "xqc_cid_test", xqc_test_cid)
        || !CU_add_test(pSuite, "xqc_test_cid_active_limit", xqc_test_cid_active_limit)
        || !CU_add_test(pSuite, "xqc_test_cid_handshake_exclusion", xqc_test_cid_handshake_exclusion)
        || !CU_add_test(pSuite, "xqc_test_cid_mark_original_idempotent", xqc_test_cid_mark_original_idempotent)
        || !CU_add_test(pSuite, "xqc_test_cid_delete_original", xqc_test_cid_delete_original)
        || !CU_add_test(pSuite, "xqc_test_get_random", xqc_test_get_random)
        || !CU_add_test(pSuite, "xqc_test_engine_create", xqc_test_engine_create)
        || !CU_add_test(pSuite, "xqc_test_conn_create", xqc_test_conn_create)
        || !CU_add_test(pSuite, "xqc_test_conn_idle_timeout", xqc_test_conn_idle_timeout)
        || !CU_add_test(pSuite, "xqc_test_conn_early_data_reject", xqc_test_conn_early_data_reject)
        || !CU_add_test(pSuite, "xqc_test_conn_early_data_reject_flow_ctl", xqc_test_conn_early_data_reject_flow_ctl)
        /* RFC 9000 §20.1 CRYPTO_ERROR dynamic construction */
        || !CU_add_test(pSuite, "xqc_test_conn_tls_error_cb_constructs_crypto_error", xqc_test_conn_tls_error_cb_constructs_crypto_error)
        || !CU_add_test(pSuite, "xqc_test_conn_crypto_error_base_value", xqc_test_conn_crypto_error_base_value)
        || !CU_add_test(pSuite, "xqc_test_conn_tls_error_first_writer_wins", xqc_test_conn_tls_error_first_writer_wins)
        || !CU_add_test(pSuite, "xqc_test_conn_tls_error_cb_alert_zero", xqc_test_conn_tls_error_cb_alert_zero)
        || !CU_add_test(pSuite, "xqc_test_conn_tls_error_cb_max_alert", xqc_test_conn_tls_error_cb_max_alert)
        || !CU_add_test(pSuite, "xqc_test_pq", xqc_test_pq)
        || !CU_add_test(pSuite, "xqc_test_common", xqc_test_common)
        || !CU_add_test(pSuite, "xqc_test_vint", xqc_test_vint)
        || !CU_add_test(pSuite, "xqc_test_recv_record", xqc_test_recv_record)
        || !CU_add_test(pSuite, "xqc_test_reno", xqc_test_reno)
        || !CU_add_test(pSuite, "xqc_test_reno_init_cwnd", xqc_test_reno_init_cwnd)
        || !CU_add_test(pSuite, "xqc_test_reno_init_cwnd_override", xqc_test_reno_init_cwnd_override)
        || !CU_add_test(pSuite, "xqc_test_cubic", xqc_test_cubic)
        || !CU_add_test(pSuite, "xqc_test_cubic_init_cwnd", xqc_test_cubic_init_cwnd)
        || !CU_add_test(pSuite, "xqc_test_short_header_parse_cid", xqc_test_short_header_packet_parse_cid)
        || !CU_add_test(pSuite, "xqc_test_long_header_parse_cid", xqc_test_long_header_packet_parse_cid)
        || !CU_add_test(pSuite, "xqc_test_crypto_frame_flood", xqc_test_crypto_frame_flood)
        || !CU_add_test(pSuite, "xqc_test_crypto_frame_bytes_limit", xqc_test_crypto_frame_bytes_limit)
        || !CU_add_test(pSuite, "xqc_test_crypto_frame_recycle", xqc_test_crypto_frame_recycle)
        || !CU_add_test(pSuite, "xqc_test_stream_frame_offset_overflow", xqc_test_stream_frame_offset_overflow)
        || !CU_add_test(pSuite, "xqc_test_crypto_frame_in_0rtt_rejected", xqc_test_crypto_frame_in_0rtt_rejected)
        || !CU_add_test(pSuite, "xqc_test_crypto_frame_in_initial_accepted", xqc_test_crypto_frame_in_initial_accepted)
        || !CU_add_test(pSuite, "xqc_test_crypto_frame_in_handshake_accepted", xqc_test_crypto_frame_in_handshake_accepted)
        || !CU_add_test(pSuite, "xqc_test_crypto_frame_in_short_header_accepted", xqc_test_crypto_frame_in_short_header_accepted)
        || !CU_add_test(pSuite, "xqc_test_crypto_frame_dispatched_via_xqc_process_frame", xqc_test_crypto_frame_dispatched_via_xqc_process_frame)
        || !CU_add_test(pSuite, "xqc_test_crypto_in_0rtt_emits_connection_close", xqc_test_crypto_in_0rtt_emits_connection_close)
        || !CU_add_test(pSuite, "xqc_test_crypto", xqc_test_crypto)
        || !CU_add_test(pSuite, "xqc_test_hp_sample_boundary", xqc_test_hp_sample_boundary)
        || !CU_add_test(pSuite, "xqc_test_packet_encrypt_hp_sample_boundary", xqc_test_packet_encrypt_hp_sample_boundary)
        || !CU_add_test(pSuite, "xqc_test_empty_pkt", xqc_test_empty_pkt)
        || !CU_add_test(pSuite, "xqc_test_stateless_reset_parse_boundary", xqc_test_stateless_reset_parse_boundary)
        || !CU_add_test(pSuite, "xqc_test_transport_params", xqc_test_transport_params)
        || !CU_add_test(pSuite, "xqc_test_tp_cid_overflow", xqc_test_tp_cid_overflow)
        || !CU_add_test(pSuite, "xqc_test_check_transport_params_cids", xqc_test_check_transport_params_cids)
        || !CU_add_test(pSuite, "xqc_test_engine_packet_process", xqc_test_engine_packet_process)
        || !CU_add_test(pSuite, "xqc_test_stream_frame", xqc_test_stream_frame)
                || !CU_add_test(pSuite, "xqc_test_stream_frame_buffered_limit", xqc_test_stream_frame_buffered_limit)
        || !CU_add_test(pSuite, "xqc_test_process_frame", xqc_test_process_frame)
        || !CU_add_test(pSuite, "xqc_test_parse_padding_frame", xqc_test_parse_padding_frame)
        || !CU_add_test(pSuite, "xqc_test_large_ack_frame", xqc_test_large_ack_frame)
        /* issue #632: ACK_ECN frame parsing (RFC 9000 19.3) */
        || !CU_add_test(pSuite, "xqc_test_ack_ecn_normal_parse", xqc_test_ack_ecn_normal_parse)
        || !CU_add_test(pSuite, "xqc_test_ack_plain_regression", xqc_test_ack_plain_regression)
        || !CU_add_test(pSuite, "xqc_test_ack_ecn_truncated", xqc_test_ack_ecn_truncated)
        || !CU_add_test(pSuite, "xqc_test_ack_ecn_followed_by_ping", xqc_test_ack_ecn_followed_by_ping)
        || !CU_add_test(pSuite, "xqc_test_new_conn_id_zero_len_cid", xqc_test_new_conn_id_zero_len_cid)
        || !CU_add_test(pSuite, "xqc_test_new_conn_id_active_limit_accept",
                        xqc_test_new_conn_id_active_limit_accept)
        || !CU_add_test(pSuite, "xqc_test_new_conn_id_active_limit_exceeded",
                        xqc_test_new_conn_id_active_limit_exceeded)
        || !CU_add_test(pSuite, "xqc_test_conn_close_application_error_type",
                        xqc_test_conn_close_application_error_type)
        || !CU_add_test(pSuite,
                        "xqc_test_conn_close_transport_error_type_overlap",
                        xqc_test_conn_close_transport_error_type_overlap)
        || !CU_add_test(pSuite, "xqc_test_h3_frame", xqc_test_frame)
        || !CU_add_test(pSuite, "xqc_test_h3_single_vint_frame_valid",
                        xqc_test_h3_single_vint_frame_valid)
        || !CU_add_test(pSuite,
                        "xqc_test_h3_single_vint_frame_length_error",
                        xqc_test_h3_single_vint_frame_length_error)
        || !CU_add_test(pSuite, "xqc_test_tls", xqc_test_tls)
        || !CU_add_test(pSuite, "xqc_test_h3_stream", xqc_test_stream)
        || !CU_add_test(pSuite, "xqc_test_h3_critical_stream_close", xqc_test_h3_critical_stream_close)
        || !CU_add_test(pSuite, "xqc_test_h3_second_control_stream_rejected", xqc_test_h3_second_control_stream_rejected)
        || !CU_add_test(pSuite, "xqc_test_h3_reserved_uni_stream_accepted",
                        xqc_test_h3_reserved_uni_stream_accepted)
        || !CU_add_test(pSuite, "xqc_test_h3_push_stream_error_codes",
                        xqc_test_h3_push_stream_error_codes)
        || !CU_add_test(pSuite, "xqc_test_h3_max_push_id_valid",
                        xqc_test_h3_max_push_id_valid)
        || !CU_add_test(pSuite, "xqc_test_h3_max_push_id_errors",
                        xqc_test_h3_max_push_id_errors)
        /* RFC 9114 §4.2.2 field-section-size 32B overhead (issue 751) */
        || !CU_add_test(pSuite, "xqc_test_h3_uncompressed_fields_size", xqc_test_h3_uncompressed_fields_size)
        || !CU_add_test(pSuite, "xqc_test_h3_recv_header_field_section_size", xqc_test_h3_recv_header_field_section_size)
        /* issue #744: RFC 9114 §4.1.2 / §8.1 H3_MESSAGE_ERROR + INTERNAL split */
        || !CU_add_test(pSuite, "xqc_test_h3_message_error_code_value", xqc_test_h3_message_error_code_value)
        || !CU_add_test(pSuite, "xqc_test_h3_malformed_headers_uses_message_error", xqc_test_h3_malformed_headers_uses_message_error)
        || !CU_add_test(pSuite, "xqc_test_h3_headers_capacity_uses_internal_error", xqc_test_h3_headers_capacity_uses_internal_error)
        || !CU_add_test(pSuite, "xqc_test_h3_valid_headers_smoke", xqc_test_h3_valid_headers_smoke)
        || !CU_add_test(pSuite, "xqc_test_h3_frame_parse_error_uses_frame_error", xqc_test_h3_frame_parse_error_uses_frame_error)
                || !CU_add_test(pSuite, "xqc_test_h3_settings_frame_size_limit", xqc_test_h3_settings_frame_size_limit)
        || !CU_add_test(pSuite, "xqc_test_h3_control_frame_unexpected", xqc_test_h3_control_frame_unexpected)
        || !CU_add_test(pSuite, "xqc_test_h3_missing_settings", xqc_test_h3_missing_settings)
        || !CU_add_test(pSuite, "xqc_test_h3_request_frame_unexpected", xqc_test_h3_request_frame_unexpected)
        || !CU_add_test(pSuite,
                        "xqc_test_h3_server_reserved_request_frame_accepted",
                        xqc_test_h3_server_reserved_request_frame_accepted)
        || !CU_add_test(pSuite,
                        "xqc_test_h3_server_push_promise_rejected",
                        xqc_test_h3_server_push_promise_rejected)
        /* issue #746: RFC 9114 §4.2 forbidden connection-specific headers */
        || !CU_add_test(pSuite, "xqc_test_h3_message_error_enum", xqc_test_h3_message_error_enum)
        || !CU_add_test(pSuite, "xqc_test_h3_forbidden_headers_rejected", xqc_test_h3_forbidden_headers_rejected)
        || !CU_add_test(pSuite, "xqc_test_h3_allowed_headers_pass", xqc_test_h3_allowed_headers_pass)
        || !CU_add_test(pSuite, "xqc_test_h3_blocked_stream_limit_uses_local", xqc_test_h3_blocked_stream_limit_uses_local)
        || !CU_add_test(pSuite, "xqc_test_stable", xqc_test_stable)
        || !CU_add_test(pSuite, "xqc_test_dtable", xqc_test_dtable)
        || !CU_add_test(pSuite, "test_2d_hash_table", test_2d_hash_table)
        || !CU_add_test(pSuite, "test_ring_array", test_ring_array)
        || !CU_add_test(pSuite, "xqc_test_ring_mem", xqc_test_ring_mem)
        || !CU_add_test(pSuite, "xqc_test_huffman", xqc_test_huffman)
        || !CU_add_test(pSuite, "xqc_test_encoder", xqc_test_encoder)
        || !CU_add_test(pSuite, "xqc_test_h3_ins", xqc_test_ins)
        || !CU_add_test(pSuite, "xqc_test_h3_rep", xqc_test_rep)
        || !CU_add_test(pSuite, "xqc_qpack_test", xqc_qpack_test)
        || !CU_add_test(pSuite, "xqc_test_prefixed_str", xqc_test_prefixed_str)
        || !CU_add_test(pSuite, "xqc_test_id_hash", xqc_test_id_hash)
        || !CU_add_test(pSuite, "xqc_test_retry", xqc_test_retry)
        || !CU_add_test(pSuite, "xqc_test_receive_invalid_dgram", xqc_test_receive_invalid_dgram)
        || !CU_add_test(pSuite, "xqc_test_h3_ext_frame", xqc_test_h3_ext_frame)
        /* --- from mqvpn-main PR#52: multipath validation-stall fix tests --- */
        || !CU_add_test(pSuite, "test_next_wakeup_includes_validating_path_timer",
                        test_next_wakeup_includes_validating_path_timer)
        || !CU_add_test(pSuite, "test_validation_pto_counts_attempts_and_abandons",
                        test_validation_pto_counts_attempts_and_abandons)
#ifdef XQC_ENABLE_FEC
        || !CU_add_test(pSuite, "xqc_test_galois_calculation",
                        xqc_test_galois_calculation) ||
        !CU_add_test(pSuite, "xqc_test_fec_scheme", xqc_test_fec_scheme) ||
        !CU_add_test(pSuite, "xqc_test_fec", xqc_test_fec)
#endif
        || !CU_add_test(pSuite, "xqc_test_ack_with_timestamp", xqc_test_ack_with_timestamp)
        || !CU_add_test(pSuite, "xqc_test_pto_uses_remote_max_ack_delay",
                        xqc_test_pto_uses_remote_max_ack_delay)
        || !CU_add_test(pSuite, "xqc_test_pto_remote_default_when_unset",
                        xqc_test_pto_remote_default_when_unset)
        || !CU_add_test(pSuite, "xqc_test_send_ctl_update_rtt_ack_delay_cap",
                        xqc_test_send_ctl_update_rtt_ack_delay_cap)
        /* issue #739: persistent-congestion RTT reset (RFC 9002 §5.2) */
        || !CU_add_test(pSuite, "xqc_test_send_ctl_persistent_congestion_resets_rtt",
                        xqc_test_send_ctl_persistent_congestion_resets_rtt)
        || !CU_add_test(pSuite, "xqc_test_send_ctl_persistent_congestion_rtt_reseeds_from_new_sample",
                        xqc_test_send_ctl_persistent_congestion_rtt_reseeds_from_new_sample)
        || !CU_add_test(pSuite, "xqc_test_send_ctl_single_loss_does_not_reset_rtt",
                        xqc_test_send_ctl_single_loss_does_not_reset_rtt)
        || !CU_add_test(pSuite, "xqc_test_send_ctl_persistent_congestion_no_rtt_sample_early_return",
                        xqc_test_send_ctl_persistent_congestion_no_rtt_sample_early_return)
        /* RFC 9000 §6.2 Version Negotiation abort suite */
        || !CU_add_test(pSuite, "xqc_test_vn_abort_on_unsupported_version", xqc_test_vn_abort_on_unsupported_version)
        || !CU_add_test(pSuite, "xqc_test_vn_downgrade_protection_when_version_matches", xqc_test_vn_downgrade_protection_when_version_matches)
        || !CU_add_test(pSuite, "xqc_test_vn_reject_when_dcid_mismatch", xqc_test_vn_reject_when_dcid_mismatch)
        || !CU_add_test(pSuite, "xqc_test_vn_reject_when_scid_mismatch", xqc_test_vn_reject_when_scid_mismatch)
        || !CU_add_test(pSuite, "xqc_test_vn_reject_when_state_not_initial_sent", xqc_test_vn_reject_when_state_not_initial_sent)
        || !CU_add_test(pSuite, "xqc_test_vn_abort_on_multi_unsupported_versions", xqc_test_vn_abort_on_multi_unsupported_versions)
        /* issue #534: xqc_frame_type_bit_t 64-bit overflow fix */
        || !CU_add_test(pSuite, "xqc_test_frame_type_enum_ordinals",
                        xqc_test_frame_type_enum_ordinals)
        || !CU_add_test(pSuite, "xqc_test_frame_bit_high_values_nonzero",
                        xqc_test_frame_bit_high_values_nonzero)
        || !CU_add_test(pSuite, "xqc_test_frame_type_bit_sizeof",
                        xqc_test_frame_type_bit_sizeof)
        || !CU_add_test(pSuite, "xqc_test_frame_bit_or_high_low",
                        xqc_test_frame_bit_or_high_low)
        || !CU_add_test(pSuite, "xqc_test_need_repair_with_high_bit",
                        xqc_test_need_repair_with_high_bit)
        || !CU_add_test(pSuite, "xqc_test_ack_eliciting_with_high_bit",
                        xqc_test_ack_eliciting_with_high_bit)
        || !CU_add_test(pSuite, "xqc_test_can_in_flight_with_high_bit",
                        xqc_test_can_in_flight_with_high_bit)
        || !CU_add_test(pSuite, "xqc_test_frame_type_2_str_high_bit",
                        xqc_test_frame_type_2_str_high_bit)
        || !CU_add_test(pSuite, "xqc_test_packet_frame_types_64bit_storage",
                        xqc_test_packet_frame_types_64bit_storage)
        || !CU_add_test(pSuite, "xqc_test_frame_bit_all_constants_correct",
                        xqc_test_frame_bit_all_constants_have_correct_bit_position)
        || !CU_add_test(pSuite, "xqc_test_frame_bit_32bit_boundary",
                        xqc_test_frame_bit_32bit_boundary)
        || !CU_add_test(pSuite, "xqc_test_frame_type_bit_roundtrip",
                        xqc_test_frame_type_bit_roundtrip)
        /* RFC 9001 Appendix A test vector verification (#719) */
        || !CU_add_test(pSuite, "xqc_test_rfc9001_initial_secret", xqc_test_rfc9001_initial_secret)
        || !CU_add_test(pSuite, "xqc_test_rfc9001_derive_initial_secrets", xqc_test_rfc9001_derive_initial_secrets)
        || !CU_add_test(pSuite, "xqc_test_rfc9001_client_initial_keys", xqc_test_rfc9001_client_initial_keys)
        || !CU_add_test(pSuite, "xqc_test_rfc9001_server_initial_keys", xqc_test_rfc9001_server_initial_keys)
        /* issue #695: initial salt strlen fix */
        || !CU_add_test(pSuite, "xqc_test_initial_salt_length", xqc_test_initial_salt_length)
        || !CU_add_test(pSuite, "xqc_test_initial_salt_v1_value", xqc_test_initial_salt_v1_value)
        || !CU_add_test(pSuite, "xqc_test_initial_salt_null_byte_regression", xqc_test_initial_salt_null_byte_regression)
        /* issue #717: 0-RTT transport parameter validation (RFC 9000 Section 7.4.1) */
        || !CU_add_test(pSuite, "xqc_test_0rtt_params_all_equal",
                        xqc_test_0rtt_params_all_equal)
        || !CU_add_test(pSuite, "xqc_test_0rtt_params_all_increased",
                        xqc_test_0rtt_params_all_increased)
        || !CU_add_test(pSuite, "xqc_test_0rtt_params_each_reduced",
                        xqc_test_0rtt_params_each_reduced)
        || !CU_add_test(pSuite, "xqc_test_early_params_forbidden_fields_reset",
                        xqc_test_early_params_forbidden_fields_reset)
        || !CU_add_test(pSuite, "xqc_test_0rtt_calc_pto_ignores_stale_max_ack_delay",
                        xqc_test_0rtt_calc_pto_ignores_stale_max_ack_delay)
        || !CU_add_test(pSuite, "xqc_test_0rtt_persistent_congestion_default_max_ack_delay",
                        xqc_test_0rtt_persistent_congestion_default_max_ack_delay)
        || !CU_add_test(pSuite, "xqc_test_pto_space_no_max_ack_delay_before_confirm",
                        xqc_test_pto_space_no_max_ack_delay_before_confirm)
        || !CU_add_test(pSuite, "xqc_test_0rtt_ack_delay_exponent_default_in_parse",
                        xqc_test_0rtt_ack_delay_exponent_default_in_parse)
        || !CU_add_test(pSuite, "xqc_test_0rtt_remote_mad_timeline",
                        xqc_test_0rtt_remote_mad_timeline)
        /* issue #704: AEAD integrity limit per RFC 9001 §6.6 */
        || !CU_add_test(pSuite, "xqc_test_aead_integrity_limit",
                        xqc_test_aead_integrity_limit)
        || !CU_add_test(pSuite, "xqc_test_aead_integrity_limit_unknown_cipher",
                        xqc_test_aead_integrity_limit_unknown_cipher)
        || !CU_add_test(pSuite, "xqc_test_aead_integrity_limit_conn_triggered",
                        xqc_test_aead_integrity_limit_conn_triggered)
        || !CU_add_test(pSuite, "xqc_test_aead_integrity_limit_conn_no_crypto",
                        xqc_test_aead_integrity_limit_conn_no_crypto)
        /* ALPN negotiation tests (issue #709) */
        || !CU_add_test(pSuite, "xqc_test_alpn_error_code_value",
                        xqc_test_alpn_error_code_value)
        || !CU_add_test(pSuite, "xqc_test_alpn_server_cb_propagates_error",
                        xqc_test_alpn_server_cb_propagates_error)
        || !CU_add_test(pSuite, "xqc_test_alpn_client_handshake_no_alpn",
                        xqc_test_alpn_client_handshake_no_alpn)
        || !CU_add_test(pSuite, "xqc_test_masque", xqc_test_masque)
        || !CU_add_test(pSuite, "xqc_test_datagram_send_on_path", xqc_test_datagram_send_on_path)
        || !CU_add_test(pSuite, "xqc_test_datagram_frame_path_pinning", xqc_test_datagram_frame_path_pinning)
        || !CU_add_test(pSuite, "xqc_test_mp21_version_enum", xqc_test_mp21_version_enum)
        || !CU_add_test(pSuite, "xqc_test_mp21_frame_type_constants", xqc_test_mp21_frame_type_constants)
        || !CU_add_test(pSuite, "xqc_test_mp21_path_abandon_recv_no_reason", xqc_test_mp21_path_abandon_recv_no_reason)
        || !CU_add_test(pSuite, "xqc_test_mp10_path_abandon_recv_with_reason_still_works", xqc_test_mp10_path_abandon_recv_with_reason_still_works)
        || !CU_add_test(pSuite, "xqc_test_mp21_path_abandon_gen_no_reason", xqc_test_mp21_path_abandon_gen_no_reason)
        || !CU_add_test(pSuite, "xqc_test_mp21_dual_version_dispatch", xqc_test_mp21_dual_version_dispatch)
        || !CU_add_test(pSuite, "xqc_test_mp21_path_ack_ecn_parse_skip", xqc_test_mp21_path_ack_ecn_parse_skip)
        || !CU_add_test(pSuite, "xqc_test_mp21_init_max_path_id_tp_codepoint", xqc_test_mp21_init_max_path_id_tp_codepoint)
        || !CU_add_test(pSuite, "xqc_test_mp21_fixture_smoke", xqc_test_mp21_fixture_smoke)
        || !CU_add_test(pSuite, "xqc_test_mp21_validate_recv_path_id", xqc_test_mp21_validate_recv_path_id)
        || !CU_add_test(pSuite, "xqc_test_mp21_max_path_id_validation", xqc_test_mp21_max_path_id_validation)
        || !CU_add_test(pSuite, "xqc_test_mp21_init_max_path_id_upper_bound", xqc_test_mp21_init_max_path_id_upper_bound)
        || !CU_add_test(pSuite, "xqc_test_mp21_aead_nonce_min_length", xqc_test_mp21_aead_nonce_min_length)
        || !CU_add_test(pSuite, "xqc_test_mp21_mp_frame_1rtt_only", xqc_test_mp21_mp_frame_1rtt_only)
        || !CU_add_test(pSuite, "xqc_test_mp21_path_new_conn_id_cid_len_guard", xqc_test_mp21_path_new_conn_id_cid_len_guard)
        || !CU_add_test(pSuite, "xqc_test_mp21_non_zero_cid_constraint", xqc_test_mp21_non_zero_cid_constraint)
        || !CU_add_test(pSuite, "xqc_test_mp21_abandoned_path_silently_ignored", xqc_test_mp21_abandoned_path_silently_ignored)
        || !CU_add_test(pSuite, "xqc_test_mp21_duplicate_path_abandon_short_circuit", xqc_test_mp21_duplicate_path_abandon_short_circuit)
        || !CU_add_test(pSuite, "xqc_test_mp21_path_create_refuses_abandoned", xqc_test_mp21_path_create_refuses_abandoned)
        || !CU_add_test(pSuite, "xqc_test_mp21_aead_nonce_check_tls_wrapper", xqc_test_mp21_aead_nonce_check_tls_wrapper)
        || !CU_add_test(pSuite, "xqc_test_mp21_gen_path_status_dual_version", xqc_test_mp21_gen_path_status_dual_version)
        || !CU_add_test(pSuite, "xqc_test_mp21_parse_path_status_v21_codepoints", xqc_test_mp21_parse_path_status_v21_codepoints)
        || !CU_add_test(pSuite, "xqc_test_mp21_parse_mp_new_retire_conn_id_v21_codepoints", xqc_test_mp21_parse_mp_new_retire_conn_id_v21_codepoints)
        || !CU_add_test(pSuite, "xqc_test_mp21_gen_mp_new_conn_id_dual_version", xqc_test_mp21_gen_mp_new_conn_id_dual_version)
        || !CU_add_test(pSuite, "xqc_test_mp21_gen_mp_retire_conn_id_dual_version", xqc_test_mp21_gen_mp_retire_conn_id_dual_version)
        || !CU_add_test(pSuite, "xqc_test_mp21_gen_max_path_id_dual_version", xqc_test_mp21_gen_max_path_id_dual_version)
        || !CU_add_test(pSuite, "xqc_test_mp21_gen_ack_mp_dual_version", xqc_test_mp21_gen_ack_mp_dual_version)
        || !CU_add_test(pSuite, "xqc_test_mp21_paths_blocked_validation", xqc_test_mp21_paths_blocked_validation)
        || !CU_add_test(pSuite, "xqc_test_mp21_path_cids_blocked_validation", xqc_test_mp21_path_cids_blocked_validation)
        || !CU_add_test(pSuite, "xqc_test_mp21_blocked_frames_pi_frame_types", xqc_test_mp21_blocked_frames_pi_frame_types)
        || !CU_add_test(pSuite, "xqc_test_mp21_solo_frame_in_datagram_no_pv", xqc_test_mp21_solo_frame_in_datagram_no_pv)
        || !CU_add_test(pSuite, "xqc_test_mp21_max_path_id_grant_disabled_by_default", xqc_test_mp21_max_path_id_grant_disabled_by_default)
        || !CU_add_test(pSuite, "xqc_test_mp21_max_path_id_grant_trigger_on_paths_blocked", xqc_test_mp21_max_path_id_grant_trigger_on_paths_blocked)
        || !CU_add_test(pSuite, "xqc_test_mp21_max_path_id_grant_skipped_at_max", xqc_test_mp21_max_path_id_grant_skipped_at_max)
        || !CU_add_test(pSuite, "xqc_test_mp21_max_path_id_grant_rate_limited", xqc_test_mp21_max_path_id_grant_rate_limited)
        || !CU_add_test(pSuite, "xqc_test_mp21_path_challenge_1200b_validation", xqc_test_mp21_path_challenge_1200b_validation)
        || !CU_add_test(pSuite, "xqc_test_mp21_path_validation_timeout", xqc_test_mp21_path_validation_timeout)
        || !CU_add_test(pSuite, "xqc_test_mp21_loss_replay_should_suppress_stale", xqc_test_mp21_loss_replay_should_suppress_stale)
        || !CU_add_test(pSuite, "xqc_test_mp21_gp10_iteration_visits_all_unused", xqc_test_mp21_gp10_iteration_visits_all_unused)
        || !CU_add_test(pSuite, "xqc_test_mp21_gp10_skips_above_curr_max", xqc_test_mp21_gp10_skips_above_curr_max)
        || !CU_add_test(pSuite, "xqc_test_mp21_gp14_pick_alt_active_path", xqc_test_mp21_gp14_pick_alt_active_path)
        || !CU_add_test(pSuite, "xqc_test_mp21_gp14_pick_alt_active_path_single", xqc_test_mp21_gp14_pick_alt_active_path_single)
        || !CU_add_test(pSuite, "xqc_test_mp21_gen_paths_blocked_frame", xqc_test_mp21_gen_paths_blocked_frame)
        || !CU_add_test(pSuite, "test_path_create_no_heavy_state_on_validation_fail", test_path_create_no_heavy_state_on_validation_fail)
        || !CU_add_test(pSuite, "test_path_create_hard_cap_stress", test_path_create_hard_cap_stress)
        || !CU_add_test(pSuite, "test_conn_stats_dynamic_paths_info", test_conn_stats_dynamic_paths_info)
        || !CU_add_test(pSuite, "test_dos_peer_init_max_path_id_max_valid", test_dos_peer_init_max_path_id_max_valid)
        || !CU_add_test(pSuite, "xqc_test_server_set_conn_settings_propagation", xqc_test_server_set_conn_settings_propagation)
        || !CU_add_test(pSuite, "xqc_test_server_set_conn_settings_zero_defaults", xqc_test_server_set_conn_settings_zero_defaults)
        || !CU_add_test(pSuite, "xqc_test_server_set_conn_settings_clamp", xqc_test_server_set_conn_settings_clamp)
        || !CU_add_test(pSuite, "xqc_test_conn_flush_or_defer", xqc_test_conn_flush_or_defer)
        || !CU_add_test(pSuite, "xqc_test_dos_crypto_frame_flood_recv_path", xqc_test_dos_crypto_frame_flood_recv_path)
        || !CU_add_test(pSuite, "xqc_test_h3_blocked_buf_limit", xqc_test_h3_blocked_buf_limit)
        || !CU_add_test(pSuite, "xqc_test_wlb_asym_p1_pin_to_wide", xqc_test_wlb_asym_p1_pin_to_wide)
        || !CU_add_test(pSuite, "xqc_test_wlb_asym_p1_pin_to_wide_when_wide_blocked", xqc_test_wlb_asym_p1_pin_to_wide_when_wide_blocked)
        || !CU_add_test(pSuite, "xqc_test_wlb_soft_pin_no_repin_on_block", xqc_test_wlb_soft_pin_no_repin_on_block)
        || !CU_add_test(pSuite, "xqc_test_wlb_sym_multiflow_distributes", xqc_test_wlb_sym_multiflow_distributes)
        || !CU_add_test(pSuite, "xqc_test_wlb_recovery_prefer_skips_initial_path_addition", xqc_test_wlb_recovery_prefer_skips_initial_path_addition)
        || !CU_add_test(pSuite, "xqc_test_wlb_recovery_prefer_fires_after_real_failover", xqc_test_wlb_recovery_prefer_fires_after_real_failover)
        || !CU_add_test(pSuite, "xqc_test_wlb_single_path_does_not_pin", xqc_test_wlb_single_path_does_not_pin)
        || !CU_add_test(pSuite, "xqc_test_wlb_new_path_detected_without_expire_throttle", xqc_test_wlb_new_path_detected_without_expire_throttle)
        || !CU_add_test(pSuite, "xqc_test_wlb_reinject_bypasses_pin", xqc_test_wlb_reinject_bypasses_pin)
        /* ADD TESTS HERE */)
    {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    if (argc == 2) {
        pTest = CU_get_test_by_name(argv[1], pSuite);
        if (pTest == NULL) {
            fprintf(stderr, "unknown test: %s\n", argv[1]);
            CU_cleanup_registry();
            return 2;
        }

        CU_basic_run_test(pSuite, pTest);

    } else {
        CU_basic_run_tests();
    }

    failed_tests_count = CU_get_number_of_tests_failed();

    CU_cleanup_registry();
    if (CU_get_error() == CUE_SUCCESS) {
        return (int)failed_tests_count;
    } else {
        printf("CUnit Error: %s\n", CU_get_error_msg());
        return (int)CU_get_error();
    }
}
