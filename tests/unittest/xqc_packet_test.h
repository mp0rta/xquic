/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_PACKET_TEST_H
#define XQC_PACKET_TEST_H

void xqc_test_short_header_packet_parse_cid();
void xqc_test_long_header_packet_parse_cid();
void xqc_test_packet_encrypt_hp_sample_boundary();
void xqc_test_empty_pkt();
void xqc_test_stateless_reset_parse_boundary(void);
void xqc_test_ack_room_capped_at_mss(void);
void xqc_test_ack_refused_by_full_packet_at_cap(void);
void xqc_test_parse_uint32_high_bytes(void);


#endif
