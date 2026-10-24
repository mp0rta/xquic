/**
 * @copyright Copyright (c) 2026, Abdul Wasey
 */

#ifndef XQC_PMTUD_TEST_H_INCLUDED
#define XQC_PMTUD_TEST_H_INCLUDED

void xqc_test_pmtud_big_losses_make_path_suspect(void);
void xqc_test_pmtud_small_losses_do_not_make_path_suspect(void);
void xqc_test_pmtud_blackhole_confirmed_by_probes(void);
void xqc_test_pmtud_search_probe_loss_is_not_blackhole(void);
void xqc_test_pmtud_blackhole_at_base_goes_to_floor(void);
void xqc_test_pmtud_outage_at_base_keeps_base(void);
void xqc_test_pmtud_split_lost_stream_packet(void);
void xqc_test_pmtud_split_lost_rejects_other_packets(void);
void xqc_test_pmtud_drop_oversize_datagram(void);
void xqc_test_pmtud_drop_oversize_keeps_probes_and_fitting(void);
void xqc_test_pmtud_search_stops_within_precision(void);
void xqc_test_pmtud_search_probes_wide_range(void);

#endif /* XQC_PMTUD_TEST_H_INCLUDED */
