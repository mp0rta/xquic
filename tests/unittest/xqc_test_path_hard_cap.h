/**
 * @copyright Copyright (c) 2026, mqvpn project
 *
 * PR3 Chunk 1: tests for the three-stage xqc_path_create() refactor
 * and the XQC_PATH_HARD_CAP defensive ceiling.
 */

#ifndef XQC_TEST_PATH_HARD_CAP_H
#define XQC_TEST_PATH_HARD_CAP_H

void test_path_create_no_heavy_state_on_validation_fail(void);
void test_path_create_hard_cap_stress(void);
void test_conn_stats_dynamic_paths_info(void);
void test_dos_peer_init_max_path_id_max_valid(void);

#endif /* XQC_TEST_PATH_HARD_CAP_H */
