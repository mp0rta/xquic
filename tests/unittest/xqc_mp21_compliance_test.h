#ifndef _XQC_MP21_COMPLIANCE_TEST_H
#define _XQC_MP21_COMPLIANCE_TEST_H

#include <stdint.h>
#include <stddef.h>
#include "src/transport/xqc_conn.h"

/* Chunk 4 shared test fixture (Task 13b).
 *
 * Builds a minimum xqc_connection_t + xqc_log_t sufficient to exercise
 * draft-21 frame-processor guards without spinning up a real engine /
 * TLS / socket. Only the fields touched by Tasks 14-23 are populated;
 * everything else stays zeroed-out by calloc().
 *
 * The fixture is XQC_MULTIPATH_3E-only by design — draft-10 guards are
 * still exercised in pre-existing tests. `remote_init_max_path_id` is
 * mutated by Task 15 callers AFTER xqc_test_mp21_make_conn() returns.
 */
typedef struct xqc_test_mp21_conn_params_s {
    uint64_t    local_max_path_id;
    uint64_t    remote_max_path_id;
    uint8_t     scid_len;
    uint8_t     dcid_len;
} xqc_test_mp21_conn_params_t;

xqc_connection_t *xqc_test_mp21_make_conn(const xqc_test_mp21_conn_params_t *p);
void xqc_test_mp21_free_conn(xqc_connection_t *conn);

void xqc_test_mp21_version_enum(void);
void xqc_test_mp21_frame_type_constants(void);
void xqc_test_mp21_path_abandon_recv_no_reason(void);
void xqc_test_mp10_path_abandon_recv_with_reason_still_works(void);
void xqc_test_mp21_path_abandon_gen_no_reason(void);
void xqc_test_mp21_dual_version_dispatch(void);
void xqc_test_mp21_path_ack_ecn_parse_skip(void);
void xqc_test_mp21_init_max_path_id_tp_codepoint(void);

/* Chunk 4 — Tasks 13b through 23. */
void xqc_test_mp21_fixture_smoke(void);
void xqc_test_mp21_validate_recv_path_id(void);
void xqc_test_mp21_max_path_id_validation(void);
void xqc_test_mp21_init_max_path_id_upper_bound(void);
void xqc_test_mp21_aead_nonce_min_length(void);
void xqc_test_mp21_mp_frame_1rtt_only(void);
void xqc_test_mp21_path_new_conn_id_cid_len_guard(void);
void xqc_test_mp21_non_zero_cid_constraint(void);
void xqc_test_mp21_abandoned_path_silently_ignored(void);
void xqc_test_mp21_duplicate_path_abandon_short_circuit(void);
void xqc_test_mp21_path_create_refuses_abandoned(void);
void xqc_test_mp21_aead_nonce_check_tls_wrapper(void);

/* Dual-version codepoint emission tests for the 5 remaining MP generators. */
void xqc_test_mp21_gen_path_status_dual_version(void);
void xqc_test_mp21_gen_mp_new_conn_id_dual_version(void);
void xqc_test_mp21_gen_mp_retire_conn_id_dual_version(void);
void xqc_test_mp21_gen_max_path_id_dual_version(void);
void xqc_test_mp21_gen_ack_mp_dual_version(void);

/* draft-21 §4.7 informational frames: mp21 L2 M1 full receive validation
 * (the test names keep the legacy "_parse_and_discard" suffix to preserve
 * git blame and CI history; the test bodies cover the violation/ignore
 * matrix specified by the L2 plan §M1). */
void xqc_test_mp21_paths_blocked_parse_and_discard(void);
void xqc_test_mp21_path_cids_blocked_parse_and_discard(void);

#endif /* _XQC_MP21_COMPLIANCE_TEST_H */
