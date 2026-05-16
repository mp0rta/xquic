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
 * (renamed from L1+ "_parse_and_discard" — bodies now cover the violation/
 * ignore matrix specified by the L2 plan §M1). */
void xqc_test_mp21_paths_blocked_validation(void);
void xqc_test_mp21_path_cids_blocked_validation(void);

/* mp21 L2 M3 — MAX_PATH_ID credit grant gate behaviour. */
void xqc_test_mp21_max_path_id_grant_disabled_by_default(void);
void xqc_test_mp21_max_path_id_grant_trigger_on_paths_blocked(void);
void xqc_test_mp21_max_path_id_grant_skipped_at_max(void);
void xqc_test_mp21_max_path_id_grant_rate_limited(void);

/* PR5 L5b validation hardening — draft-21 §3.1 path-validation MUSTs. */
void xqc_test_mp21_path_challenge_1200b_validation(void);
void xqc_test_mp21_path_validation_timeout(void);

/* PR6 L5c loss-replay correctness — draft-21 §4.3 ¶12 / §4.6 ¶8 SHOULDs. */
void xqc_test_mp21_loss_replay_should_suppress_stale(void);

/* PR7 L5d send-side RECOMMENDEDs.
 *  - G-P10 (§3.2.1 ¶1): proactive CID per unused path_id.
 *  - G-P14 (§3.4 ¶3):   PATH_ABANDON on an alternate open path.
 */
void xqc_test_mp21_gp10_iteration_visits_all_unused(void);
void xqc_test_mp21_gp10_skips_above_curr_max(void);
void xqc_test_mp21_gp14_pick_alt_active_path(void);

#endif /* _XQC_MP21_COMPLIANCE_TEST_H */
