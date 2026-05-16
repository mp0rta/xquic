# PR4 (L5a) MUST-audit batch — findings

> **Verified against:** `mp0rta/xquic` commit `ddaae63` (PR4 third commit). Re-audit needed if MP frame parsers, `xqc_path_immediate_close`, `xqc_conn_add_path_cid_sets`, or `xqc_write_*_frame_to_packet` writers change.

Audit of 18 residual draft-ietf-quic-multipath-21 MUST / SHOULD / VERIFY
items flagged for L5a. Each row: where the relevant code lives, what it
does, and verdict.

Spec: <https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/21/>

**Summary: 14 clean / 1 compile-time pin / 1 deferred-to-mqvpn-side / 1 partial (receive clean, send-side constants deferred) / 1 deferred-to-future-PR.**

---

| ID | spec § | file:line | what code does | verdict |
|---|---|---|---|---|
| G-N2  | §2.1 ¶7   | `src/tls/xqc_crypto.c:81-91`, `src/tls/xqc_tls.c:1170-1189` | `xqc_crypto_check_mp_nonce_len` returns `-TRA_TRANSPORT_PARAMETER_ERROR` (not PROTOCOL_VIOLATION) when MP enabled and noncelen<12; wired at handshake_complete via `xqc_tls_check_mp_aead_nonce_len`. | clean |
| G-N7  | §2.3 ¶2   | `src/transport/xqc_frame.c:370-373, 912-944` | Legacy ACK (0x02/0x03) is dispatched to `xqc_process_ack_frame`, which credits acks against `conn->conn_initial_path` (path 0). No MP-rejection guard exists, so legacy ACKs for 0-RTT/1-RTT pkts on path 0 are still processed post-handshake. | clean |
| G-P1  | §3.4 ¶2,¶4 | `src/transport/xqc_frame.c:1938-2006`, `src/transport/xqc_multipath.c:453-492` | Normal branch calls `xqc_path_immediate_close(path)` which (a) writes corresponding PATH_ABANDON, (b) marks both `scid_set` and `dcid_set` for `path_id` to `XQC_CID_SET_ABANDONED` (lines 488-489). Path-not-found branch directly marks both sets ABANDONED (lines 1980-1981). Only-active-path branch goes to `xqc_conn_immediate_close` (conn-level CONNECTION_CLOSE), so per-path CID state is moot. The pre-PR4 residual gaps memo asserting the normal branch missed retirement was inaccurate — code at line 489 satisfies §3.4 ¶2. | clean |
| G-P4  | §3.1 ¶4   | `src/transport/xqc_frame.c:1715-1772` | `xqc_process_path_challenge_frame` resolves `path` from `packet_in->pi_path_id` (server may create path on demand) and calls `xqc_write_path_response_frame_to_packet(conn, path, ...)`. The frame is written onto the same path the challenge arrived on. | clean |
| G-P6  | §3.2.2 ¶1 | `src/transport/xqc_cid.c:453-479` | `xqc_get_unused_cid(set, cid, path_id)` calls `xqc_get_path_cid_set(set, path_id)` and iterates only the per-path inner_set. The picker cannot cross path_id boundaries. | clean |
| G-P8  | §3.2.1 ¶6 | `src/transport/xqc_packet_out.c:1710`, `src/transport/xqc_conn.c:5239-5300, 4284-4302`, `src/transport/xqc_frame.c:2330-2338` | inner_sets are only created for `path_id <= min(local_max_path_id, remote_max_path_id)` via `xqc_conn_add_path_cid_sets` at init (line 4340) and on MAX_PATH_ID grant (line 2333). The only caller of `xqc_write_mp_new_conn_id_frame_to_packet` is `xqc_conn_try_add_new_conn_id`, which iterates the existing inner_sets. Therefore over-cap path_ids can never be enqueued: the bookkeeping is the guard. | clean |
| G-P11 | §3.2 ¶2   | `src/transport/xqc_conn.c:5246-5296` | When `multipath_version >= XQC_MULTIPATH_10`, `xqc_conn_try_add_new_conn_id` issues `xqc_write_mp_new_conn_id_frame_to_packet` for every `XQC_CID_SET_USED` inner_set, including `XQC_INITIAL_PATH_ID` (path 0). Legacy `xqc_write_new_conn_id_frame_to_packet` only fires in non-MP mode (else branch at 5283). Path 0 uses the MP-form NEW_CONNECTION_ID in MP21 mode per spec. | clean |
| G-P12 | §3.2.2 ¶2 | `src/transport/xqc_frame.c:2207-2289`, `src/transport/xqc_conn.c:5239-5300`, `src/transport/xqc_engine.c:780` | `xqc_process_mp_retire_conn_id_frame` retires the SCID. On every engine main-tick the engine calls `xqc_conn_try_add_new_conn_id`, which top-ups unused_cnt back to `unused_limit=2` for each in-use inner_set (per-path). Replenishment is automatic. | clean |
| G-F6  | §4.2.1    | `include/xquic/xqc_errno.h:34-38` | Defined: `TRA_APPLICATION_ABANDON_PATH = 0x3e`, `TRA_PATH_RESOURCE_LIMIT_REACHED = 0x3e75`, `TRA_PATH_UNSTABLE_OR_POOR = 0x3e76`, `TRA_NO_CID_AVAILABLE_FOR_PATH = 0x3e77`. Generic `TRA_NO_ERROR = 0x0` covers NO_ERROR. The spec's STATELESS_RESET and MIGRATION_REFUSED error codes for PATH_ABANDON are not yet defined as named constants — only callers using the explicit numeric value would emit them, but no caller currently does. Receive-side parser accepts any varint error code so peer-emitted codes are still tolerated. | partial (receive clean, send-side constants deferred — see TODO in xqc_errno.h) |
| G-F12 | §4.4 ¶7   | `src/transport/xqc_frame.c:2054-2204` | The Retire Prior To enforcement (lines 2126-2152) calls `xqc_get_path_cid_set(&conn->dcid_set, path_id)` and `xqc_cid_set_set_largest_seq_or_rpt(..., path_id, ...)` — all retirement operations scoped to the same `path_id` carried in the frame. | clean |
| G-F14 | §4.5 ¶7   | `src/transport/xqc_frame.c:2207-2289` | `xqc_process_mp_retire_conn_id_frame` looks up SCID via `xqc_get_inner_cid_by_seq(&conn->scid_set, seq_num, path_id)`. Sequence number space is per-path. | clean |
| G-F15 | §4.5 ¶6   | `src/transport/xqc_frame.c:1153-1227` | Legacy `xqc_process_retire_conn_id_frame` always passes `XQC_INITIAL_PATH_ID` to `xqc_cid_set_get_largest_seq_or_rpt` / `xqc_get_inner_cid_by_seq` (lines 1169, 1188). Since the legacy frame has no path_id field, it inherently targets path 0 — spec compliant. | clean |
| G-I1a | §5.3      | `include/xquic/xquic.h:992,995,1599` | Public API exposes per-path `path_cwnd` (in stats struct) and `xqc_cong_ctl_get_cwnd` callback. mqvpn schedulers can read per-path cwnd. | clean |
| G-I1b | §5.3      | n/a (mqvpn repo) | Per-path cwnd gating in schedulers is a mqvpn-side concern, out of scope for the xquic library audit. | deferred-to-mqvpn-side |
| G-I2  | §5.3      | `src/transport/xqc_send_ctl.h:101-104` | `xqc_send_ctl_t::ctl_srtt`, `ctl_minrtt`, `ctl_rttvar`, `ctl_latest_rtt` are per-`send_ctl`, which is per-`path` (each `xqc_path_ctx_t` owns one `path_send_ctl`). Per-path RTT is therefore tracked and exposable. | clean |
| G-I3  | §5.4      | `src/transport/xqc_send_ctl.h:142,269`, `xqc_send_ctl_check_anti_amplification` impl | `ctl_bytes_recv` is a per-`send_ctl` field (= per-path). `xqc_send_ctl_check_anti_amplification(send_ctl, send_bytes)` takes the per-path send_ctl, so anti-amplification budget is enforced per path. | clean |
| G-I4  | RFC 9000 §9.4 | `src/transport/xqc_engine.c:1239-1284`, `src/transport/xqc_frame.c:1820-1855` | NAT rebinding validates the new peer address (PATH_CHALLENGE/PATH_RESPONSE) and updates `path->peer_addr`, but it does **not** call `xqc_cong_ctl_reset_cwnd` or reset RTT estimators after migration. RFC 9000 §9.4 mandates: "an endpoint MUST reset the congestion controller and round-trip time estimator." This is a genuine gap, but RFC 9000-side rather than draft-21-specific, and L5a's scope is the multipath audit batch. Filed for follow-up PR. | deferred-to-future-PR |
| G-C3  | §4 (frame bits) | `src/transport/xqc_frame.h:99-145` | Added 11 `_Static_assert` entries pinning each MP frame bit (ACK_MP, PATH_ABANDON, PATH_STATUS, PATH_STANDBY, PATH_AVAILABLE, MP_NEW_CONNECTION_ID, MP_RETIRE_CONNECTION_ID, MAX_PATH_ID, PATH_FROZEN) to its enum ordinal, plus two ordinal-range pins (`ACK_MP < 31`, `PATH_FROZEN < 31`) catching anyone reordering MP frames above the bit-31 boundary. Manual audit of `po_frame_types \|= XQC_FRAME_BIT_*` in `src/transport/xqc_frame_parser.c` confirms all 9 MP frame writers OR the correct bit (line 2398 ACK_MP, 2623 PATH_ABANDON, 2762 PATH_STATUS/STANDBY/AVAILABLE via `ft_flag`, 2891 MP_NEW_CID, 3006 MP_RETIRE_CID, 3081 MAX_PATH_ID). `XQC_IS_ACK_ELICITING` / `XQC_CAN_IN_FLIGHT` / `XQC_NEED_REPAIR` macros and loss replay therefore include MP frames correctly. | fix-applied |

---

## Notes on items flagged for follow-up

### G-F6 (PATH_ABANDON error codepoints)

draft-21 §4.2.1 enumerates six application error codes for the
PATH_ABANDON frame: NO_ERROR, RESOURCE_LIMIT_REACHED, UNSTABLE_INTERFACE,
NO_CID_AVAILABLE, STATELESS_RESET, MIGRATION_REFUSED. The codebase
defines three explicit constants (`TRA_PATH_RESOURCE_LIMIT_REACHED`,
`TRA_PATH_UNSTABLE_OR_POOR`, `TRA_NO_CID_AVAILABLE_FOR_PATH`) plus the
generic NO_ERROR (= 0). The two remaining codes (STATELESS_RESET,
MIGRATION_REFUSED) are not currently named.

Adding the missing constants requires confirming the IANA-assigned
codepoints against the latest draft, and no current send-site uses
them. Receive-side is already tolerant (parser accepts any varint).
Recommended for a tiny follow-up PR once codepoints are locked.

### G-I4 (NAT-rebind cwnd/RTT reset, RFC 9000 §9.4)

The NAT-rebinding flow in `xqc_engine.c:1239-1284` triggers
PATH_CHALLENGE/PATH_RESPONSE and updates `path->peer_addr` on success
(`xqc_frame.c:1827-1853`), but never invokes
`send_ctl->ctl_cong_callback->xqc_cong_ctl_reset_cwnd(send_ctl->ctl_cong)`
or resets the RTT estimator. RFC 9000 §9.4 requires both.

This is a single-path congestion-control concern (cwnd reset on
address change) and equally affects non-MP connections that experience
NAT rebinding. It is therefore better addressed in a focused RFC 9000
compliance PR rather than buried inside the multipath audit batch.
Recorded here so a future sweep can pick it up.

### G-I1b (mqvpn-side scheduler cwnd gating)

Spec §5.3 mandates per-path cwnd respect, but the actual gating
happens in mqvpn's scheduler dispatch (WLB / min_srtt / backup_fec).
xquic's job is to expose the per-path cwnd, which it does (G-I1a).
Marked deferred-to-mqvpn-side; not a xquic-repo task.
