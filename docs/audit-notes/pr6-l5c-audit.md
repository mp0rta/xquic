# PR6 (L5c loss replay correctness) — findings

> **Verified against:** `mp0rta/xquic` commit `1a7a7eb` (branch
> `feat/mp21/L5c-loss-replay`). Re-audit needed if
> `xqc_send_ctl_detect_lost`, the `XQC_NEED_REPAIR` mask,
> `app_path_status_send_seq_num` lifecycle, or `local_max_path_id`
> monotonicity change.

Per slim memo pattern: only non-trivial findings recorded. The
mechanical fixes (helper + wire-in + test) are captured by the commit
bodies and don't need duplication here.

Spec: <https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/21/>

| ID | spec § | file:line | finding | verdict |
|---|---|---|---|---|
| G-F5 base SHOULD | §4.2 ¶6 | `src/transport/xqc_frame.h:170` | `XQC_NEED_REPAIR` mask already includes PATH_ABANDON (not in the excluded set: ACK / PADDING / PING / CONNECTION_CLOSE / DATAGRAM / SID / REPAIR_SYMBOL). Loss replay therefore already happens via `xqc_send_queue_copy_to_lost`. No PR6 code change needed. | clean (pre-existing) |
| G-F5 alt-path RECOMMENDED | §3.4 ¶3 | (deferred) | Rebinding a lost PATH_ABANDON to an alternate path via `po_path_id` mutation is insufficient: the packet header DCID has already been encoded into `po_payload` at send time. Re-emitting on a different path requires a fresh `xqc_write_path_abandon_to_packet` call on the alternate path. Deferred to PR7 G-P14 which handles broken-source rebind systematically. | deferred-to-PR7 |
| G-F19 stale detection assumption | §4.6 ¶8 | `src/transport/xqc_multipath.c:171` | `conn->local_max_path_id` is monotonically non-decreasing — only `+=` at the credit grant site (`new_max = local_max_path_id + XQC_MAX_PATH_ID_GRANT_INCREMENT`), no decrement site exists. Spec §4.6 forbids decrease. The strict `<` comparison in `xqc_loss_replay_should_suppress` is safe; `carried == local_max_path_id` returns 0 (replay) per "no more recent" wording. | recorded |
| Scope frontier (PATHS_BLOCKED / PATH_CIDS_BLOCKED) | §4.7 ¶14 | — | Retransmit-when-still-blocked of PATHS_BLOCKED / PATH_CIDS_BLOCKED is `MAY` per spec §4.7 ¶14, not in PR6 scope. Send-side emission of these frames lands in PR7 G-P16 (or deferred G-P17). The PR6 helper does not need a branch for them. | recorded |
