# PR8 / L5e audit memo

> **Verified against:** `mp0rta/xquic` branch `feat/mp21/L5e-paths-blocked`,
> 4 commits on top of `db887c1`. Re-audit needed if `ack_flag` plumbing,
> `xqc_write_ack_or_mp_ack_or_ext_ack_to_packets`, or the PATHS_BLOCKED
> rate-limit (`paths_blocked_last_sent_us`) lifecycle change.

Per slim memo pattern: only non-trivial findings recorded. Mechanical
gen/writer/trigger/test plumbing is captured by commit bodies.

Spec: <https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/21/>

## Scope

- G-P16 PATHS_BLOCKED send-side (§3.2.1 ¶7 + §4.7): gen + writer + Stage 1
  trigger + PTO rate-limit + frame enum + dual `_Static_assert`.
- G-N6 forensic re-audit (§2.3 SHOULD post-handshake PATH_ACK for 0-RTT).
- Wire coverage: gen via CUnit; writer+trigger via mqvpn netns log-grep
  e2e; full wire validation deferred to PR9 picoquic interop.

## Pre-memo grep audit

| query | count |
|---|---|
| `paths_blocked\|PATHS_BLOCKED` in src/transport/*.{c,h} | 55 |
| `XQC_FRAME_BIT_PATHS_BLOCKED\|XQC_FRAME_PATHS_BLOCKED` in src/+tests/ | 6 |
| `_Static_assert.*PATHS_BLOCKED` | 2 (frame.h:142, frame_parser.c:3131) |
| Receive-side intact: `xqc_process_paths_blocked_frame` + `xqc_parse_paths_blocked_frame` | present at frame.c:2409 / frame_parser.c:3166 (untouched) |

gen / parse / send / recv symmetry intact; no decl/use drift.

## G-N6 verdict: **CLEAN**

Spec §2.3 SHOULD: post-handshake, unacknowledged 0-RTT packets MUST be
acknowledged with PATH_ACK on path_id 0.

Path traversed by received-but-unacked 0-RTT:

1. 0-RTT decrypts into `XQC_PNS_APP_DATA` (no separate 0-RTT recv record);
   initial path is path_id 0 (`xqc_conn.c:874`, `xqc_multipath.c:362`).
2. `xqc_recv_record.c:289` sets the path-0 APP_DATA bit in `conn->ack_flag`.
3. Engine loop (`xqc_engine.c:770`) calls
   `xqc_write_ack_or_mp_ack_or_ext_ack_to_packets`.
4. Writer iterates `conn_paths_list`, gates on path_state ∈
   [VALIDATING, CLOSED) and per-path SHOULD_ACK bit
   (`xqc_packet_out.c:566-575`), and for APP_DATA with `enable_multipath ==
   XQC_CONN_MP_ENABLED` forces `is_mp_ack=1` → PATH_ACK
   (`xqc_packet_out.c:600`). Path 0 is in `conn_paths_list` from initial
   creation, so its APP_DATA recv_record (containing 0-RTT pkt numbers
   received pre-handshake) drains as PATH_ACK on path_id 0 once multipath
   enables at handshake confirm.

No PR8 code change needed for G-N6.

## Non-trivial findings

| ID | spec § | file:line | finding | verdict |
|---|---|---|---|---|
| G-P16 trigger granularity | §3.2.1 ¶7 | `src/transport/xqc_multipath.c:` (PATHS_BLOCKED trigger site) | Spec says "SHOULD send PATHS_BLOCKED when peer's `max_paths` limits new path creation". We trigger on `xqc_conn_create_path` failure when the cause is local-side `local_max_path_id` exhaustion vs. transport TP `initial_max_path_id`. Distinguishing the two failure modes is necessary so we don't spam PATHS_BLOCKED when the cap is our own. Resolved by checking `path_id > peer_max_path_id` at the trigger site. | recorded |
| G-P16 rate-limit choice (1 PTO) | §4.7 ¶14 | `src/transport/xqc_conn.h` (new `paths_blocked_last_sent_us`) | Spec gives no upper-bound cadence for PATHS_BLOCKED retransmit; §4.7 ¶14 says retransmit is MAY when still blocked. We chose 1×PTO (using `xqc_send_ctl_calc_pto(conn_initial_path)`) as the floor — matches the same throttle xquic uses for MAX_PATH_ID and PATH_CHALLENGE retry. Single PTO is conservative; if logs show flapping, may extend to N×PTO in PR9. | recorded |
| G-N6 re-audit correction of PR7 claim | §2.3 SHOULD | `src/transport/xqc_engine.c:770` | PR7 audit memo cited engine.c:770 as proof G-N6 was VERIFY-CLEAN, but that's only the call site. Forensic trace (above) now provides the full path including recv_record insert, ack_flag bit positioning, multipath gate, and frame-type selection. Verdict unchanged (CLEAN) but rationale is now actually documented. | corrected |

## Deferred to PR9+

- Engine-equipped CUnit fixture (needed to drive `xqc_connection_t`
  through `tick()` for any real wire-level test).
- CUnit wire tests for writer + trigger (rate-limit count, on-wire
  3-byte layout on PTO replay).
- G-P14 / G-P10 / G-P15 mqvpn netns e2e — false claim in
  `project_pr8_test_debt.md` corrected 2026-05-19: PR7 did **not** ship
  these (helper-level CUnit only).
- picoquic interop (peer-side draft-21 MP frame validation).

## Plan vs impl drift

None observed. Plan promised: gen + writer + trigger + PTO rate-limit +
frame enum + dual `_Static_assert`. Grep audit (above) confirms all six
shipped, receive-side untouched, no `include/xquic/xqc_configure.h`
modification in the 4-commit diff.
