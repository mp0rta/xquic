/**
 * @copyright Copyright (c) 2026, mp0rta
 */

#ifndef _XQC_SET_CONN_SETTINGS_TEST_H
#define _XQC_SET_CONN_SETTINGS_TEST_H

/* PR8 G-N6 test gap #c. Pins xqc_server_set_conn_settings field
 * propagation for the 18 xqc_conn_settings_t fields that mqvpn (the
 * primary downstream consumer) actually sets today.
 *
 * What this test catches: deleting / breaking a copy line for one of
 * the 18 fields in src/transport/xqc_conn.c — the matching field's
 * sentinel won't land in engine->default_conn_settings, an assertion
 * trips.
 *
 * What it does NOT catch: adding a new field to xqc_conn_settings_t
 * and forgetting to either propagate it in the SUT or extend this
 * test. Value-probe coverage is bounded by the probes it writes.
 * Reviewers of any future field-adding PR remain the gate for
 * extending both sides in lock-step.
 */
void xqc_test_server_set_conn_settings_propagation(void);
void xqc_test_server_set_conn_settings_zero_defaults(void);
void xqc_test_server_set_conn_settings_clamp(void);

/* Behaviour of the shared deferral helper itself (xqc_conn_flush_or_defer),
 * as opposed to the settings that select it: that the deferred branch latches
 * and arms exactly one wakeup per run, that it is idempotent within a run,
 * and — the branch the helper's own comment calls load-bearing — that a conn
 * without XQC_CONN_FLAG_TICKING does NOT defer.
 *
 * Bounded on purpose: the connection is a stub and the engine is marked
 * RUNNING, so the immediate branch's xqc_engine_conn_logic() returns at its
 * top and leaves nothing to assert on. This pins the deferred bookkeeping
 * (latch / wakeup / idempotence / the TICKING precondition), not that the
 * non-deferred branch transmits. The e2e's UdpGso=false arm covers that. */
void xqc_test_conn_flush_or_defer(void);

#endif /* _XQC_SET_CONN_SETTINGS_TEST_H */
