/**
 * @copyright Copyright (c) 2026, mp0rta
 */

#ifndef _XQC_SET_CONN_SETTINGS_TEST_H
#define _XQC_SET_CONN_SETTINGS_TEST_H

/* PR8 G-N6 test gap #c. Pins xqc_server_set_conn_settings field
 * propagation for the 16 xqc_conn_settings_t fields that mqvpn (the
 * primary downstream consumer) actually sets today.
 *
 * What this test catches: deleting / breaking a copy line for one of
 * the 16 fields in src/transport/xqc_conn.c — the matching field's
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

#endif /* _XQC_SET_CONN_SETTINGS_TEST_H */
