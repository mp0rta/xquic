/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_SET_CONN_SETTINGS_TEST_H
#define _XQC_SET_CONN_SETTINGS_TEST_H

/* PR8 G-N6 test gap #c. Pins xqc_server_set_conn_settings field
 * propagation for the subset of xqc_conn_settings_t fields that
 * mqvpn (the primary downstream consumer) actually sets.
 *
 * Adding a new field that mqvpn consumes? Three places must update
 * together, or this test will go red:
 *   (1) xqc_conn_settings_t in include/xquic/xquic.h
 *   (2) corresponding copy line in xqc_server_set_conn_settings
 *       (src/transport/xqc_conn.c)
 *   (3) a new row / assertion in this test file
 */
void xqc_test_server_set_conn_settings_propagation(void);
void xqc_test_server_set_conn_settings_zero_defaults(void);
void xqc_test_server_set_conn_settings_clamp(void);

#endif /* _XQC_SET_CONN_SETTINGS_TEST_H */
