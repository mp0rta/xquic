/**
 * @copyright Copyright (c) 2026, mp0rta
 */

#ifndef XQC_ALLOC_FAIL_TEST_H
#define XQC_ALLOC_FAIL_TEST_H

void xqc_test_client_connect_active_queue_full(void);
void xqc_test_conn_create_alloc_failures(void);
void xqc_test_conn_destroy_frees_crypto_data(void);

void xqc_test_qpack_create_alloc_failures(void);

/* the allocation-failure switch, for tests in other files (Linux only, with
 * XQC_TEST_ALLOC_WRAP; elsewhere these do nothing) */
void xqc_test_af_arm(long fail_at);
int  xqc_test_af_disarm(void);
void xqc_test_af_live_begin(void);
long xqc_test_af_live_end(void);

#endif
