/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 * @copyright Copyright (c) 2026, mp0rta
 */

#ifndef _XQC_DOS_E2E_TEST_H_INCLUDED_
#define _XQC_DOS_E2E_TEST_H_INCLUDED_

/* #811 DoS mitigations driven through the real receive/dispatch path. */
void xqc_test_dos_crypto_frame_flood_recv_path(void);

#endif /* _XQC_DOS_E2E_TEST_H_INCLUDED_ */
