/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * Tests for xqc_conn_reapply_settings().
 */
#include <CUnit/CUnit.h>
#include <stdlib.h>
#include <string.h>
#include "xquic/xquic.h"
#include "xquic/xquic_typedef.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_memory_pool.h"
#include "xqc_test_helpers.h"
#include "xqc_conn_reapply_test.h"

#define REAPPLY_MAX_PATHS 2

typedef struct {
    xqc_connection_t *conn;
    xqc_path_ctx_t   *paths[REAPPLY_MAX_PATHS];
    int               n_paths;
} reapply_fixture_t;

static void
reapply_params_defaults(xqc_conn_settings_t *s)
{
    s->scheduler_params.bw_Bps_thr = 375000;
    s->scheduler_params.loss_percent_thr_high = 30;
    s->scheduler_params.loss_percent_thr_low = 10;
    s->scheduler_params.pto_cnt_thr = 2;
    s->scheduler_params.rtt_us_thr_high = 2000000;
    s->scheduler_params.rtt_us_thr_low = 500000;
}

static void
reapply_setup(reapply_fixture_t *f)
{
    memset(f, 0, sizeof(*f));
    f->conn = xqc_test_helper_conn_create(NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f->conn);
    xqc_connection_t *c = f->conn;

#ifdef XQC_PROTECT_POOL_MEM
    c->conn_pool = xqc_create_pool(4096, XQC_FALSE);
#else
    c->conn_pool = xqc_create_pool(4096);
#endif
    CU_ASSERT_PTR_NOT_NULL_FATAL(c->conn_pool);
    c->conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
    c->scheduler_callback = &c->conn_settings.scheduler_callback;
    c->scheduler = xqc_pcalloc(c->conn_pool, 0);
    reapply_params_defaults(&c->conn_settings);

    f->paths[f->n_paths++] =
        xqc_test_helper_path_synthesize(c, 0, XQC_PATH_STATE_ACTIVE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f->paths[0]);
}

static void
reapply_teardown(reapply_fixture_t *f)
{
    for (int i = 0; i < f->n_paths; i++) {
        xqc_test_helper_path_destroy(f->paths[i]);
    }
    xqc_destroy_pool(f->conn->conn_pool);
    f->conn->conn_pool = NULL;
    xqc_test_helper_conn_destroy(f->conn);
}

static xqc_conn_settings_t
reapply_settings(const xqc_scheduler_callback_t *cb)
{
    xqc_conn_settings_t s;
    memset(&s, 0, sizeof(s));
    s.scheduler_callback = *cb;
    return s;
}

void
xqc_test_reapply_minrtt_to_wlb(void)
{
    reapply_fixture_t f;
    reapply_setup(&f);
    xqc_connection_t *c = f.conn;
    void *old = c->scheduler;

    xqc_conn_settings_t s = reapply_settings(&xqc_wlb_scheduler_cb);
    CU_ASSERT_EQUAL(xqc_conn_reapply_settings(c, &s, XQC_CONN_REAPPLY_SCHEDULER), XQC_OK);
    CU_ASSERT(c->scheduler_callback->xqc_scheduler_get_path
              == xqc_wlb_scheduler_cb.xqc_scheduler_get_path);
    CU_ASSERT(c->scheduler_callback == &c->conn_settings.scheduler_callback);
    CU_ASSERT_PTR_NOT_NULL(c->scheduler);
    CU_ASSERT(c->scheduler != old);

    reapply_teardown(&f);
}

void
xqc_test_reapply_same_vtable_keeps_state(void)
{
    reapply_fixture_t f;
    reapply_setup(&f);
    xqc_connection_t *c = f.conn;

    xqc_conn_settings_t s = reapply_settings(&xqc_wlb_scheduler_cb);
    CU_ASSERT_EQUAL(xqc_conn_reapply_settings(c, &s, XQC_CONN_REAPPLY_SCHEDULER), XQC_OK);
    void *state = c->scheduler;
    CU_ASSERT_EQUAL(xqc_conn_reapply_settings(c, &s, XQC_CONN_REAPPLY_SCHEDULER), XQC_OK);
    CU_ASSERT(c->scheduler == state);

    reapply_teardown(&f);
}

/* Reapply must return -XQC_ESTATE and leave the connection untouched. */
static void
reapply_expect_estate(reapply_fixture_t *f)
{
    xqc_connection_t *c = f->conn;
    xqc_scheduler_callback_t cb = c->conn_settings.scheduler_callback;
    xqc_scheduler_params_t params = c->conn_settings.scheduler_params;
    void *state = c->scheduler;
    const xqc_scheduler_callback_t *active = c->scheduler_callback;

    xqc_conn_settings_t s = reapply_settings(&xqc_wlb_scheduler_cb);
    s.scheduler_params.pto_cnt_thr = 5;
    CU_ASSERT_EQUAL(xqc_conn_reapply_settings(c, &s, XQC_CONN_REAPPLY_SCHEDULER),
                    -XQC_ESTATE);
    CU_ASSERT_EQUAL(memcmp(&cb, &c->conn_settings.scheduler_callback, sizeof(cb)), 0);
    CU_ASSERT_EQUAL(memcmp(&params, &c->conn_settings.scheduler_params, sizeof(params)), 0);
    CU_ASSERT(c->scheduler == state);
    CU_ASSERT(c->scheduler_callback == active);
}

void
xqc_test_reapply_refuses_two_paths(void)
{
    reapply_fixture_t f;
    reapply_setup(&f);
    f.paths[f.n_paths++] = xqc_test_helper_path_synthesize(f.conn, 1, XQC_PATH_STATE_ACTIVE);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f.paths[1]);
    reapply_expect_estate(&f);
    reapply_teardown(&f);
}

/* create_path_count guard alone: second path exists but is not ACTIVE. */
void
xqc_test_reapply_refuses_created_path_count(void)
{
    reapply_fixture_t f;
    reapply_setup(&f);
    f.paths[f.n_paths++] =
        xqc_test_helper_path_synthesize(f.conn, 1, XQC_PATH_STATE_VALIDATING);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f.paths[1]);
    CU_ASSERT_EQUAL(f.conn->create_path_count, 2);
    CU_ASSERT_EQUAL(f.conn->active_path_count, 1);
    reapply_expect_estate(&f);
    reapply_teardown(&f);
}

/* active_path_count guard alone: counters set by hand. */
void
xqc_test_reapply_refuses_active_path_count(void)
{
    reapply_fixture_t f;
    reapply_setup(&f);
    f.conn->active_path_count = 2;
    CU_ASSERT_EQUAL(f.conn->create_path_count, 1);
    reapply_expect_estate(&f);
    f.conn->active_path_count = 1;
    reapply_teardown(&f);
}

void
xqc_test_reapply_refuses_datagram_redundancy(void)
{
    reapply_fixture_t f;
    reapply_setup(&f);
    f.conn->conn_settings.datagram_redundancy = 1;
    reapply_expect_estate(&f);
    reapply_teardown(&f);
}

/* conn created without a scheduler setting: active vtable is the global minrtt
 * cb while conn_settings.scheduler_callback is zero. */
void
xqc_test_reapply_same_as_active_global_vtable(void)
{
    reapply_fixture_t f;
    reapply_setup(&f);
    xqc_connection_t *c = f.conn;
    memset(&c->conn_settings.scheduler_callback, 0,
           sizeof(c->conn_settings.scheduler_callback));
    c->scheduler_callback = &xqc_minrtt_scheduler_cb;
    void *state = c->scheduler;

    xqc_conn_settings_t s = reapply_settings(&xqc_minrtt_scheduler_cb);
    CU_ASSERT_EQUAL(xqc_conn_reapply_settings(c, &s, XQC_CONN_REAPPLY_SCHEDULER), XQC_OK);
    CU_ASSERT(c->scheduler == state);
    CU_ASSERT(c->scheduler_callback == &c->conn_settings.scheduler_callback);
    CU_ASSERT(c->scheduler_callback->xqc_scheduler_get_path
              == xqc_minrtt_scheduler_cb.xqc_scheduler_get_path);

    reapply_teardown(&f);
}

void
xqc_test_reapply_same_vtable_params_land(void)
{
    reapply_fixture_t f;
    reapply_setup(&f);
    xqc_connection_t *c = f.conn;

    xqc_conn_settings_t s = reapply_settings(&xqc_wlb_scheduler_cb);
    CU_ASSERT_EQUAL(xqc_conn_reapply_settings(c, &s, XQC_CONN_REAPPLY_SCHEDULER), XQC_OK);
    void *state = c->scheduler;
    s.scheduler_params.pto_cnt_thr = 5;
    CU_ASSERT_EQUAL(xqc_conn_reapply_settings(c, &s, XQC_CONN_REAPPLY_SCHEDULER), XQC_OK);
    CU_ASSERT(c->scheduler == state);
    CU_ASSERT_EQUAL(c->conn_settings.scheduler_params.pto_cnt_thr, 5);
    CU_ASSERT_EQUAL(c->conn_settings.scheduler_params.bw_Bps_thr, 375000);

    reapply_teardown(&f);
}

static void
reapply_expect_param(reapply_fixture_t *f, xqc_conn_settings_t *s, uint32_t fields,
                     xqc_connection_t *conn)
{
    xqc_scheduler_callback_t cb = f->conn->conn_settings.scheduler_callback;
    xqc_scheduler_params_t params = f->conn->conn_settings.scheduler_params;
    void *state = f->conn->scheduler;

    CU_ASSERT_EQUAL(xqc_conn_reapply_settings(conn, s, fields), -XQC_EPARAM);
    CU_ASSERT_EQUAL(memcmp(&cb, &f->conn->conn_settings.scheduler_callback, sizeof(cb)), 0);
    CU_ASSERT_EQUAL(memcmp(&params, &f->conn->conn_settings.scheduler_params, sizeof(params)), 0);
    CU_ASSERT(f->conn->scheduler == state);
}

void
xqc_test_reapply_rejects_bad_args(void)
{
    reapply_fixture_t f;
    reapply_setup(&f);
    xqc_conn_settings_t s = reapply_settings(&xqc_wlb_scheduler_cb);

    reapply_expect_param(&f, &s, XQC_CONN_REAPPLY_SCHEDULER, NULL);
    reapply_expect_param(&f, NULL, XQC_CONN_REAPPLY_SCHEDULER, f.conn);
    reapply_expect_param(&f, &s, 0, f.conn);
    reapply_expect_param(&f, &s, 1u << 1, f.conn);

    xqc_conn_settings_t bad = s;
    bad.scheduler_callback.xqc_scheduler_size = NULL;
    reapply_expect_param(&f, &bad, XQC_CONN_REAPPLY_SCHEDULER, f.conn);
    bad = s;
    bad.scheduler_callback.xqc_scheduler_init = NULL;
    reapply_expect_param(&f, &bad, XQC_CONN_REAPPLY_SCHEDULER, f.conn);
    bad = s;
    bad.scheduler_callback.xqc_scheduler_get_path = NULL;
    reapply_expect_param(&f, &bad, XQC_CONN_REAPPLY_SCHEDULER, f.conn);

    reapply_teardown(&f);
}

void
xqc_test_reapply_params_zero_keeps_current(void)
{
    reapply_fixture_t f;
    reapply_setup(&f);
    xqc_scheduler_params_t before = f.conn->conn_settings.scheduler_params;

    xqc_conn_settings_t s = reapply_settings(&xqc_wlb_scheduler_cb);
    CU_ASSERT_EQUAL(xqc_conn_reapply_settings(f.conn, &s, XQC_CONN_REAPPLY_SCHEDULER),
                    XQC_OK);
    CU_ASSERT_EQUAL(memcmp(&before, &f.conn->conn_settings.scheduler_params,
                           sizeof(before)), 0);
    CU_ASSERT_EQUAL(f.conn->conn_settings.scheduler_params.bw_Bps_thr, 375000);
    CU_ASSERT_EQUAL(f.conn->conn_settings.scheduler_params.pto_cnt_thr, 2);

    reapply_teardown(&f);
}

void
xqc_test_reapply_params_override(void)
{
    reapply_fixture_t f;
    reapply_setup(&f);

    xqc_conn_settings_t s = reapply_settings(&xqc_wlb_scheduler_cb);
    s.scheduler_params.pto_cnt_thr = 5;
    CU_ASSERT_EQUAL(xqc_conn_reapply_settings(f.conn, &s, XQC_CONN_REAPPLY_SCHEDULER),
                    XQC_OK);
    xqc_scheduler_params_t *p = &f.conn->conn_settings.scheduler_params;
    CU_ASSERT_EQUAL(p->pto_cnt_thr, 5);
    CU_ASSERT_EQUAL(p->bw_Bps_thr, 375000);
    CU_ASSERT_EQUAL(p->loss_percent_thr_high, 30);
    CU_ASSERT_EQUAL(p->loss_percent_thr_low, 10);
    CU_ASSERT_EQUAL(p->rtt_us_thr_high, 2000000);
    CU_ASSERT_EQUAL(p->rtt_us_thr_low, 500000);

    reapply_teardown(&f);
}
