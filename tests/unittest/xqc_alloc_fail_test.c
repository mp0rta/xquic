/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * An allocation that fails while a connection is being created must fail
 * the creation, not crash the process. On Linux the test binary is linked
 * with --wrap for malloc, calloc and realloc (tests/CMakeLists.txt): the
 * wrappers below make the Nth allocation after arming return NULL, and the
 * tests sweep N over every allocation that xqc_connect() makes on a client
 * engine and that the first Initial packet makes on a server engine.
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include <arpa/inet.h>
#include "xquic/xquic.h"
#include "src/common/xqc_time.h"
#include "src/common/xqc_priority_q.h"
#include "src/transport/xqc_engine.h"
#include "xqc_alloc_fail_test.h"

#ifdef XQC_TEST_ALLOC_WRAP

static long g_alloc_count = -1;     /* -1: disarmed */
static long g_alloc_fail_at;
static int  g_alloc_failed;

void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void *__real_realloc(void *ptr, size_t size);

static int
xqc_test_alloc_should_fail(void)
{
    if (g_alloc_count < 0) {
        return 0;
    }
    if (++g_alloc_count == g_alloc_fail_at) {
        g_alloc_failed = 1;
        return 1;
    }
    return 0;
}

void *
__wrap_malloc(size_t size)
{
    return xqc_test_alloc_should_fail() ? NULL : __real_malloc(size);
}

void *
__wrap_calloc(size_t nmemb, size_t size)
{
    return xqc_test_alloc_should_fail() ? NULL : __real_calloc(nmemb, size);
}

void *
__wrap_realloc(void *ptr, size_t size)
{
    return xqc_test_alloc_should_fail() ? NULL : __real_realloc(ptr, size);
}

static unsigned char g_initial[2048];
static size_t        g_initial_len;

static ssize_t
xqc_test_af_write(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    if (g_initial_len == 0 && size <= sizeof(g_initial)) {
        memcpy(g_initial, buf, size);
        g_initial_len = size;
    }
    return size;
}

static void
xqc_test_af_set_timer(xqc_msec_t wake_after, void *engine_user_data)
{
}

static void
xqc_test_af_log(xqc_log_level_t lvl, const void *buf, size_t count, void *user_data)
{
}

static int
xqc_test_af_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data)
{
    return 0;
}

static xqc_config_t *g_af_config;   /* NULL: the default engine config */

static xqc_engine_t *
xqc_test_af_engine(xqc_engine_type_t type)
{
    xqc_engine_ssl_config_t ssl;
    memset(&ssl, 0, sizeof(ssl));
    ssl.private_key_file = "./server.key";
    ssl.cert_file = "./server.crt";
    ssl.ciphers = XQC_TLS_CIPHERS;
    ssl.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t cb = {
        .log_callbacks = {.xqc_log_write_err = xqc_test_af_log},
        .set_event_timer = xqc_test_af_set_timer,
    };
    xqc_transport_callbacks_t tcbs = {
        .write_socket = xqc_test_af_write,
        .server_accept = xqc_test_af_accept,
    };

    xqc_engine_t *engine = xqc_engine_create(type, g_af_config, &ssl, &cb,
                                             &tcbs, NULL);
    if (engine != NULL) {
        xqc_app_proto_callbacks_t ap = {{NULL}, {NULL}};
        xqc_engine_register_alpn(engine, "transport", 9, &ap, NULL);
    }
    return engine;
}

static const xqc_cid_t *
xqc_test_af_connect(xqc_engine_t *engine)
{
    xqc_conn_settings_t cs;
    memset(&cs, 0, sizeof(cs));
    cs.proto_version = XQC_VERSION_V1;
    xqc_conn_ssl_config_t ssl;
    memset(&ssl, 0, sizeof(ssl));
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return xqc_connect(engine, &cs, NULL, 0, "", 0, &ssl, (struct sockaddr *)&peer,
                       sizeof(peer), "transport", NULL);
}

static int       g_af_created, g_af_closed;
static xqc_cid_t g_af_created_cid;

static int
xqc_test_af_count_create(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *conn_user_data, void *conn_proto_data)
{
    g_af_created++;
    g_af_created_cid = *cid;
    return 0;
}

static int
xqc_test_af_count_close(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *conn_user_data, void *conn_proto_data)
{
    g_af_closed++;
    return 0;
}

static void *
xqc_test_af_no_growth(void *opaque, size_t size)
{
    return NULL;
}

/*
 * An xqc_connect() that fails after conn_create_notify must not leave its
 * connection behind: the connection must be gone from the engine, and
 * conn_close_notify must have run. Called from one of the engine's callbacks
 * (the engine is running), xqc_connect() leaves its connection in the active
 * queue: with a capacity of one, the second connection finds the queue full,
 * and here the queue cannot grow.
 */
void
xqc_test_client_connect_active_queue_full(void)
{
    xqc_config_t config;
    CU_ASSERT_FATAL(xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT)
                    == XQC_OK);
    config.conns_active_pq_capacity = 1;

    xqc_app_proto_callbacks_t ap = {{NULL}, {NULL}};
    ap.conn_cbs.conn_create_notify = xqc_test_af_count_create;
    ap.conn_cbs.conn_close_notify = xqc_test_af_count_close;

    for (int grows = 1; grows >= 0; grows--) {
        g_af_config = &config;
        xqc_engine_t *engine = xqc_test_af_engine(XQC_ENGINE_CLIENT);
        g_af_config = NULL;
        CU_ASSERT_FATAL(engine != NULL);
        xqc_engine_register_alpn(engine, "transport", 9, &ap, NULL);

        engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
        CU_ASSERT_FATAL(xqc_test_af_connect(engine) != NULL);

        xqc_malloc_wrap_t pq_malloc = engine->conns_active_pq->a.malloc;
        if (!grows) {
            engine->conns_active_pq->a.malloc = xqc_test_af_no_growth;
        }
        g_af_created = 0;
        g_af_closed = 0;
        const xqc_cid_t *cid = xqc_test_af_connect(engine);
        engine->conns_active_pq->a.malloc = pq_malloc;

        CU_ASSERT(g_af_created == 1);
        if (grows) {
            CU_ASSERT(cid != NULL);
            CU_ASSERT(g_af_closed == 0);

        } else {
            CU_ASSERT(cid == NULL);
            CU_ASSERT(g_af_closed == 1);
            CU_ASSERT(xqc_engine_get_conn_by_scid(engine, &g_af_created_cid)
                      == NULL);
        }

        engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
        xqc_engine_destroy(engine);
    }
}

void
xqc_test_conn_create_alloc_failures(void)
{
    /* client: every allocation of xqc_connect() in turn */
    long n;
    for (n = 1; n < 100000; n++) {
        xqc_engine_t *engine = xqc_test_af_engine(XQC_ENGINE_CLIENT);
        CU_ASSERT_FATAL(engine != NULL);
        g_alloc_failed = 0;
        g_alloc_fail_at = n;
        g_alloc_count = 0;
        const xqc_cid_t *cid = xqc_test_af_connect(engine);
        g_alloc_count = -1;
        if (!g_alloc_failed) {
            CU_ASSERT(cid != NULL);
        }
        xqc_engine_destroy(engine);
        if (!g_alloc_failed) {
            break;
        }
    }
    CU_ASSERT(n > 1);

    /* server: every allocation made for a client's first Initial packet */
    xqc_engine_t *client = xqc_test_af_engine(XQC_ENGINE_CLIENT);
    CU_ASSERT_FATAL(client != NULL);
    g_initial_len = 0;
    CU_ASSERT_FATAL(xqc_test_af_connect(client) != NULL);
    xqc_engine_main_logic(client);
    CU_ASSERT_FATAL(g_initial_len > 0);

    struct sockaddr_in local, peer;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(4433);
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    peer = local;
    peer.sin_port = htons(5555);

    for (n = 1; n < 100000; n++) {
        xqc_engine_t *server = xqc_test_af_engine(XQC_ENGINE_SERVER);
        CU_ASSERT_FATAL(server != NULL);
        g_alloc_failed = 0;
        g_alloc_fail_at = n;
        g_alloc_count = 0;
        xqc_engine_packet_process(server, g_initial, g_initial_len,
                                  (struct sockaddr *)&local, sizeof(local),
                                  (struct sockaddr *)&peer, sizeof(peer),
                                  xqc_monotonic_timestamp(), NULL);
        xqc_engine_main_logic(server);
        g_alloc_count = -1;
        xqc_engine_destroy(server);
        if (!g_alloc_failed) {
            break;
        }
    }
    CU_ASSERT(n > 1);

    xqc_engine_destroy(client);
}

#else

void
xqc_test_client_connect_active_queue_full(void)
{
    /* shares the helpers above, built where --wrap is (Linux) */
}

void
xqc_test_conn_create_alloc_failures(void)
{
    /* needs the linker's --wrap (see tests/CMakeLists.txt) */
}

#endif
