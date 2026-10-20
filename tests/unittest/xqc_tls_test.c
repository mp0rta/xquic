/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/tls/xqc_tls_ctx.h"
#include "src/tls/xqc_tls.h"
#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define XQC_TEST_MAX_CRYPTO_DATA_BUF 16 * 1024

#define XQC_TEST_SESSION_TICKET_KEY "\xa8\x6d\x19\x70\x06\x08\x9b\x2d" \
"\xa7\x17\x50\xf7\x97\x78\xf7\xe8\x3c\x5a\xc4\x9d\x61\x34\xe3\xa1\xfa" \
"\x62\x7b\x66\xf0\x2f\x5b\xdc\x63\x12\x8d\x10\x9a\x57\x5c\xdd\x1b\xc3" \
"\x8f\x13\x93\x3c\x85"

typedef struct xqc_tls_test_buff_s {
    union {
        struct {
            xqc_list_head_t    initial_crypto_data_list;
            xqc_list_head_t    hsk_crypto_data_list;
            xqc_list_head_t    application_crypto_data_list;
        
            xqc_bool_t         handshake_completed;
        
            unsigned char     *new_session_ticket;
            size_t             new_session_ticket_len;
        
            /* for test corner case: multiple crypto data */
            int                crypto_data_cnt;
            size_t             crypto_data_total_len;
        
            uint64_t           error_code;
        };
        xqc_connection_t conn;
    };
} xqc_tls_test_buff_t;

static inline xqc_tls_test_buff_t*
xqc_create_tls_test_buffer()
{
    xqc_tls_test_buff_t *ttbuf = xqc_malloc(sizeof(xqc_tls_test_buff_t));
    xqc_init_list_head(&ttbuf->initial_crypto_data_list);
    xqc_init_list_head(&ttbuf->hsk_crypto_data_list);
    xqc_init_list_head(&ttbuf->application_crypto_data_list);

    ttbuf->handshake_completed = XQC_FALSE;

    ttbuf->new_session_ticket = NULL;
    ttbuf->new_session_ticket_len = 0;

    ttbuf->crypto_data_cnt = 0;
    ttbuf->crypto_data_total_len = 0;

    ttbuf->error_code = 0;

    return ttbuf;
}

static inline void
xqc_free_crypto_data_list(xqc_list_head_t *buffer_list)
{
    xqc_list_head_t *head = buffer_list;
    xqc_list_head_t *pos, *next;
    xqc_hs_buffer_t *hs_buf = NULL;

    xqc_list_for_each_safe(pos, next, head) {
        hs_buf = xqc_list_entry(pos, xqc_hs_buffer_t, list_head);
        xqc_list_del(pos);
        xqc_free(hs_buf);
    }
}

static inline void
xqc_destroy_tls_test_buffer(xqc_tls_test_buff_t *ttbuf)
{
    xqc_free_crypto_data_list(&ttbuf->initial_crypto_data_list);
    xqc_free_crypto_data_list(&ttbuf->hsk_crypto_data_list);
    xqc_free_crypto_data_list(&ttbuf->application_crypto_data_list);

    if (ttbuf->new_session_ticket != NULL) {
        xqc_free(ttbuf->new_session_ticket);
    }
    ttbuf->new_session_ticket_len = 0;

    xqc_free(ttbuf);
    ttbuf = NULL;
}

static inline size_t
xqc_crypto_data_list_get_buf(xqc_list_head_t *head, uint8_t *data)
{
    xqc_hs_buffer_t *hs_buf = NULL;
    xqc_list_head_t *pos, *next;
    size_t len = 0;

    xqc_list_for_each_safe(pos, next, head) {
        hs_buf = xqc_list_entry(pos, xqc_hs_buffer_t, list_head);

        if (len + hs_buf->data_len > XQC_TEST_MAX_CRYPTO_DATA_BUF) {
            return -XQC_TLS_NOBUF;
        }

        memcpy(data + len, hs_buf->data, hs_buf->data_len);
        len += hs_buf->data_len;
    }

    return len;
}

static inline xqc_hs_buffer_t *
xqc_create_hs_buffer(int buf_size)
{
    xqc_hs_buffer_t *buf = xqc_malloc(sizeof(xqc_hs_buffer_t) + buf_size);
    if (buf == NULL) {
        return NULL;
    }

    xqc_init_list_head(&buf->list_head);
    buf->data_len = buf_size;
    return buf;
}

xqc_int_t
xqc_tt_crypto_data_cb(xqc_encrypt_level_t level, const uint8_t *data, size_t len, void *user_data)
{
    xqc_tls_test_buff_t *ttbuf = (xqc_tls_test_buff_t *)user_data;
    xqc_list_head_t *crypto_data_list = NULL;

    switch (level) {
    case XQC_ENC_LEV_INIT:
        crypto_data_list = &ttbuf->initial_crypto_data_list;
        break;

    case XQC_ENC_LEV_HSK:
        crypto_data_list = &ttbuf->hsk_crypto_data_list;
        break;

    case XQC_ENC_LEV_1RTT:
        crypto_data_list = &ttbuf->application_crypto_data_list;
        break;

    default:
        return -XQC_EFATAL;
    }

    xqc_hs_buffer_t *hs_buf = xqc_create_hs_buffer(len);
    if (XQC_UNLIKELY(!hs_buf)) {
        return -XQC_EMALLOC;
    }

    memcpy(hs_buf->data, data, len);
    xqc_list_add_tail(&hs_buf->list_head, crypto_data_list);

    ttbuf->crypto_data_cnt++;
    ttbuf->crypto_data_total_len += len;

    return XQC_OK;
}

void
xqc_tt_transport_params_cb(const uint8_t *tp, size_t len, void *user_data)
{
}

xqc_int_t
xqc_tt_alpn_select_cb(const char *alpn, size_t alpn_len, void *user_data)
{
    return XQC_OK;
}

xqc_int_t
xqc_tt_cert_verify_cb(const unsigned char *certs[], const size_t cert_len[],
                      size_t certs_len, void *user_data)
{
    return XQC_OK;
}

void
xqc_tt_session_cb(const char *data, size_t data_len, void *user_data)
{
    xqc_tls_test_buff_t *ttbuf = (xqc_tls_test_buff_t *)user_data;
    if (ttbuf->new_session_ticket == NULL && ttbuf->new_session_ticket_len == 0) {
        ttbuf->new_session_ticket = xqc_malloc(data_len);
        memcpy(ttbuf->new_session_ticket, data, data_len);
        ttbuf->new_session_ticket_len = data_len;
    }
}

void
xqc_tt_keylog_cb(const char *line, void *user_data)
{
}

void
xqc_tt_tls_error_cb(xqc_int_t tls_err, void *user_data)
{
    xqc_tls_test_buff_t *ttbuf = (xqc_tls_test_buff_t *)user_data;

    ttbuf->error_code = tls_err;
}

void
xqc_tt_handshake_completed_cb(void *user_data)
{
    xqc_tls_test_buff_t *ttbuf = (xqc_tls_test_buff_t *)user_data;
    ttbuf->handshake_completed = XQC_TRUE;
}

xqc_tls_callbacks_t tls_test_cbs = {
    .crypto_data_cb = xqc_tt_crypto_data_cb,
    .tp_cb = xqc_tt_transport_params_cb,
    .alpn_select_cb = xqc_tt_alpn_select_cb,
    .cert_verify_cb = xqc_tt_cert_verify_cb,
    .session_cb = xqc_tt_session_cb,
    .keylog_cb = xqc_tt_keylog_cb,
    .error_cb = xqc_tt_tls_error_cb,
    .hsk_completed_cb = xqc_tt_handshake_completed_cb,
};

#define def_engine_ssl_config_svr                            \
    xqc_engine_ssl_config_t engine_ssl_config_svr = {0};     \
    engine_ssl_config_svr.private_key_file = "./server.key"; \
    engine_ssl_config_svr.cert_file = "./server.crt";        \
    engine_ssl_config_svr.ciphers = XQC_TLS_CIPHERS;         \
    engine_ssl_config_svr.groups = XQC_TLS_GROUPS;           \
    engine_ssl_config_svr.session_ticket_key_len = 48;       \
    engine_ssl_config_svr.session_ticket_key_data = XQC_TEST_SESSION_TICKET_KEY;   

#define def_engine_ssl_config_cli                            \
    xqc_engine_ssl_config_t engine_ssl_config_cli = {0};     \
    engine_ssl_config_cli.ciphers = XQC_TLS_CIPHERS;         \
    engine_ssl_config_cli.groups = XQC_TLS_GROUPS;  
    
static xqc_log_t *test_log;
static xqc_tls_ctx_t *ctx_cli, *ctx_svr;

void
xqc_test_create_client_tls_ctx()
{
    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));

    /* not set ciphers and groups */
    xqc_tls_ctx_t *ctx;
    SSL_CTX *ssl_ctx;
    xqc_tls_type_t tls_type;
    xqc_engine_ssl_config_t *cfg = NULL;

    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT, &engine_ssl_config,
            &tls_test_cbs, test_log);
    CU_ASSERT(ctx != NULL);

    ssl_ctx = xqc_tls_ctx_get_ssl_ctx(ctx);
    CU_ASSERT(ssl_ctx != NULL);

    tls_type = xqc_tls_ctx_get_type(ctx);
    CU_ASSERT(tls_type == XQC_TLS_TYPE_CLIENT);

    xqc_tls_ctx_get_cfg(ctx, &cfg);
    CU_ASSERT(0 == strcmp(cfg->ciphers, XQC_TLS_CIPHERS));
    CU_ASSERT(0 == strcmp(cfg->groups, XQC_TLS_GROUPS));

    xqc_tls_ctx_destroy(ctx);

    /* set ciphers and groups */
    def_engine_ssl_config_cli;
    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT, &engine_ssl_config_cli, &tls_test_cbs, test_log);
    CU_ASSERT(ctx != NULL);

    ssl_ctx = xqc_tls_ctx_get_ssl_ctx(ctx);
    CU_ASSERT(ssl_ctx != NULL);

    tls_type = xqc_tls_ctx_get_type(ctx);
    CU_ASSERT(tls_type == XQC_TLS_TYPE_CLIENT);

    cfg = NULL;
    xqc_tls_ctx_get_cfg(ctx, &cfg);
    CU_ASSERT(0 == strcmp(cfg->ciphers, XQC_TLS_CIPHERS));
    CU_ASSERT(0 == strcmp(cfg->groups, XQC_TLS_GROUPS));

    ctx_cli = ctx;
}

void
xqc_test_create_server_tls_ctx()
{
    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));

    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;
    /* no private key file */
    xqc_tls_ctx_t *ctx;
    SSL_CTX *ssl_ctx;
    xqc_tls_type_t tls_type;
    xqc_engine_ssl_config_t *cfg = NULL;
    xqc_ssl_session_ticket_key_t *key = NULL;

    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config,
            &tls_test_cbs, test_log);
    CU_ASSERT(ctx == NULL);

    /* no cert file */
    engine_ssl_config.private_key_file = "./server.key";
    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config, &tls_test_cbs, test_log);
    CU_ASSERT(ctx == NULL);

    /* no session ticket key data */
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.session_ticket_key_data = NULL;
    engine_ssl_config.session_ticket_key_len = 0;
    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config, &tls_test_cbs, test_log);
    CU_ASSERT(ctx != NULL);

    ssl_ctx = xqc_tls_ctx_get_ssl_ctx(ctx);
    CU_ASSERT(ssl_ctx != NULL);

    tls_type = xqc_tls_ctx_get_type(ctx);
    CU_ASSERT(tls_type == XQC_TLS_TYPE_SERVER);

    
    xqc_tls_ctx_get_cfg(ctx, &cfg);
    CU_ASSERT(0 == strcmp(cfg->ciphers, XQC_TLS_CIPHERS));
    CU_ASSERT(0 == strcmp(cfg->groups, XQC_TLS_GROUPS));
    CU_ASSERT(0 == strcmp(cfg->private_key_file, "./server.key"));
    CU_ASSERT(0 == strcmp(cfg->cert_file, "./server.crt"));

    
    xqc_tls_ctx_get_session_ticket_key(ctx, &key);
    CU_ASSERT(key->size == 0);

    xqc_tls_ctx_destroy(ctx);

    /* init session ticket key error */
    engine_ssl_config.session_ticket_key_data = "test_stk";
    engine_ssl_config.session_ticket_key_len = 8;

    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config, &tls_test_cbs, test_log);
    CU_ASSERT(ctx == NULL);

    /* final one */
    def_engine_ssl_config_svr;
    ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_SERVER, &engine_ssl_config_svr,
            &tls_test_cbs, test_log);
    CU_ASSERT(ctx != NULL);
    
    ctx_svr = ctx;
}

#define TEST_ALPN_1 "transport"
#define TEST_ALPN_2 "h3"

void
xqc_test_tls_ctx_register_alpn()
{
    xqc_int_t ret;
    uint8_t *alpn_list = NULL;
    size_t alpn_list_len = 0;

    /* register alpn in tls context */
    ret = xqc_tls_ctx_register_alpn(ctx_cli, TEST_ALPN_1, sizeof(TEST_ALPN_1) - 1);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_tls_ctx_register_alpn(ctx_cli, TEST_ALPN_2, sizeof(TEST_ALPN_2) - 1);
    CU_ASSERT(ret == XQC_OK);

    xqc_tls_ctx_get_alpn_list(ctx_cli, &alpn_list, &alpn_list_len);
    CU_ASSERT(alpn_list_len == sizeof(TEST_ALPN_1) + sizeof(TEST_ALPN_2));

    /* unregister alpn in tls context */
    ret = xqc_tls_ctx_unregister_alpn(ctx_cli, TEST_ALPN_2, sizeof(TEST_ALPN_2) - 1);
    CU_ASSERT(ret == XQC_OK);

    xqc_tls_ctx_get_alpn_list(ctx_cli, &alpn_list, &alpn_list_len);
    CU_ASSERT(alpn_list_len == sizeof(TEST_ALPN_1));

    /* register alpn in tls context */
    ret = xqc_tls_ctx_register_alpn(ctx_svr, TEST_ALPN_1, sizeof(TEST_ALPN_1) - 1);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_tls_ctx_register_alpn(ctx_svr, TEST_ALPN_2, sizeof(TEST_ALPN_2) - 1);
    CU_ASSERT(ret == XQC_OK);

    xqc_tls_ctx_get_alpn_list(ctx_svr, &alpn_list, &alpn_list_len);
    CU_ASSERT(alpn_list_len == sizeof(TEST_ALPN_1) + sizeof(TEST_ALPN_2));

    /* unregister alpn in tls context */
    ret = xqc_tls_ctx_unregister_alpn(ctx_svr, TEST_ALPN_2, sizeof(TEST_ALPN_2) - 1);
    CU_ASSERT(ret == XQC_OK);

    xqc_tls_ctx_get_alpn_list(ctx_svr, &alpn_list, &alpn_list_len);
    CU_ASSERT(alpn_list_len == sizeof(TEST_ALPN_1));
}

void
xqc_test_tls_reset_initial()
{
    /* get tls config */
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "test.xquic.com";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;
    tls_config.trans_params = "10086";
    tls_config.trans_params_len = 5;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid = {1};

    xqc_int_t ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    /* reset initial keys */
    ret = xqc_tls_reset_initial(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    ret = xqc_tls_is_key_ready(tls_cli, XQC_ENC_LEV_INIT, XQC_KEY_TYPE_RX_READ);
    CU_ASSERT(ret == XQC_TRUE);
    ret = xqc_tls_is_key_ready(tls_cli, XQC_ENC_LEV_INIT, XQC_KEY_TYPE_TX_WRITE);
    CU_ASSERT(ret == XQC_TRUE);

    xqc_destroy_tls_test_buffer(ttbuf_cli);
    xqc_tls_destroy(tls_cli);
}        

void
xqc_test_tls_generic()
{
    xqc_int_t ret;
    int cnt;

    uint8_t *data_buf = malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    size_t   data_len = 0;

    /* get tls config */
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "test.xquic.com";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;
    tls_config.trans_params = "10086";
    tls_config.trans_params_len = 5;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid = {1};

    ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_svr = xqc_tls_create(ctx_svr, &tls_config, test_log, ttbuf_svr);

    /* server handshake, process ClientHello, genrate ServerHello & Handshake data */
    ret = xqc_tls_init(tls_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->initial_crypto_data_list)); /* ServerHello */
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->hsk_crypto_data_list));     /* EE, CERT, CV, FIN */

    /* client process handshake data from server */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_HSK, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ttbuf_cli->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->hsk_crypto_data_list)); /* FIN */

    /* server process handshake data from client, send new session ticket */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_HSK, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ttbuf_svr->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->application_crypto_data_list)); /* New Session Ticket */

    /* client save session ticket data */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->application_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_1RTT, data_buf, data_len);
    CU_ASSERT(ttbuf_cli->new_session_ticket != NULL);
    CU_ASSERT(ttbuf_cli->new_session_ticket_len > 0);

    /* 0-RTT */
    tls_config.session_ticket = ttbuf_cli->new_session_ticket;
    tls_config.session_ticket_len = ttbuf_cli->new_session_ticket_len;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_0rtt_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_0rtt_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_0rtt_cli);

    /* client start handshake, generate ClientHello */
    ret = xqc_tls_init(tls_0rtt_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_0rtt_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_0rtt_svr = xqc_tls_create(ctx_svr, &tls_config, test_log, ttbuf_0rtt_svr);

    /* server handshake, process ClientHello, genrate ServerHello & Handshake data */
    ret = xqc_tls_init(tls_0rtt_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_0rtt_svr, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_svr->initial_crypto_data_list)); /* ServerHello */
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_svr->hsk_crypto_data_list));     /* EE, CERT, CV, FIN */

    /* client process handshake data from server */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_svr->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_0rtt_cli, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_svr->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_0rtt_cli, XQC_ENC_LEV_HSK, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ttbuf_0rtt_cli->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_cli->hsk_crypto_data_list)); /* FIN */

    /* server process handshake data from client */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_cli->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_0rtt_svr, XQC_ENC_LEV_HSK, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ttbuf_0rtt_svr->handshake_completed == XQC_TRUE);

    xqc_destroy_tls_test_buffer(ttbuf_cli);
    xqc_destroy_tls_test_buffer(ttbuf_svr);
    xqc_destroy_tls_test_buffer(ttbuf_0rtt_cli);
    xqc_destroy_tls_test_buffer(ttbuf_0rtt_svr);

    xqc_tls_destroy(tls_cli);
    xqc_tls_destroy(tls_svr);
    xqc_tls_destroy(tls_0rtt_cli);
    xqc_tls_destroy(tls_0rtt_svr);

    free(data_buf);
}

void
xqc_test_tls_multiple_crypto_data()
{
    xqc_int_t ret;
    int cnt;

    uint8_t *data_buf = malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    size_t  data_len = 0;

    /* get tls config */
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "test.xquic.com";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;
    tls_config.trans_params = "test";
    tls_config.trans_params_len = 4;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid = {1};

    ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_svr = xqc_tls_create(ctx_svr, &tls_config, test_log, ttbuf_svr);

    /* server handshake, process ClientHello, genrate ServerHello & Handshake data */
    ret = xqc_tls_init(tls_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->initial_crypto_data_list)); /* ServerHello */
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->hsk_crypto_data_list));     /* EE, CERT, CV, FIN */

    int svr_cnt = ttbuf_svr->crypto_data_cnt;
    size_t svr_total_len = ttbuf_svr->crypto_data_total_len;

    /* 
     * mock client sent 2 ClientHello, then server xqc_tls_process_crypto_data will return error,
     * and server crypto_data_list will not increase.
     */

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret != XQC_OK);
    CU_ASSERT(ttbuf_svr->crypto_data_cnt == svr_cnt);
    CU_ASSERT(ttbuf_svr->crypto_data_total_len == svr_total_len);

    xqc_destroy_tls_test_buffer(ttbuf_cli);
    xqc_destroy_tls_test_buffer(ttbuf_svr);
    xqc_tls_destroy(tls_cli);
    xqc_tls_destroy(tls_svr);

    free(data_buf);
}

void
xqc_test_tls_process_truncated_crypto_handshake()
{
    xqc_int_t ret;
    int cnt;

    uint8_t *data_buf = malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    size_t   data_len = 0;

    /* get tls config */
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "test.xquic.com";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;
    tls_config.trans_params = "test";
    tls_config.trans_params_len = 4;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid = {1};

    ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_svr = xqc_tls_create(ctx_svr, &tls_config, test_log, ttbuf_svr);

    /* server handshake */
    ret = xqc_tls_init(tls_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    /* process ClientHello, genrate ServerHello & Handshake data */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_INIT, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->initial_crypto_data_list)); /* ServerHello */
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->hsk_crypto_data_list));     /* EE, CERT, CV, FIN */

    /* client process handshake data from server */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_INIT, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_HSK, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(ttbuf_cli->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->hsk_crypto_data_list)); /* FIN */

    /* server process handshake data from client, send new session ticket */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_HSK, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(ttbuf_svr->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->application_crypto_data_list)); /* New Session Ticket */

    /* client process new session ticket data */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->application_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_1RTT, data_buf, data_len);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_1RTT, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(ttbuf_cli->new_session_ticket != NULL);
    CU_ASSERT(ttbuf_cli->new_session_ticket_len > 0);

    /* 0-RTT and Resumption */
    tls_config.session_ticket = ttbuf_cli->new_session_ticket;
    tls_config.session_ticket_len = ttbuf_cli->new_session_ticket_len;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_0rtt_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_0rtt_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_0rtt_cli);

    /* client start handshake, generate ClientHello */
    ret = xqc_tls_init(tls_0rtt_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server buffer */
    xqc_tls_test_buff_t *ttbuf_0rtt_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_0rtt_svr = xqc_tls_create(ctx_svr, &tls_config, test_log, ttbuf_0rtt_svr);

    /* create server tls */
    ret = xqc_tls_init(tls_0rtt_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    /* server process ClientHello, genrate ServerHello & Handshake data ClientHello */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_0rtt_svr, XQC_ENC_LEV_INIT, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_svr->initial_crypto_data_list)); /* ServerHello */
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_svr->hsk_crypto_data_list));     /* EE, CERT, CV, FIN */

    /* client process handshake data from server */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_svr->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_0rtt_cli, XQC_ENC_LEV_INIT, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_svr->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_0rtt_cli, XQC_ENC_LEV_HSK, data_buf + i, 1);
       CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(ttbuf_0rtt_cli->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_0rtt_cli->hsk_crypto_data_list)); /* FIN */

    /* server process handshake data from client */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_0rtt_cli->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 0; i < data_len; i++) {
        ret = xqc_tls_process_crypto_data(tls_0rtt_svr, XQC_ENC_LEV_HSK, data_buf + i, 1);
        CU_ASSERT(ret == XQC_OK);
    }
    CU_ASSERT(ttbuf_0rtt_svr->handshake_completed == XQC_TRUE);

    xqc_destroy_tls_test_buffer(ttbuf_cli);
    xqc_destroy_tls_test_buffer(ttbuf_svr);
    xqc_destroy_tls_test_buffer(ttbuf_0rtt_cli);
    xqc_destroy_tls_test_buffer(ttbuf_0rtt_svr);

    xqc_tls_destroy(tls_cli);
    xqc_tls_destroy(tls_svr);
    xqc_tls_destroy(tls_0rtt_cli);
    xqc_tls_destroy(tls_0rtt_svr);

    free(data_buf);
}


void
xqc_test_tls_failure()
{
    xqc_int_t ret;
    int cnt;

    uint8_t *data_buf = malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    size_t   data_len = 0;

    /* 1-RTT */
    /* get tls config */
    xqc_tls_config_t tls_config = {0};
    tls_config.session_ticket = NULL;
    tls_config.session_ticket_len = 0;
    tls_config.cert_verify_flag = 0;
    tls_config.hostname = "test.xquic.com";
    tls_config.alpn = "transport";
    tls_config.no_crypto_flag = 0;
    tls_config.trans_params = "test";
    tls_config.trans_params_len = 4;

    /* create client tls */
    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx_cli, &tls_config, test_log, ttbuf_cli);

    /* client start handshake, generate ClientHello */
    xqc_cid_t odcid = {1};

    ret = xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->initial_crypto_data_list)); /* ClientHello */

    /* create server tls */
    xqc_tls_test_buff_t *ttbuf_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_svr = xqc_tls_create(ctx_svr, &tls_config, test_log, ttbuf_svr);

    /* server handshake, process ClientHello, genrate ServerHello & Handshake data */
    ret = xqc_tls_init(tls_svr, XQC_VERSION_V1, &odcid);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->initial_crypto_data_list)); /* ServerHello */
    CU_ASSERT(!xqc_list_empty(&ttbuf_svr->hsk_crypto_data_list));     /* EE, CERT, CV, FIN */

    /* client process handshake data from server */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_INIT, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);

    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_HSK, data_buf, data_len);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(ttbuf_cli->handshake_completed == XQC_TRUE);
    CU_ASSERT(!xqc_list_empty(&ttbuf_cli->hsk_crypto_data_list)); /* FIN */

    /* corrupt crypto data */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    for (size_t i = 20; i < data_len; i++) {
        if (i % 3 == 0) {
            data_buf[i] = ~data_buf[i];
        }
    }

    /* process error crypto data */
    ret = xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_HSK, data_buf, data_len);
    CU_ASSERT(ret != XQC_OK);
    CU_ASSERT(ttbuf_svr->error_code != 0);

    xqc_destroy_tls_test_buffer(ttbuf_cli);
    xqc_destroy_tls_test_buffer(ttbuf_svr);
    xqc_tls_destroy(tls_cli);
    xqc_tls_destroy(tls_svr);

    free(data_buf);
}


/* ---- XQC_TLS_CERT_FLAG_APP_VERIFY: the application owns the chain decision ---- */

static struct {
    int             calls;
    size_t          n_certs;
    unsigned char   leaf[4096];
    size_t          leaf_len;
    xqc_int_t       ret;        /* what cert_verify_cb returns */
    xqc_int_t       first_err;  /* first error_cb value (0 = none yet) */
    int             failed_calls;   /* cert_verify_failed_cb calls */
    int             failed_err;     /* its last x509_err */
} xqc_tt_av;

static xqc_int_t
xqc_tt_av_cert_verify_cb(const unsigned char *certs[], const size_t cert_len[],
    size_t certs_len, void *user_data)
{
    xqc_tt_av.calls++;
    xqc_tt_av.n_certs = certs_len;
    xqc_tt_av.leaf_len = 0;
    if (certs_len > 0 && cert_len[0] <= sizeof(xqc_tt_av.leaf)) {
        memcpy(xqc_tt_av.leaf, certs[0], cert_len[0]);
        xqc_tt_av.leaf_len = cert_len[0];
    }
    return xqc_tt_av.ret;
}

static void
xqc_tt_av_error_cb(xqc_int_t tls_err, void *user_data)
{
    if (xqc_tt_av.first_err == 0) {
        xqc_tt_av.first_err = tls_err;
    }
}

static void
xqc_tt_av_cert_verify_failed_cb(int x509_err, void *user_data)
{
    xqc_tt_av.failed_calls++;
    xqc_tt_av.failed_err = x509_err;
}

/* DER of ./server.crt, the certificate ctx_svr serves. 0 on failure. */
static size_t
xqc_tt_load_server_cert_der(unsigned char *out, size_t cap)
{
    FILE *fp = fopen("./server.crt", "r");
    if (fp == NULL) {
        return 0;
    }
    X509 *x = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (x == NULL) {
        return 0;
    }
    int len = i2d_X509(x, NULL);
    if (len <= 0 || (size_t)len > cap) {
        X509_free(x);
        return 0;
    }
    unsigned char *p = out;
    i2d_X509(x, &p);
    X509_free(x);
    return (size_t)len;
}

/* Run one client (with the flag under test and the recording callbacks)
 * against ctx_svr up to the server's Handshake flight, i.e. through the
 * client's certificate verification. Returns the client's result for that
 * flight; *completed reports the client's handshake_completed. */
static xqc_int_t
xqc_tt_av_handshake(uint8_t cert_verify_flag, xqc_bool_t with_cb, xqc_bool_t *completed)
{
    uint8_t *data_buf = malloc(XQC_TEST_MAX_CRYPTO_DATA_BUF);
    size_t data_len = 0;
    xqc_cid_t odcid = {1};

    xqc_tls_config_t tls_config = {0};
    tls_config.cert_verify_flag = cert_verify_flag;
    tls_config.hostname = "test.xquic.com";
    tls_config.alpn = "transport";
    tls_config.trans_params = "10086";
    tls_config.trans_params_len = 5;

    xqc_tls_callbacks_t cbs = tls_test_cbs;
    cbs.cert_verify_cb = with_cb ? xqc_tt_av_cert_verify_cb : NULL;
    cbs.error_cb = xqc_tt_av_error_cb;
    cbs.cert_verify_failed_cb = xqc_tt_av_cert_verify_failed_cb;
    def_engine_ssl_config_cli;
    xqc_tls_ctx_t *ctx = xqc_tls_ctx_create(XQC_TLS_TYPE_CLIENT, &engine_ssl_config_cli,
                                            &cbs, test_log);
    CU_ASSERT(ctx != NULL);

    xqc_tls_test_buff_t *ttbuf_cli = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_cli = xqc_tls_create(ctx, &tls_config, test_log, ttbuf_cli);
    CU_ASSERT(xqc_tls_init(tls_cli, XQC_VERSION_V1, &odcid) == XQC_OK);

    xqc_tls_test_buff_t *ttbuf_svr = xqc_create_tls_test_buffer();
    xqc_tls_t *tls_svr = xqc_tls_create(ctx_svr, &tls_config, test_log, ttbuf_svr);
    CU_ASSERT(xqc_tls_init(tls_svr, XQC_VERSION_V1, &odcid) == XQC_OK);

    /* ClientHello -> server */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_cli->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    CU_ASSERT(xqc_tls_process_crypto_data(tls_svr, XQC_ENC_LEV_INIT, data_buf, data_len) == XQC_OK);

    /* ServerHello -> client */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->initial_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    CU_ASSERT(xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_INIT, data_buf, data_len) == XQC_OK);

    /* EE, CERT, CV, FIN -> client: certificate verification happens here */
    data_len = xqc_crypto_data_list_get_buf(&ttbuf_svr->hsk_crypto_data_list, data_buf);
    CU_ASSERT(data_len > 0);
    xqc_int_t ret = xqc_tls_process_crypto_data(tls_cli, XQC_ENC_LEV_HSK, data_buf, data_len);
    *completed = ttbuf_cli->handshake_completed;

    xqc_destroy_tls_test_buffer(ttbuf_cli);
    xqc_destroy_tls_test_buffer(ttbuf_svr);
    xqc_tls_destroy(tls_cli);
    xqc_tls_destroy(tls_svr);
    xqc_tls_ctx_destroy(ctx);
    free(data_buf);
    return ret;
}

void
xqc_test_tls_app_verify()
{
    unsigned char der[4096];
    size_t der_len = xqc_tt_load_server_cert_der(der, sizeof(der));
    CU_ASSERT(der_len > 0);
    xqc_bool_t completed = XQC_FALSE;

    /* 1. APP_VERIFY + accepting callback: the presented chain (leaf first)
     *    reaches the application on every handshake, and its OK is final —
     *    no root store, no hostname check by the library. */
    memset(&xqc_tt_av, 0, sizeof(xqc_tt_av));
    xqc_tt_av.ret = XQC_OK;
    CU_ASSERT(xqc_tt_av_handshake(XQC_TLS_CERT_FLAG_NEED_VERIFY | XQC_TLS_CERT_FLAG_APP_VERIFY,
                                  XQC_TRUE, &completed) == XQC_OK);
    CU_ASSERT(completed == XQC_TRUE);
    CU_ASSERT(xqc_tt_av.calls == 1);
    CU_ASSERT(xqc_tt_av.n_certs == 1);
    CU_ASSERT(xqc_tt_av.leaf_len == der_len);
    CU_ASSERT(memcmp(xqc_tt_av.leaf, der, der_len) == 0);
    CU_ASSERT(xqc_tt_av.first_err == 0);

    /* 2. APP_VERIFY + rejecting callback: the ssl library turns the rejection
     *    into handshake_failure(40), delivered through xqc_tls_send_alert. */
    memset(&xqc_tt_av, 0, sizeof(xqc_tt_av));
    xqc_tt_av.ret = -XQC_TLS_INTERNAL;
    CU_ASSERT(xqc_tt_av_handshake(XQC_TLS_CERT_FLAG_NEED_VERIFY | XQC_TLS_CERT_FLAG_APP_VERIFY,
                                  XQC_TRUE, &completed) != XQC_OK);
    CU_ASSERT(completed == XQC_FALSE);
    CU_ASSERT(xqc_tt_av.calls == 1);
    CU_ASSERT(xqc_tt_av.first_err == 40);

    /* 3. NEED_VERIFY only (existing users): the ctx-level callback delegates
     *    to X509_verify_cert, so the legacy per-certificate path rejects the
     *    self-signed server.crt (18) before any application callback. The
     *    first error_cb value is the X509 code, not the alert that follows. */
    memset(&xqc_tt_av, 0, sizeof(xqc_tt_av));
    xqc_tt_av.ret = XQC_OK;
    CU_ASSERT(xqc_tt_av_handshake(XQC_TLS_CERT_FLAG_NEED_VERIFY, XQC_TRUE, &completed) != XQC_OK);
    CU_ASSERT(completed == XQC_FALSE);
    CU_ASSERT(xqc_tt_av.calls == 0);
    CU_ASSERT(xqc_tt_av.first_err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);

    /* 4. APP_VERIFY alone (no NEED_VERIFY) + rejecting callback: the flag
     *    must turn on SSL_VERIFY_PEER by itself, or the ssl library runs
     *    under verify_mode NONE and silently ignores the rejection
     *    (fail-open). */
    memset(&xqc_tt_av, 0, sizeof(xqc_tt_av));
    xqc_tt_av.ret = -XQC_TLS_INTERNAL;
    CU_ASSERT(xqc_tt_av_handshake(XQC_TLS_CERT_FLAG_APP_VERIFY, XQC_TRUE, &completed) != XQC_OK);
    CU_ASSERT(completed == XQC_FALSE);
    CU_ASSERT(xqc_tt_av.calls == 1);
    CU_ASSERT(xqc_tt_av.first_err == 40);

    /* 5. APP_VERIFY requested but no cert_verify_cb registered: fail closed
     *    rather than silently accepting because there is nothing to ask. */
    memset(&xqc_tt_av, 0, sizeof(xqc_tt_av));
    xqc_tt_av.ret = XQC_OK;
    CU_ASSERT(xqc_tt_av_handshake(XQC_TLS_CERT_FLAG_NEED_VERIFY | XQC_TLS_CERT_FLAG_APP_VERIFY,
                                  XQC_FALSE, &completed) != XQC_OK);
    CU_ASSERT(completed == XQC_FALSE);
    CU_ASSERT(xqc_tt_av.calls == 0);
    CU_ASSERT(xqc_tt_av.first_err == 40);

    /* 6. NEED_VERIFY | ALLOW_SELF_SIGNED, accepting callback: legacy
     *    contract pin — the self-signed exemption still routes the
     *    presented chain to the application callback via the per-certificate
     *    path (xqc_ssl_cert_verify_cb), unaffected by APP_VERIFY. */
    memset(&xqc_tt_av, 0, sizeof(xqc_tt_av));
    xqc_tt_av.ret = XQC_OK;
    CU_ASSERT(xqc_tt_av_handshake(
        XQC_TLS_CERT_FLAG_NEED_VERIFY | XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED,
        XQC_TRUE, &completed) == XQC_OK);
    CU_ASSERT(completed == XQC_TRUE);
    CU_ASSERT(xqc_tt_av.calls == 1);
    CU_ASSERT(xqc_tt_av.n_certs == 1);
    CU_ASSERT(xqc_tt_av.first_err == 0);
}

/* ---- cert_verify_failed_cb: notify only, library-side rejections only ---- */

void
xqc_test_tls_cert_verify_failed_notify()
{
    xqc_bool_t completed = XQC_FALSE;

    /* 1. NEED_VERIFY rejects the self-signed server.crt inside the library:
     *    notified once, with the X509 error that caused it. */
    memset(&xqc_tt_av, 0, sizeof(xqc_tt_av));
    xqc_tt_av.ret = XQC_OK;
    CU_ASSERT(xqc_tt_av_handshake(XQC_TLS_CERT_FLAG_NEED_VERIFY, XQC_TRUE, &completed) != XQC_OK);
    CU_ASSERT(completed == XQC_FALSE);
    CU_ASSERT(xqc_tt_av.failed_calls == 1);
    CU_ASSERT(xqc_tt_av.failed_err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);

    /* 2. a rejection the legacy path routes through cert_verify_cb is still
     *    the library-side path rejecting: notified once */
    memset(&xqc_tt_av, 0, sizeof(xqc_tt_av));
    xqc_tt_av.ret = -XQC_TLS_INTERNAL;
    CU_ASSERT(xqc_tt_av_handshake(
        XQC_TLS_CERT_FLAG_NEED_VERIFY | XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED,
        XQC_TRUE, &completed) != XQC_OK);
    CU_ASSERT(xqc_tt_av.calls == 1);
    CU_ASSERT(xqc_tt_av.failed_calls == 1);
    CU_ASSERT(xqc_tt_av.failed_err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);

    /* 3. a tolerated error (ALLOW_SELF_SIGNED, accepted) is not a rejection */
    memset(&xqc_tt_av, 0, sizeof(xqc_tt_av));
    xqc_tt_av.ret = XQC_OK;
    CU_ASSERT(xqc_tt_av_handshake(
        XQC_TLS_CERT_FLAG_NEED_VERIFY | XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED,
        XQC_TRUE, &completed) == XQC_OK);
    CU_ASSERT(completed == XQC_TRUE);
    CU_ASSERT(xqc_tt_av.failed_calls == 0);

    /* 4. verification off (ALLOW_SELF_SIGNED alone, verify_mode NONE): never */
    memset(&xqc_tt_av, 0, sizeof(xqc_tt_av));
    xqc_tt_av.ret = -XQC_TLS_INTERNAL;
    CU_ASSERT(xqc_tt_av_handshake(XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED, XQC_TRUE,
                                  &completed) == XQC_OK);
    CU_ASSERT(completed == XQC_TRUE);
    CU_ASSERT(xqc_tt_av.failed_calls == 0);

    /* 5. APP_VERIFY: the application decided and already knows */
    memset(&xqc_tt_av, 0, sizeof(xqc_tt_av));
    xqc_tt_av.ret = -XQC_TLS_INTERNAL;
    CU_ASSERT(xqc_tt_av_handshake(XQC_TLS_CERT_FLAG_NEED_VERIFY | XQC_TLS_CERT_FLAG_APP_VERIFY,
                                  XQC_TRUE, &completed) != XQC_OK);
    CU_ASSERT(xqc_tt_av.calls == 1);
    CU_ASSERT(xqc_tt_av.failed_calls == 0);
}

void xqc_test_destroy_tls_ctx()
{
    xqc_tls_ctx_destroy(ctx_cli);
    xqc_tls_ctx_destroy(ctx_svr);
}

void
xqc_test_tls()
{
    xqc_log_callbacks_t log_cb =  xqc_null_log_cb;
    test_log =  xqc_log_init(0, 0, 0, 0, 0, NULL, &log_cb, NULL);
    
    xqc_test_create_client_tls_ctx();
    xqc_test_create_server_tls_ctx();
    xqc_test_tls_ctx_register_alpn();
    xqc_test_tls_reset_initial();
    
    xqc_test_tls_multiple_crypto_data();
    xqc_test_tls_generic();
    xqc_test_tls_process_truncated_crypto_handshake();
    xqc_test_tls_failure();
    xqc_test_tls_app_verify();
    xqc_test_tls_cert_verify_failed_notify();

    xqc_test_destroy_tls_ctx();
    xqc_free(test_log);
}