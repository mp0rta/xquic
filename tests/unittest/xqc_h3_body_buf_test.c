/**
 * @copyright Copyright (c) 2026, mp0rta
 */

/*
 * Tests for conn_settings.max_body_buf_per_stream, the bound on HTTP/3 DATA
 * payload buffered per request stream. The h3bb_* fixture drives the real
 * HTTP/3 stack on a connection built by test_engine_connect(): request
 * streams are fed as transport STREAM frames and read by the engine's own
 * read pass, so tests see the same ordering production code does.
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include "xquic/xquic.h"
#include "xquic/xqc_errno.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/http3/xqc_h3_stream.h"
#include "src/http3/xqc_h3_request.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_timer.h"
#include "src/common/xqc_time.h"
#include "xqc_common_test.h"
#include "xqc_h3_body_buf_test.h"

#define H3BB_MAX_REQ    8
#define H3BB_CHUNK      1200

typedef struct h3bb_fx_s h3bb_fx_t;

typedef struct {
    h3bb_fx_t        *fx;
    xqc_stream_t     *stream;
    xqc_h3_stream_t  *h3s;
    xqc_h3_request_t *h3r;
    uint64_t          offset;           /* next transport offset to feed */
    int               n_read_notify;
    int               n_closing_notify;
    int               n_close_notify;
    size_t            bytes_delivered;  /* bytes the application collected */
    int               drain_in_notify;  /* collect the whole body in notify */
    void            (*on_notify)(h3bb_fx_t *fx, int idx);
    void            (*on_close)(h3bb_fx_t *fx, int idx);
} h3bb_req_t;

struct h3bb_fx_s {
    xqc_connection_t *conn;
    xqc_h3_conn_t    *h3c;
    h3bb_req_t        req[H3BB_MAX_REQ];
    int               n_req;
    int               n_wake;           /* engine set_event_timer calls */
    xqc_usec_t        last_wake_us;
    xqc_engine_t     *srv_engine;       /* server-type fixtures only */
};

/* RFC 9114 Section 7.2.1: DATA frame; the HEADERS frame is a minimal valid
 * field section (see xqc_h3_test.c). */
static const uint8_t h3bb_valid_headers[] = {0x01, 0x03, 0x00, 0x00, 0xC0};


static void
h3bb_set_event_timer(xqc_usec_t wake_after, void *engine_user_data)
{
    h3bb_fx_t *fx = (h3bb_fx_t *)engine_user_data;

    fx->n_wake++;
    fx->last_wake_us = wake_after;
}

static int
h3bb_read_notify(xqc_h3_request_t *h3r, xqc_request_notify_flag_t flag,
    void *user_data)
{
    h3bb_req_t *rq = (h3bb_req_t *)user_data;
    h3bb_fx_t  *fx = rq->fx;
    int         idx = (int)(rq - fx->req);
    unsigned char buf[16 * 1024];
    uint8_t     fin;
    ssize_t     n;

    rq->n_read_notify++;

    if (rq->drain_in_notify && (flag & XQC_REQ_NOTIFY_READ_BODY)) {
        do {
            fin = 0;
            n = xqc_h3_request_recv_body(h3r, buf, sizeof(buf), &fin);
            if (n > 0) {
                rq->bytes_delivered += (size_t)n;
            }
        } while (n > 0);
    }

    if (rq->on_notify) {
        rq->on_notify(fx, idx);
    }
    return 0;
}

static void
h3bb_closing_notify(xqc_h3_request_t *h3r, xqc_int_t err, void *user_data)
{
    ((h3bb_req_t *)user_data)->n_closing_notify++;
}

static int
h3bb_close_notify(xqc_h3_request_t *h3r, void *user_data)
{
    h3bb_req_t *rq = (h3bb_req_t *)user_data;
    h3bb_fx_t  *fx = rq->fx;

    rq->n_close_notify++;
    if (rq->on_close) {
        rq->on_close(fx, (int)(rq - fx->req));
    }

    /* the objects are freed once this callback returns */
    rq->stream = NULL;
    rq->h3s = NULL;
    rq->h3r = NULL;
    return 0;
}

/*
 * Leave the connection as xqc_engine_main_logic() leaves one after a pass:
 * out of the active queue, TICKING clear, parked in the wakeup queue. Where
 * production would destroy the connection (no next tick) this takes the
 * NO_DESTROY branch: parked with next_tick_time 0.
 */
static void
h3bb_park(h3bb_fx_t *fx)
{
    xqc_connection_t *conn = fx->conn;
    xqc_engine_t     *engine = conn->engine;

    xqc_engine_remove_active_queue(engine, conn);
    xqc_engine_remove_wakeup_queue(engine, conn);
    conn->next_tick_time = xqc_conn_next_wakeup_time(conn);
    xqc_engine_add_wakeup_queue(engine, conn);
}

/* the state the engine holds a connection in while it processes it */
static void
h3bb_enter_pass(h3bb_fx_t *fx)
{
    xqc_connection_t *conn = fx->conn;

    xqc_engine_remove_active_queue(conn->engine, conn);
    xqc_engine_remove_wakeup_queue(conn->engine, conn);
    conn->conn_flag |= XQC_CONN_FLAG_TICKING;
    conn->engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
}

static void
h3bb_leave_pass(h3bb_fx_t *fx)
{
    fx->conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
    h3bb_park(fx);
    fx->conn->engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
}

/*
 * A connection that is an H3 connection the way the engine makes one: ALPN
 * h3, the H3 connection and stream callbacks, the setting under test, an
 * established state, and the control and QPACK streams. type selects which
 * way max_body_buf_per_stream reaches the connection: a client takes
 * `limit` straight from its settings; a server takes it from its engine's
 * defaults, set through xqc_server_set_conn_settings().
 */
int
h3bb_setup(h3bb_fx_t *fx, size_t limit, xqc_conn_type_t type)
{
    xqc_connection_t *conn;

    memset(fx, 0, sizeof(*fx));

    conn = test_engine_connect();
    if (conn == NULL) {
        return -1;
    }

    if (type == XQC_CONN_TYPE_SERVER) {
        /* a server connection takes its settings from the engine defaults
         * (xqc_conn_create copies them); the connection is the client-built
         * one, which carries a usable TLS state, relabelled as a server's */
        xqc_conn_settings_t s;

        fx->srv_engine = test_create_engine_server();
        if (fx->srv_engine == NULL) {
            return -1;
        }
        memset(&s, 0, sizeof(s));
        s.max_body_buf_per_stream = limit;
        xqc_server_set_conn_settings(fx->srv_engine, &s);
        conn->conn_settings = fx->srv_engine->default_conn_settings;
        conn->conn_type = XQC_CONN_TYPE_SERVER;

    } else {
        conn->conn_settings.max_body_buf_per_stream = limit;
    }

    fx->conn = conn;

    if (conn->alpn) {
        xqc_free(conn->alpn);
    }
    conn->alpn_len = strlen(XQC_ALPN_H3);
    conn->alpn = xqc_calloc(1, conn->alpn_len + 1);
    xqc_memcpy(conn->alpn, XQC_ALPN_H3, conn->alpn_len);

    conn->app_proto_cbs.conn_cbs = h3_conn_callbacks;
    conn->app_proto_cbs.stream_cbs = h3_stream_callbacks;

    conn->conn_state = XQC_CONN_STATE_ESTABED;
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn->conn_flow_ctl.fc_max_streams_bidi_can_send = 1024;
    conn->conn_flow_ctl.fc_max_streams_uni_can_send = 1024;

    conn->engine->eng_callback.set_event_timer = h3bb_set_event_timer;
    conn->engine->user_data = fx;

    if (h3_conn_callbacks.conn_create_notify(conn, NULL, NULL, NULL) != XQC_OK) {
        return -1;
    }
    conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;

    fx->h3c = (xqc_h3_conn_t *)conn->proto_data;
    if (fx->h3c == NULL) {
        return -1;
    }

    fx->h3c->h3_request_callbacks.h3_request_read_notify = h3bb_read_notify;
    fx->h3c->h3_request_callbacks.h3_request_closing_notify =
        h3bb_closing_notify;
    fx->h3c->h3_request_callbacks.h3_request_close_notify = h3bb_close_notify;
    h3bb_park(fx);
    return 0;
}

/* a consistent connection window and the credit advertised for it */
void
h3bb_set_conn_window(h3bb_fx_t *fx, uint64_t w)
{
    xqc_conn_flow_ctl_t *fc = &fx->conn->conn_flow_ctl;

    fc->fc_recv_windows_size = w;
    fc->fc_max_data_can_recv = fc->fc_data_read + w;
}

/* a new client bidi request, wired to the real H3 stream and request */
int
h3bb_add_request(h3bb_fx_t *fx)
{
    h3bb_req_t *rq;
    int         idx = fx->n_req;

    if (idx >= H3BB_MAX_REQ) {
        return -1;
    }
    rq = &fx->req[idx];
    rq->fx = fx;

    rq->stream = xqc_create_stream_with_conn(fx->conn, XQC_UNDEFINE_STREAM_ID,
                                             XQC_CLI_BID, NULL, NULL);
    if (rq->stream == NULL) {
        return -1;
    }

    rq->h3s = xqc_h3_stream_create(fx->h3c, rq->stream,
                                   XQC_H3_STREAM_TYPE_REQUEST, NULL);
    if (rq->h3s == NULL) {
        return -1;
    }

    rq->h3r = xqc_h3_request_create_inner(fx->h3c, rq->h3s, rq);
    if (rq->h3r == NULL) {
        return -1;
    }

    fx->n_req++;
    h3bb_park(fx);
    return idx;
}

uint64_t
h3bb_conn_credit_left(const h3bb_fx_t *fx)
{
    return fx->conn->conn_flow_ctl.fc_max_data_can_recv
           - fx->conn->conn_flow_ctl.fc_data_recved;
}

/*
 * Hand `len` bytes to the request's transport stream as STREAM frames of at
 * most H3BB_CHUNK bytes at the stream's current receive offset, with the
 * receive accounting xqc_process_stream_frame() does, after the two flow
 * control checks it makes first (RFC 9000 Section 4.1).
 */
void
h3bb_feed(h3bb_fx_t *fx, int idx, const uint8_t *h3, size_t len, int fin)
{
    h3bb_req_t          *rq = &fx->req[idx];
    xqc_stream_t        *stream = rq->stream;
    xqc_connection_t    *conn = fx->conn;
    xqc_stream_data_in_t *in = &stream->stream_data_in;
    size_t               done = 0;

    do {
        size_t              n = len - done > H3BB_CHUNK ? H3BB_CHUNK
                                                        : len - done;
        int                 last = (done + n == len);
        uint64_t            end = rq->offset + n;
        uint64_t            ext = end > stream->stream_max_recv_offset
                                  ? end - stream->stream_max_recv_offset : 0;
        xqc_stream_frame_t *f;
        xqc_int_t           ret;

        CU_ASSERT_FATAL(end <= stream->stream_flow_ctl
                                     .fc_max_stream_data_can_recv);
        CU_ASSERT_FATAL(conn->conn_flow_ctl.fc_data_recved + ext
                        <= conn->conn_flow_ctl.fc_max_data_can_recv);

        f = xqc_calloc(1, sizeof(xqc_stream_frame_t));
        f->data_offset = rq->offset;
        f->data_length = n;
        f->fin = (fin && last) ? 1 : 0;
        f->data = xqc_malloc(n ? n : 1);
        if (n) {
            memcpy(f->data, h3 + done, n);
        }

        if (f->fin) {
            in->stream_length = end;
            in->stream_determined = XQC_TRUE;
            if (stream->stream_state_recv == XQC_RECV_STREAM_ST_RECV) {
                xqc_stream_recv_state_update(stream,
                                             XQC_RECV_STREAM_ST_SIZE_KNOWN);
            }
        }

        ret = xqc_insert_stream_frame(conn, stream, f);
        CU_ASSERT_EQUAL_FATAL(ret, XQC_OK);

        conn->conn_flow_ctl.fc_data_recved += ext;
        if (ext) {
            stream->stream_max_recv_offset = end;
        }
        rq->offset = end;
        done += n;

        if (in->stream_determined && in->stream_length == in->merged_offset_end) {
            if (stream->stream_state_recv == XQC_RECV_STREAM_ST_SIZE_KNOWN) {
                xqc_stream_recv_state_update(stream,
                                             XQC_RECV_STREAM_ST_DATA_RECVD);
            }
            xqc_stream_ready_to_read(stream);

        } else if (in->next_read_offset < in->merged_offset_end) {
            xqc_stream_ready_to_read(stream);
        }
    } while (done < len);

    h3bb_park(fx);
}

void
h3bb_feed_headers(h3bb_fx_t *fx, int idx)
{
    h3bb_feed(fx, idx, h3bb_valid_headers, sizeof(h3bb_valid_headers), 0);
}

/* H3 DATA frames of `frame_payload` bytes (pattern 0xa5) until
 * `payload_len` bytes are fed, packed into transport chunks */
void
h3bb_feed_data(h3bb_fx_t *fx, int idx, size_t payload_len,
    size_t frame_payload, int fin)
{
    uint8_t *buf;
    size_t   cap = payload_len / frame_payload * (frame_payload + 5) + 2 * frame_payload + 16;
    size_t   n = 0;

    buf = xqc_malloc(cap);
    while (payload_len > 0) {
        size_t p = payload_len < frame_payload ? payload_len : frame_payload;

        buf[n++] = 0x00;                                /* DATA */
        if (p < 64) {
            buf[n++] = (uint8_t)p;
        } else if (p < 16384) {
            buf[n++] = (uint8_t)(0x40 | (p >> 8));
            buf[n++] = (uint8_t)(p & 0xff);
        } else {
            buf[n++] = (uint8_t)(0x80 | (p >> 24));
            buf[n++] = (uint8_t)(p >> 16);
            buf[n++] = (uint8_t)(p >> 8);
            buf[n++] = (uint8_t)p;
        }
        memset(buf + n, 0xa5, p);
        n += p;
        payload_len -= p;
    }

    h3bb_feed(fx, idx, buf, n, fin);
    xqc_free(buf);
}

size_t
h3bb_fed(const h3bb_fx_t *fx, int idx)
{
    return (size_t)fx->req[idx].offset;
}

/* one direct read turn of the request's own stream */
int
h3bb_read(h3bb_fx_t *fx, int idx)
{
    h3bb_req_t *rq = &fx->req[idx];

    int         ret;

    h3bb_enter_pass(fx);
    ret = h3_stream_callbacks.stream_read_notify(rq->stream, rq->h3s);
    h3bb_leave_pass(fx);
    return ret;
}

/* one emulated engine pass in production order: due timers first, then the
 * connection's read list; a timer armed during the pass fires in the next */
void
h3bb_turn(h3bb_fx_t *fx)
{
    h3bb_enter_pass(fx);
    xqc_timer_expire(&fx->conn->conn_timer_manager, xqc_monotonic_timestamp());
    xqc_process_read_streams(fx->conn);
    h3bb_leave_pass(fx);
}

/* the production path: the engine pops the connection from its queues and
 * destroys it, which runs the H3 connection teardown */
void
h3bb_teardown(h3bb_fx_t *fx)
{
    xqc_engine_destroy(fx->conn->engine);
    xqc_engine_destroy(fx->srv_engine);
    fx->conn = NULL;
    fx->h3c = NULL;
}


/* the limit reaches the H3 connection from client settings and, through the
 * engine defaults, from server settings (xqc_conn_create copies them) */
void
xqc_test_h3bb_settings_propagate(void)
{
    h3bb_fx_t           fx;
    xqc_engine_t       *engine;
    xqc_conn_settings_t s;

    engine = test_create_engine_server();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    memset(&s, 0, sizeof(s));
    s.max_body_buf_per_stream = 64 * 1024;
    xqc_server_set_conn_settings(engine, &s);
    CU_ASSERT_EQUAL(engine->default_conn_settings.max_body_buf_per_stream,
                    64 * 1024);
    xqc_engine_destroy(engine);

    CU_ASSERT_EQUAL_FATAL(h3bb_setup(&fx, 64 * 1024, XQC_CONN_TYPE_SERVER), 0);
    CU_ASSERT_EQUAL(fx.srv_engine->default_conn_settings
                        .max_body_buf_per_stream, 64 * 1024);
    CU_ASSERT_EQUAL(fx.conn->conn_settings.max_body_buf_per_stream, 64 * 1024);
    CU_ASSERT_EQUAL(fx.h3c->max_body_buf_per_stream, 64 * 1024);
    h3bb_teardown(&fx);

    CU_ASSERT_EQUAL_FATAL(h3bb_setup(&fx, 0, XQC_CONN_TYPE_SERVER), 0);
    CU_ASSERT_EQUAL(fx.h3c->max_body_buf_per_stream, 0);
    h3bb_teardown(&fx);

    CU_ASSERT_EQUAL_FATAL(h3bb_setup(&fx, 32768, XQC_CONN_TYPE_CLIENT), 0);
    CU_ASSERT_EQUAL(fx.h3c->max_body_buf_per_stream, 32768);
    h3bb_teardown(&fx);
}

/* limit 0: one read turn takes everything the transport holds and leaves
 * the pause bit down */
void
xqc_test_h3bb_limit_zero_reads_all(void)
{
    h3bb_fx_t fx;
    int       i;

    CU_ASSERT_EQUAL_FATAL(h3bb_setup(&fx, 0, XQC_CONN_TYPE_CLIENT), 0);
    h3bb_set_conn_window(&fx, 16 * 1024 * 1024);
    i = h3bb_add_request(&fx);
    CU_ASSERT_EQUAL_FATAL(i, 0);
    fx.req[i].stream->stream_flow_ctl.fc_max_stream_data_can_recv =
        16 * 1024 * 1024;
    fx.req[i].drain_in_notify = 0;

    h3bb_feed_headers(&fx, i);
    h3bb_feed_data(&fx, i, 256 * 1024, 1000, 0);

    h3bb_read(&fx, i);
    CU_ASSERT_EQUAL(fx.req[i].stream->stream_data_in.next_read_offset,
                    h3bb_fed(&fx, i));
    CU_ASSERT_EQUAL(fx.req[i].h3s->flags
                    & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED, 0);

    h3bb_teardown(&fx);
}

/* the fixture itself: the H3 callbacks are wired, the engine pass reads, and
 * teardown runs the H3 connection close */
static int h3bb_test_close_hook_runs;

static void
h3bb_test_on_close(h3bb_fx_t *fx, int idx)
{
    /* the request's objects are still valid inside the hook */
    CU_ASSERT_PTR_NOT_NULL(fx->req[idx].h3r);
    h3bb_test_close_hook_runs++;
}

/* after each fixture step the connection is parked as the engine leaves it */
static void
h3bb_test_assert_parked(h3bb_fx_t *fx)
{
    CU_ASSERT_EQUAL(fx->conn->conn_flag & XQC_CONN_FLAG_TICKING, 0);
    CU_ASSERT_EQUAL(fx->conn->engine->eng_flag & XQC_ENG_FLAG_RUNNING, 0);
    CU_ASSERT_NOT_EQUAL(fx->conn->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP, 0);
}

void
xqc_test_h3bb_fixture_engine_turn(void)
{
    h3bb_fx_t fx;
    int       i;

    CU_ASSERT_EQUAL_FATAL(h3bb_setup(&fx, 0, XQC_CONN_TYPE_CLIENT), 0);
    h3bb_set_conn_window(&fx, 16 * 1024 * 1024);
    i = h3bb_add_request(&fx);
    CU_ASSERT_EQUAL_FATAL(i, 0);
    fx.req[i].on_close = h3bb_test_on_close;
    h3bb_test_close_hook_runs = 0;

    h3bb_feed_headers(&fx, i);
    h3bb_test_assert_parked(&fx);
    h3bb_feed_data(&fx, i, 4096, 1000, 0);
    h3bb_test_assert_parked(&fx);

    h3bb_read(&fx, i);
    h3bb_test_assert_parked(&fx);

    h3bb_feed_data(&fx, i, 4096, 1000, 0);
    h3bb_turn(&fx);
    h3bb_test_assert_parked(&fx);
    CU_ASSERT(fx.req[i].n_read_notify >= 1);
    CU_ASSERT_EQUAL(fx.conn->conn_err, 0);

    h3bb_teardown(&fx);
    for (i = 0; i < fx.n_req; i++) {
        CU_ASSERT_EQUAL(fx.req[i].n_close_notify, 1);
    }
    CU_ASSERT_EQUAL(h3bb_test_close_hook_runs, 1);
}

#define H3BB_LIMIT  16384

/* a client request with the stream and connection windows opened wide
 * enough for the tests to feed more than the default window */
static int
h3bb_open_request(h3bb_fx_t *fx, size_t limit)
{
    int i;

    CU_ASSERT_EQUAL_FATAL(h3bb_setup(fx, limit, XQC_CONN_TYPE_CLIENT), 0);
    h3bb_set_conn_window(fx, 16 * 1024 * 1024);
    i = h3bb_add_request(fx);
    CU_ASSERT_EQUAL_FATAL(i, 0);
    fx->req[i].stream->stream_flow_ctl.fc_max_stream_data_can_recv =
        16 * 1024 * 1024;
    fx->req[i].drain_in_notify = 0;
    return i;
}

static size_t
h3bb_put_varint(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(0x80 | (v >> 24));
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
    return 4;
}

/*
 * Run the transport's own RESET_STREAM (RFC 9000 Section 19.4) or, with
 * `reliable` set, RESET_STREAM_AT frame processing on the request's stream,
 * inside an emulated engine pass.
 */
static void
h3bb_process_reset(h3bb_fx_t *fx, int idx, uint64_t final_size, int reliable,
    uint64_t reliable_size)
{
    uint8_t          frame[32];
    size_t           n = 0;
    xqc_packet_in_t  pi;

    frame[n++] = reliable ? XQC_FRAME_TYPE_RESET_STREAM_AT
                          : XQC_FRAME_TYPE_RESET_STREAM;
    n += h3bb_put_varint(frame + n, fx->req[idx].stream->stream_id);
    n += h3bb_put_varint(frame + n, 0x10c);
    n += h3bb_put_varint(frame + n, final_size);
    if (reliable) {
        n += h3bb_put_varint(frame + n, reliable_size);
    }

    memset(&pi, 0, sizeof(pi));
    pi.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    pi.pos = frame;
    pi.last = frame + n;

    h3bb_enter_pass(fx);
    if (reliable) {
        fx->conn->local_settings.reset_stream_at = XQC_TRUE;
        fx->conn->remote_settings.reset_stream_at = XQC_TRUE;
        CU_ASSERT_EQUAL(xqc_process_reset_stream_at_frame(fx->conn, &pi),
                        XQC_OK);
    } else {
        CU_ASSERT_EQUAL(xqc_process_reset_stream_frame(fx->conn, &pi),
                        XQC_OK);
    }
    h3bb_leave_pass(fx);
}

/* F1: at the limit the normal read loop stops and the stream leaves the
 * read list */
static void
h3bb_fill_to_limit(h3bb_fx_t *fx, int i)
{
    h3bb_feed_headers(fx, i);
    h3bb_feed_data(fx, i, 65536, 1400, 0);
    h3bb_read(fx, i);
}

void
xqc_test_h3bb_pause_at_limit(void)
{
    h3bb_fx_t fx;
    int       i;

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    h3bb_fill_to_limit(&fx, i);

    CU_ASSERT(fx.req[i].h3r->body_buf_bytes >= H3BB_LIMIT
              && fx.req[i].h3r->body_buf_bytes < H3BB_LIMIT + 4096);
    CU_ASSERT(fx.req[i].h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    CU_ASSERT(fx.req[i].stream->stream_data_in.next_read_offset
              < h3bb_fed(&fx, i));
    CU_ASSERT(!(fx.req[i].stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ));

    h3bb_teardown(&fx);
}

/* data arriving while paused wakes the stream, but the read turn leaves it
 * alone */
void
xqc_test_h3bb_paused_notify_reads_nothing(void)
{
    h3bb_fx_t fx;
    int       i;
    uint64_t  off;
    size_t    bytes;

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    h3bb_fill_to_limit(&fx, i);
    off = fx.req[i].stream->stream_data_in.next_read_offset;
    bytes = fx.req[i].h3r->body_buf_bytes;

    h3bb_feed_data(&fx, i, 1400, 1400, 0);
    h3bb_read(&fx, i);

    CU_ASSERT_EQUAL(fx.req[i].stream->stream_data_in.next_read_offset, off);
    CU_ASSERT_EQUAL(fx.req[i].h3r->body_buf_bytes, bytes);
    CU_ASSERT(!(fx.req[i].stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ));

    h3bb_teardown(&fx);
}

/* F2: one-byte DATA frames share nodes */
void
xqc_test_h3bb_tiny_data_coalesced(void)
{
    h3bb_fx_t fx;
    int       i;

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    h3bb_feed_headers(&fx, i);
    h3bb_feed_data(&fx, i, 20000, 1, 0);
    h3bb_read(&fx, i);

    CU_ASSERT(fx.req[i].h3r->body_buf_count
              <= 2 * (H3BB_LIMIT + 4096) / 256 + 2);
    CU_ASSERT(fx.req[i].h3r->body_buf_bytes < H3BB_LIMIT + 4096);
    CU_ASSERT(fx.req[i].h3r->body_buf_bytes >= H3BB_LIMIT);

    h3bb_teardown(&fx);
}

/* F9: the read that crosses the limit also reads FIN; no pause */
void
xqc_test_h3bb_no_pause_after_fin(void)
{
    h3bb_fx_t fx;
    int       i;

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    h3bb_feed_headers(&fx, i);
    h3bb_feed_data(&fx, i, 17000, 17000, 1);
    h3bb_read(&fx, i);

    CU_ASSERT(fx.req[i].h3r->body_buf_bytes >= H3BB_LIMIT);
    CU_ASSERT(fx.req[i].h3s->flags & XQC_HTTP3_STREAM_FLAG_READ_EOF);
    CU_ASSERT(!(fx.req[i].h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED));

    h3bb_teardown(&fx);
}

/* F9: a reset stream is never paused, the read reaches the transport */
void
xqc_test_h3bb_no_pause_after_reset(void)
{
    h3bb_fx_t     fx;
    int           i;
    xqc_stream_t *stream;

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    stream = fx.req[i].stream;
    h3bb_fill_to_limit(&fx, i);
    CU_ASSERT(fx.req[i].h3r->body_buf_bytes >= H3BB_LIMIT);

    h3bb_process_reset(&fx, i, h3bb_fed(&fx, i), 0, 0);
    CU_ASSERT_EQUAL_FATAL(stream->stream_state_recv,
                          XQC_RECV_STREAM_ST_RESET_RECVD);
    CU_ASSERT(fx.req[i].h3r->body_buf_bytes >= H3BB_LIMIT);

    h3bb_read(&fx, i);
    CU_ASSERT_EQUAL(stream->stream_state_recv, XQC_RECV_STREAM_ST_RESET_READ);

    h3bb_teardown(&fx);
}

/* F9: RESET_STREAM_AT whose reliable part is already read while the buffer
 * is at the limit: the first read ends on a short read at the reliable size
 * and re-queues the stream; the next read turn (read_called false) must not
 * pause and completes the reset. 5 + 5 + 29990 = 30000 bytes fed; the
 * reliable size 20000 is not a multiple of 4 KiB. */
void
xqc_test_h3bb_no_pause_reliable_prefix_read(void)
{
    h3bb_fx_t     fx;
    int           i;
    xqc_stream_t *stream;

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    stream = fx.req[i].stream;
    h3bb_feed_headers(&fx, i);
    h3bb_feed_data(&fx, i, 29990, 29990, 0);
    CU_ASSERT_EQUAL_FATAL(h3bb_fed(&fx, i), 30000);

    h3bb_process_reset(&fx, i, 30000, 1, 20000);
    CU_ASSERT_EQUAL_FATAL(stream->reset_at.recv_state, XQC_RESET_AT_RELIABLE);
    CU_ASSERT(stream->stream_state_recv < XQC_RECV_STREAM_ST_RESET_RECVD);

    /* the reliable prefix is read in full, the reset is still pending */
    h3bb_read(&fx, i);
    CU_ASSERT_EQUAL(stream->stream_data_in.next_read_offset, 20000);
    CU_ASSERT(fx.req[i].h3r->body_buf_bytes >= H3BB_LIMIT);
    CU_ASSERT(!(fx.req[i].h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED));
    CU_ASSERT(stream->stream_state_recv < XQC_RECV_STREAM_ST_RESET_RECVD);
    CU_ASSERT(stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ);

    h3bb_read(&fx, i);
    CU_ASSERT_EQUAL(stream->stream_state_recv, XQC_RECV_STREAM_ST_RESET_READ);
    CU_ASSERT(!(fx.req[i].h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED));

    h3bb_teardown(&fx);
}

/* recv_body keeps body_buf_bytes exact: whole nodes, a partial node, and
 * the empty node that carries FIN */
void
xqc_test_h3bb_body_bytes_accounting(void)
{
    h3bb_fx_t     fx;
    int           i;
    unsigned char buf[4096];
    uint8_t       fin;
    size_t        before;
    ssize_t       n;
    static const uint8_t empty_fin[] = {0x00, 0x00};

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    h3bb_fill_to_limit(&fx, i);

    before = fx.req[i].h3r->body_buf_bytes;
    n = xqc_h3_request_recv_body(fx.req[i].h3r, buf, 1000, &fin);
    CU_ASSERT_EQUAL(n, 1000);
    CU_ASSERT_EQUAL(fx.req[i].h3r->body_buf_bytes, before - 1000);

    /* a read that ends inside a node */
    before = fx.req[i].h3r->body_buf_bytes;
    n = xqc_h3_request_recv_body(fx.req[i].h3r, buf, 1, &fin);
    CU_ASSERT_EQUAL(n, 1);
    CU_ASSERT_EQUAL(fx.req[i].h3r->body_buf_bytes, before - 1);

    before = fx.req[i].h3r->body_buf_bytes;
    n = xqc_h3_request_recv_body(fx.req[i].h3r, buf, sizeof(buf), &fin);
    CU_ASSERT(n > 0);
    CU_ASSERT_EQUAL(fx.req[i].h3r->body_buf_bytes, before - (size_t)n);
    h3bb_teardown(&fx);

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    h3bb_feed_headers(&fx, i);
    h3bb_feed_data(&fx, i, 100, 100, 0);
    h3bb_feed(&fx, i, empty_fin, sizeof(empty_fin), 1);
    h3bb_read(&fx, i);
    CU_ASSERT_EQUAL(fx.req[i].h3r->body_buf_bytes, 100);

    n = xqc_h3_request_recv_body(fx.req[i].h3r, buf, 60, &fin);
    CU_ASSERT_EQUAL(n, 60);
    CU_ASSERT_EQUAL(fx.req[i].h3r->body_buf_bytes, 40);
    n = xqc_h3_request_recv_body(fx.req[i].h3r, buf, sizeof(buf), &fin);
    CU_ASSERT_EQUAL(n, 40);
    CU_ASSERT_EQUAL(fx.req[i].h3r->body_buf_bytes, 0);
    CU_ASSERT(fin);

    h3bb_teardown(&fx);
}

/* take everything the application can see out of the request's body buffer */
static size_t
h3bb_drain(h3bb_fx_t *fx, int idx)
{
    unsigned char buf[16 * 1024];
    uint8_t       fin;
    ssize_t       n;
    size_t        total = 0;

    do {
        fin = 0;
        n = xqc_h3_request_recv_body(fx->req[idx].h3r, buf, sizeof(buf), &fin);
        if (n > 0) {
            total += (size_t)n;
        }
    } while (n > 0);
    fx->req[idx].bytes_delivered += total;
    return total;
}

/* F3a: a drain inside the body notify is followed by more reading in the same
 * engine pass, until the transport is empty */
void
xqc_test_h3bb_resume_in_body_notify(void)
{
    h3bb_fx_t fx;
    int       i;

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    fx.req[i].drain_in_notify = 1;
    h3bb_feed_headers(&fx, i);
    h3bb_feed_data(&fx, i, 256 * 1024, 1400, 0);

    h3bb_read(&fx, i);

    CU_ASSERT_EQUAL(fx.req[i].bytes_delivered, 256 * 1024);
    CU_ASSERT_EQUAL(fx.req[i].h3s->flags
                    & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED, 0);
    CU_ASSERT_EQUAL(fx.req[i].h3s->flags
                    & XQC_HTTP3_STREAM_FLAG_IN_BODY_NOTIFY, 0);

    h3bb_teardown(&fx);
}

/* F3b: a drain elsewhere inside the engine leaves a due timer, and the next
 * pass reads the stream on */
void
xqc_test_h3bb_resume_in_engine_elsewhere(void)
{
    h3bb_fx_t   fx;
    int         i;
    uint64_t    off;
    xqc_bool_t  is_set = XQC_FALSE;
    xqc_usec_t  expire = 0;

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    h3bb_fill_to_limit(&fx, i);
    CU_ASSERT(fx.req[i].h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    off = fx.req[i].stream->stream_data_in.next_read_offset;
    CU_ASSERT(fx.h3c->body_buf_revisit_timer < 0);

    fx.conn->engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
    CU_ASSERT(h3bb_drain(&fx, i) > 0);
    fx.conn->engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;

    CU_ASSERT_EQUAL(fx.req[i].h3s->flags
                    & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED, 0);
    CU_ASSERT_FATAL(fx.h3c->body_buf_revisit_timer >= 0);
    CU_ASSERT_EQUAL(xqc_conn_gp_timer_get_info(fx.conn,
                        fx.h3c->body_buf_revisit_timer, &is_set, &expire),
                    XQC_OK);
    CU_ASSERT(is_set);
    CU_ASSERT(expire <= xqc_monotonic_timestamp());

    h3bb_turn(&fx);
    CU_ASSERT(fx.req[i].stream->stream_data_in.next_read_offset > off);

    h3bb_teardown(&fx);
}

/* F3c: a drain outside the engine fires the app's event timer at once and
 * queues the connection */
void
xqc_test_h3bb_resume_outside_engine(void)
{
    h3bb_fx_t fx;
    int       i;
    int       wakes;

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    h3bb_fill_to_limit(&fx, i);
    CU_ASSERT(fx.req[i].h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);
    wakes = fx.n_wake;

    CU_ASSERT(h3bb_drain(&fx, i) > 0);

    CU_ASSERT(fx.n_wake > wakes);
    CU_ASSERT(fx.last_wake_us <= 1);
    CU_ASSERT_NOT_EQUAL(fx.conn->conn_flag & XQC_CONN_FLAG_TICKING, 0);
    CU_ASSERT(fx.req[i].stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ);
    CU_ASSERT(fx.h3c->body_buf_revisit_timer < 0);

    h3bb_turn(&fx);
    h3bb_teardown(&fx);
}

/* F3d: the notify drains the request and closes the connection: the read-on
 * loop must not read again */
static uint64_t h3bb_off_after_first_drain;
static int      h3bb_close_done;

static void
h3bb_test_drain_then_close(h3bb_fx_t *fx, int idx)
{
    if (h3bb_close_done || !(fx->req[idx].h3s->flags
                             & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED))
    {
        return;
    }
    h3bb_close_done = 1;
    h3bb_drain(fx, idx);
    h3bb_off_after_first_drain =
        fx->req[idx].stream->stream_data_in.next_read_offset;
    CU_ASSERT_EQUAL(xqc_conn_close(fx->conn->engine,
                                   &fx->conn->scid_set.user_scid), XQC_OK);
}

void
xqc_test_h3bb_resume_loop_stops_on_conn_close(void)
{
    h3bb_fx_t fx;
    int       i;

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    fx.req[i].on_notify = h3bb_test_drain_then_close;
    h3bb_close_done = 0;
    h3bb_feed_headers(&fx, i);
    h3bb_feed_data(&fx, i, 256 * 1024, 1400, 0);

    h3bb_read(&fx, i);

    CU_ASSERT_EQUAL(h3bb_close_done, 1);
    CU_ASSERT(xqc_conn_is_tearing_down(fx.conn));
    CU_ASSERT_EQUAL(fx.req[i].stream->stream_data_in.next_read_offset,
                    h3bb_off_after_first_drain);

    h3bb_teardown(&fx);
}

/* F11: while the connection is destroyed, a drain from a close callback does
 * not queue the connection or arm the timer */
static int h3bb_destroy_checked;
static int h3bb_destroy_wakes;

static void
h3bb_test_drain_in_close(h3bb_fx_t *fx, int idx)
{
    if (idx != 0) {
        return;
    }
    CU_ASSERT_NOT_EQUAL(fx->conn->conn_flag & XQC_CONN_FLAG_DESTROYING, 0);
    CU_ASSERT(h3bb_drain(fx, 1) > 0);
    CU_ASSERT(!(fx->req[1].stream->stream_flag & XQC_STREAM_FLAG_READY_TO_READ));
    CU_ASSERT_EQUAL(fx->n_wake, h3bb_destroy_wakes);
    CU_ASSERT(fx->h3c->body_buf_revisit_timer < 0);
    h3bb_destroy_checked = 1;
}

void
xqc_test_h3bb_resume_during_destroy_not_queued(void)
{
    h3bb_fx_t fx;
    int       i, j;

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    j = h3bb_add_request(&fx);
    CU_ASSERT_EQUAL_FATAL(j, 1);
    fx.req[j].stream->stream_flow_ctl.fc_max_stream_data_can_recv =
        16 * 1024 * 1024;
    h3bb_fill_to_limit(&fx, j);
    CU_ASSERT(fx.req[j].h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED);

    fx.req[i].on_close = h3bb_test_drain_in_close;
    h3bb_destroy_checked = 0;
    h3bb_destroy_wakes = fx.n_wake;

    h3bb_teardown(&fx);

    CU_ASSERT_EQUAL(h3bb_destroy_checked, 1);
    CU_ASSERT_EQUAL(fx.req[i].n_close_notify, 1);
    CU_ASSERT_EQUAL(fx.req[j].n_close_notify, 1);
}

/* the application leaves a little in the buffer; the read-on finds the
 * transport empty and must not notify that leftover a second time */
static int h3bb_body_notifies;

static void
h3bb_test_drain_to_low_water(h3bb_fx_t *fx, int idx)
{
    unsigned char buf[512];
    uint8_t       fin;

    if (fx->req[idx].h3r->body_buf_bytes == 0) {
        return;
    }
    h3bb_body_notifies++;
    while (fx->req[idx].h3r->body_buf_bytes > H3BB_LIMIT / 8) {
        if (xqc_h3_request_recv_body(fx->req[idx].h3r, buf, sizeof(buf), &fin) <= 0) {
            break;
        }
    }
}

void
xqc_test_h3bb_resume_loop_no_empty_notify(void)
{
    h3bb_fx_t fx;
    int       i;

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    fx.req[i].on_notify = h3bb_test_drain_to_low_water;
    h3bb_body_notifies = 0;
    h3bb_feed_headers(&fx, i);
    /* HEADERS + DATA header + payload = five full 4 KiB reads: the read
     * ends paused with the transport empty */
    h3bb_feed_data(&fx, i, 5 * 4096 - 10, 5 * 4096 - 10, 0);

    h3bb_read(&fx, i);

    CU_ASSERT_EQUAL(fx.req[i].stream->stream_data_in.next_read_offset,
                    h3bb_fed(&fx, i));
    CU_ASSERT_EQUAL(h3bb_body_notifies, 1);

    h3bb_teardown(&fx);
}

/* a trailer parsed by the read-on notifies the body; the connection is
 * closed there with body left: no further notify */
static int h3bb_notifies_at_close;

static void
h3bb_test_drain_then_close_in_trailer(h3bb_fx_t *fx, int idx)
{
    if (fx->req[idx].h3s->flags & XQC_HTTP3_STREAM_FLAG_BODY_BUF_PAUSED) {
        h3bb_drain(fx, idx);

    } else if (!h3bb_notifies_at_close && fx->req[idx].h3r->body_buf_bytes > 0) {
        h3bb_notifies_at_close = fx->req[idx].n_read_notify;
        CU_ASSERT_EQUAL(xqc_conn_close(fx->conn->engine,
                                       &fx->conn->scid_set.user_scid), XQC_OK);
    }
}

void
xqc_test_h3bb_resume_loop_no_notify_after_close(void)
{
    h3bb_fx_t fx;
    int       i;

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    fx.req[i].on_notify = h3bb_test_drain_then_close_in_trailer;
    h3bb_notifies_at_close = 0;
    h3bb_feed_headers(&fx, i);
    h3bb_feed_data(&fx, i, H3BB_LIMIT + 6000, 1400, 0);
    h3bb_feed(&fx, i, h3bb_valid_headers, sizeof(h3bb_valid_headers), 0);

    h3bb_read(&fx, i);

    CU_ASSERT(h3bb_notifies_at_close > 0);
    CU_ASSERT(xqc_conn_is_tearing_down(fx.conn));
    /* only the trailer notify of the same parse follows the close */
    CU_ASSERT_EQUAL(fx.req[i].n_read_notify, h3bb_notifies_at_close + 1);

    h3bb_teardown(&fx);
}

/* the final, empty DATA frame with FIN arrives after the application drained
 * everything in the resumed notify: the read-on must still notify it */
void
xqc_test_h3bb_resume_loop_final_empty_data_fin(void)
{
    h3bb_fx_t fx;
    int       i;
    static const uint8_t empty_data[] = {0x00, 0x00};

    i = h3bb_open_request(&fx, H3BB_LIMIT);
    fx.req[i].drain_in_notify = 1;
    h3bb_feed_headers(&fx, i);
    h3bb_feed_data(&fx, i, 5 * 4096 - 10, 5 * 4096 - 10, 0);
    h3bb_feed(&fx, i, empty_data, sizeof(empty_data), 1);

    h3bb_read(&fx, i);

    CU_ASSERT_EQUAL(fx.req[i].bytes_delivered, 5 * 4096 - 10);
    CU_ASSERT(fx.req[i].h3s->flags & XQC_HTTP3_STREAM_FLAG_READ_EOF);
    /* the application was told that the message ended */
    CU_ASSERT(xqc_list_empty(&fx.req[i].h3r->body_buf));
    CU_ASSERT(fx.req[i].h3r->h3r_end_time > 0);
    CU_ASSERT_EQUAL(fx.req[i].n_read_notify, 3);

    h3bb_teardown(&fx);
}
