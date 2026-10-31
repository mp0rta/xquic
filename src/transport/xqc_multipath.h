
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 * @copyright Copyright (c) 2026, mp0rta
 */

#ifndef XQC_MULTIPATH_H
#define XQC_MULTIPATH_H

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include "src/transport/xqc_cid.h"
#include "src/common/xqc_common.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_recv_record.h"
#include "src/transport/xqc_frame_parser.h"


/* enable multipath */
typedef enum {
    XQC_CONN_MP_DISABLED      = 0,    /* 00 */
    XQC_CONN_MP_ENABLED       = 1,    /* 01 */
} xqc_multipath_mode_t;

/* path state */
typedef enum {
    XQC_PATH_STATE_INIT       = 0,    /* initial state */
    XQC_PATH_STATE_VALIDATING = 1,    /* PATH_CHALLENGE sent/received on new path */
    XQC_PATH_STATE_ACTIVE     = 2,    /* PATH_RESPONSE received */
    XQC_PATH_STATE_CLOSING    = 3,    /* PATH_ABANDONED sent or received */
    XQC_PATH_STATE_CLOSED     = 4,    /* PATH_ABANDONED acked or draining timeout */
} xqc_path_state_t;

/* path close mode: passive & proactive */
typedef enum {
    XQC_PATH_CLOSE_PASSIVE    = 0,
    XQC_PATH_CLOSE_PROACTIVE  = 1,
} xqc_path_close_mode_t;

typedef enum {
    XQC_SEND_TYPE_NORMAL,
    XQC_SEND_TYPE_NORMAL_HIGH_PRI,
    XQC_SEND_TYPE_RETRANS,
    XQC_SEND_TYPE_PTO_PROBE,
    XQC_SEND_TYPE_N,
} xqc_send_type_t;

typedef enum {
    XQC_PATH_FLAG_SEND_STATUS_SHIFT,
    XQC_PATH_FLAG_RECV_STATUS_SHIFT,
    XQC_PATH_FLAG_SOCKET_ERROR_SHIFT,
    XQC_PATH_FLAG_SHOULD_ACK_INIT_SHIFT,
    XQC_PATH_FLAG_SHOULD_ACK_HSK_SHIFT,
    XQC_PATH_FLAG_SHOULD_ACK_01RTT_SHIFT,
} xqc_path_flag_shift_t;

typedef enum {
    XQC_PATH_FLAG_SEND_STATUS       = 1 << XQC_PATH_FLAG_SEND_STATUS_SHIFT,
    XQC_PATH_FLAG_RECV_STATUS       = 1 << XQC_PATH_FLAG_RECV_STATUS_SHIFT,
    XQC_PATH_FLAG_SOCKET_ERROR      = 1 << XQC_PATH_FLAG_SOCKET_ERROR_SHIFT,
    XQC_PATH_FLAG_SHOULD_ACK_INIT   = 1 << XQC_PATH_FLAG_SHOULD_ACK_INIT_SHIFT,
    XQC_PATH_FLAG_SHOULD_ACK_HSK    = 1 << XQC_PATH_FLAG_SHOULD_ACK_HSK_SHIFT,
    XQC_PATH_FLAG_SHOULD_ACK_01RTT  = 1 << XQC_PATH_FLAG_SHOULD_ACK_01RTT_SHIFT,
} xqc_path_flag_t;

typedef enum {
    XQC_PATH_SPECIFIED_BY_ACK       = 1 << 0,  /* ack */
    XQC_PATH_SPECIFIED_BY_PCPR      = 1 << 1,  /* path challenge & response */
    XQC_PATH_SPECIFIED_BY_PTO       = 1 << 2,  /* PTO probe */
    XQC_PATH_SPECIFIED_BY_REINJ     = 1 << 3,  /* reinjection on a specific path */
    XQC_PATH_SPECIFIED_BY_PTMUD     = 1 << 4,  /* PMTUD Probe */
    XQC_PATH_SPECIFIED_BY_KAP       = 1 << 5,  /* Keepalive Probe */
    XQC_PATH_SPECIFIED_BY_PQP       = 1 << 6,  /* Path Quality Probe */
    XQC_PATH_SPECIFIED_BY_FEC       = 1 << 7,  /* FEC repair symbol */
    XQC_PATH_SPECIFIED_BY_DATAGRAM  = 1 << 8,  /* datagram pinned to path */
} xqc_path_specified_flag_t;

typedef enum {
    XQC_PATH_CLASS_AVAILABLE_HIGH,
    XQC_PATH_CLASS_STANDBY_HIGH,
    XQC_PATH_CLASS_AVAILABLE_MID,
    XQC_PATH_CLASS_STANDBY_MID,
    XQC_PATH_CLASS_AVAILABLE_LOW,
    XQC_PATH_CLASS_STANDBY_LOW,
    XQC_PATH_CLASS_PERF_CLASS_SIZE,
} xqc_path_perf_class_t;

#define XQC_REBINDING_MAX_MTU_PROBE_RETRIES 3

typedef enum {
    XQC_REBINDING_IDLE = 0,
    XQC_REBINDING_ADDRESS_VALIDATING,
    XQC_REBINDING_MTU_VALIDATING,
} xqc_rebinding_state_t;

typedef struct {
    /* Path lifetime statistics are preserved when a candidate is cleared. */
    uint32_t              count;
    uint32_t              valid;
    unsigned char         addr[sizeof(struct sockaddr_in6)];
    socklen_t             addrlen;
    uint64_t              recv_bytes;
    uint64_t              sent_bytes;
    uint32_t              mtu_probe_retries;
    xqc_rebinding_state_t state;
    xqc_bool_t            initial_challenge_padded;
    unsigned char         challenge_data[XQC_PATH_CHALLENGE_DATA_LEN];
} xqc_path_rebinding_t;

/* path context */
struct xqc_path_ctx_s {

    /* Path_identifier */
    uint64_t            path_id;    /* path identifier */
    xqc_cid_t           path_scid;
    xqc_cid_t           path_dcid;

    /* Path_address: 4-tuple */
    unsigned char       peer_addr[sizeof(struct sockaddr_in6)],
                        local_addr[sizeof(struct sockaddr_in6)];
    socklen_t           peer_addrlen,
                        local_addrlen;

    char                addr_str[2*(XQC_MAX_CID_LEN + INET6_ADDRSTRLEN) + 10];
    socklen_t           addr_str_len;

    /* server-side NAT rebinding candidate and validation state */
    xqc_path_rebinding_t rebinding;

    /* Path_state */
    xqc_path_state_t    path_state;
    unsigned char       path_challenge_data[XQC_PATH_CHALLENGE_DATA_LEN];

    xqc_path_flag_t     path_flag;

    /* application layer path status, sync via PATH_STATUS frame */
    xqc_app_path_status_t   app_path_status;
    xqc_app_path_status_t   next_app_path_state;
    uint64_t                app_path_status_send_seq_num;
    uint64_t                app_path_status_recv_seq_num;

    xqc_usec_t              last_app_path_status_changed_time;

    /* Path cc & ack tracking */
    xqc_send_ctl_t     *path_send_ctl;
    xqc_pn_ctl_t       *path_pn_ctl;

    /* lowest packet number sent on this path with the current key phase;
       0 on a path created after the last key update */
    xqc_packet_number_t path_ku_first_sent_pktno;
    /* lowest packet number received on this path with the current key
       phase, XQC_MAX_UINT64_VALUE until one arrives */
    xqc_packet_number_t path_ku_first_recv_pktno;


    /* path send buffer, used to store packets scheduled to this path */
    xqc_list_head_t     path_schedule_buf[XQC_SEND_TYPE_N];
    uint32_t            path_schedule_bytes;
    xqc_list_head_t     path_reinj_tmp_buf;

    /* related structs */
    xqc_connection_t   *parent_conn;
    xqc_list_head_t     path_list;

    /* Path_metrics */
    xqc_path_metrics_t  path_metrics;
    xqc_usec_t          path_create_time;
    xqc_usec_t          path_destroy_time;

    /* path backup mode */
    uint32_t            standby_probe_count;
    uint32_t            app_path_status_changed_count;

    /* PTMUD */
    size_t              curr_pkt_out_size;
    size_t              path_max_pkt_out_size;

    /* 
     * Record pkt receive timestamp info. Null if local 
     * conn_setting.extended_ack_features & XQC_ACK_EXT_FEATURE_BIT_RECV_TS == 0
     */
    xqc_recv_timestamps_info_t *recv_ts_info;
};

/* 埋点路径信息 */
/* 区别于xquic.h的xqc_path_metrics_t，填在conn_stat的conn_info字段里 */
typedef struct {
    uint64_t            path_id;
    uint8_t             path_state;
    uint8_t             app_path_status;

    uint64_t            path_bytes_send;
    uint64_t            path_bytes_recv;
    
    uint64_t            path_create_time;
    uint64_t            path_destroy_time;
    
    uint64_t            srtt;
    uint32_t            loss_cnt;
    uint32_t            tlp_cnt;
    uint32_t            pkt_send_cnt;
    uint32_t            pkt_recv_cnt;
    uint32_t            dgram_send_cnt;
    uint32_t            dgram_recv_cnt;
    uint32_t            red_dgram_send_cnt;
    uint32_t            red_dgram_recv_cnt;

    uint32_t            standby_probe_count;
    uint32_t            app_path_status_changed_count;    
} xqc_path_info_t;

xqc_bool_t xqc_is_same_addr(const struct sockaddr *sa1, const struct sockaddr *sa2);
xqc_bool_t xqc_is_same_ip(const struct sockaddr *sa1, const struct sockaddr *sa2);
xqc_bool_t xqc_is_same_addr_as_any_path(xqc_connection_t *conn, const struct sockaddr *peer_addr);

xqc_int_t xqc_generate_path_challenge_data(xqc_connection_t *conn, xqc_path_ctx_t *path);

xqc_int_t xqc_path_init(xqc_path_ctx_t *path, xqc_connection_t *conn);

/* check mp support */
xqc_multipath_mode_t xqc_conn_enable_multipath(xqc_connection_t *conn);

/* check multipath version negotiation */
xqc_multipath_version_t xqc_conn_multipath_version_negotiation(xqc_connection_t *conn);

/* init path_list & initial path for connection */
xqc_int_t xqc_conn_init_paths_list(xqc_connection_t *conn);

/* destroy all the paths of the connection */
void xqc_conn_destroy_paths_list(xqc_connection_t *conn);

/* Walk every path of the connection, the closed ones included: the paths on
 * conn_paths_list, then those on conn_closed_paths_list. The loop body must
 * not move or free the path it is on. */
xqc_path_ctx_t *xqc_conn_all_paths_first(xqc_connection_t *conn);
xqc_path_ctx_t *xqc_conn_all_paths_next(xqc_connection_t *conn, xqc_path_ctx_t *path);

void xqc_path_schedule_buf_destroy(xqc_path_ctx_t *path);
void xqc_path_schedule_buf_pre_destroy(xqc_send_queue_t *send_queue, xqc_path_ctx_t *path);

/* create path inner */
xqc_path_ctx_t *xqc_conn_create_path_inner(xqc_connection_t *conn, 
    xqc_cid_t *scid, xqc_cid_t *dcid, xqc_app_path_status_t path_status, uint64_t path_id);

/* server update client addr when recv path_challenge frame */
xqc_int_t xqc_conn_server_init_path_addr(xqc_connection_t *conn, uint64_t path_id,
    const struct sockaddr *local_addr, socklen_t local_addrlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen);

void xqc_path_rebinding_clear(xqc_path_ctx_t *path);
xqc_path_ctx_t *xqc_path_rebinding_find_by_challenge(xqc_connection_t *conn,
    const unsigned char *challenge_data);
xqc_int_t xqc_path_rebinding_on_authenticated_datagram(xqc_connection_t *conn,
    xqc_path_ctx_t *path, const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    size_t recv_bytes, xqc_usec_t now);
xqc_int_t xqc_path_rebinding_on_response(xqc_connection_t *conn,
    xqc_path_ctx_t *path, const unsigned char *challenge_data, xqc_usec_t now);
void xqc_path_rebinding_on_timeout(xqc_connection_t *conn, xqc_path_ctx_t *path,
    xqc_usec_t now);

xqc_int_t xqc_conn_client_init_path_addr(xqc_connection_t *conn);

void xqc_set_path_state(xqc_path_ctx_t *path, xqc_path_state_t state);

/* path state: "ACTIVE" -> "CLOSING" */
xqc_int_t xqc_path_immediate_close(xqc_path_ctx_t *path);

/* draft-21 §3.1 ¶6 / §3.1 ¶10: explicitly close a path due to a
 * validation MUST violation. Enqueues PATH_ABANDON (best-effort) and
 * transitions path_state to CLOSING. Idempotent for paths already
 * >= CLOSING. */
xqc_int_t xqc_path_request_abandon(xqc_path_ctx_t *path, uint64_t error_code);

/* path state: "ACTIVE/CLOSING/DRAINING" -> "CLOSED" */
xqc_int_t xqc_path_closed(xqc_path_ctx_t *path);

/* find path */
xqc_path_ctx_t *xqc_conn_find_path_by_path_id(xqc_connection_t *conn, uint64_t path_id);
xqc_path_ctx_t *xqc_conn_find_path_by_scid(xqc_connection_t *conn, xqc_cid_t *scid);

void xqc_path_send_buffer_append(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, xqc_list_head_t *head);
void xqc_path_send_buffer_remove(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out);
void xqc_path_send_buffer_clear(xqc_connection_t *conn, xqc_path_ctx_t *path, xqc_list_head_t *head, xqc_send_type_t send_type);

xqc_int_t xqc_set_application_path_status(xqc_path_ctx_t *path, xqc_app_path_status_t status, xqc_bool_t is_tx);

/* G-P14 (draft-21 §3.4 ¶3 RECOMMENDED): pick an open path other than
 * `exclude`, preferring AVAILABLE over STANDBY (lowest path_id within
 * each tier for deterministic selection). Open = path_state == ACTIVE
 * per draft-21 §3 state model (CLOSING / CLOSED / VALIDATING excluded).
 * Returns NULL if no candidate exists. Used by PATH_ABANDON emission
 * to send the frame on an alt open path. */
xqc_path_ctx_t *xqc_conn_pick_alt_active_path(xqc_connection_t *conn, xqc_path_ctx_t *exclude);

/* path statistics */
void xqc_conn_path_metrics_print(xqc_connection_t *conn, xqc_conn_stats_t *stats);
void xqc_request_path_metrics_print(xqc_connection_t *conn, xqc_h3_stream_t *h3_stream, xqc_request_stats_t *stats);

void xqc_stream_path_metrics_print(xqc_connection_t *conn, xqc_stream_t *stream, char *buff, size_t buff_size);
void xqc_stream_path_metrics_on_send(xqc_connection_t *conn, xqc_packet_out_t *po);
void xqc_stream_path_metrics_on_recv(xqc_connection_t *conn, xqc_stream_t *stream, xqc_packet_in_t *pi);

xqc_msec_t xqc_path_get_idle_timeout(xqc_path_ctx_t *path);

xqc_usec_t xqc_path_get_validation_timeout(xqc_path_ctx_t *path);

void xqc_path_validate(xqc_path_ctx_t *path);

xqc_int_t xqc_conn_is_current_mp_version_supported(xqc_multipath_version_t mp_version);

/* draft-21 §3.1.1: receivers MUST treat path_id > local_max_path_id as
 * PROTOCOL_VIOLATION. Returns XQC_OK on accept, -TRA_PROTOCOL_VIOLATION
 * on reject (caller logs + XQC_CONN_ERR before propagating). */
xqc_int_t xqc_validate_recv_path_id(xqc_connection_t *conn, uint64_t path_id);

/* draft-21 §4.6: MAX_PATH_ID validation outcome. Pure (no side effects);
 * caller is responsible for state updates / error reporting. */
typedef enum {
    XQC_MAX_PATH_ID_ACCEPT       = 0,   /* value > remote_max_path_id, growth */
    XQC_MAX_PATH_ID_IGNORE_STALE = 1,   /* value <= remote_max_path_id        */
    XQC_MAX_PATH_ID_BAD_TOO_LARGE = 2,  /* value > 2^32-1 -> VIOLATION        */
    XQC_MAX_PATH_ID_BAD_BELOW_INIT = 3, /* value < remote initial -> VIOLATION */
} xqc_max_path_id_validation_t;

xqc_max_path_id_validation_t xqc_validate_max_path_id(xqc_connection_t *conn,
                                                      uint64_t value);

/* Raise curr_max_path_id to the lower of local_max_path_id and
 * remote_max_path_id after either grew, adding the connection ID sets of
 * the path IDs this makes usable. Returns -XQC_EMALLOC, curr_max_path_id
 * unchanged, when a set cannot be allocated. */
xqc_int_t xqc_conn_update_curr_max_path_id(xqc_connection_t *conn);

/* draft-21 §3.2.1 / §4.6 mp21 L2 — MAX_PATH_ID credit grant.
 * Increment applied per grant when granting auto-credit on PATHS_BLOCKED
 * receipt. Magnitude is implementation-defined (spec unspec); chosen to
 * give peer ~8 fresh paths per grant which matches typical XQC_MAX_PATHS
 * deployments. */
#define XQC_MAX_PATH_ID_GRANT_INCREMENT  8

/* Bound on the reciprocal MAX_PATH_ID grant when
 * max_path_id_grant_max_value is unset. Matches the grant bound mqvpn
 * servers set, so a client mirroring a server's grant is not limited. */
#define XQC_MAX_PATH_ID_MIRROR_DEFAULT   128

/* Evaluate whether a MAX_PATH_ID credit grant should fire on receipt of
 * PATHS_BLOCKED. Side-effects: when the grant fires, advances
 * conn->local_max_path_id, then curr_max_path_id with the connection ID
 * sets of the path IDs granted (xqc_conn_update_curr_max_path_id), and
 * updates conn->last_max_path_id_grant_us.
 * Returns the new local_max_path_id to emit (>0) or 0 when no grant
 * fires (disabled, at cap, rate-limited, initial path missing PTO, or
 * the connection ID sets cannot be allocated).
 *
 * Caller is responsible for emitting the MAX_PATH_ID frame when the
 * return value is non-zero. Splitting state mutation from emission lets
 * tests exercise the gate without a fully-wired send queue. */
uint64_t xqc_try_grant_max_path_id(xqc_connection_t *conn);

/* draft-21 §3.1: zero-length CIDs are forbidden once multipath is
 * negotiated — packets are demultiplexed by DCID across paths, so a
 * zero-length CID would collapse the per-path identity. Returns XQC_OK
 * when both scid_len and dcid_len are non-zero, -TRA_PROTOCOL_VIOLATION
 * otherwise. */
xqc_int_t xqc_validate_mp_cid_lengths(uint8_t scid_len, uint8_t dcid_len);

/* draft-21 §4.5 abandoned-path bookkeeping. Bitmap is sized to 256 ids;
 * path_id values outside that range are clamped (treated as not abandoned)
 * — the validate_recv_path_id helper has already enforced the cap. */
void      xqc_conn_mark_path_abandoned(xqc_connection_t *conn, uint64_t path_id);
xqc_bool_t xqc_conn_is_path_abandoned(xqc_connection_t *conn, uint64_t path_id);

xqc_bool_t xqc_path_is_initial_path(xqc_path_ctx_t *path);

void xqc_path_record_info(xqc_path_ctx_t *path, xqc_path_info_t *path_info);

xqc_bool_t xqc_path_is_full(xqc_path_ctx_t *path);

xqc_int_t xqc_path_standby_probe(xqc_path_ctx_t *path);

/* consecutive PTOs after which a path's unacknowledged data is sent again
 * on the other paths (xqc_path_requeue_unacked_on_pto) */
#define XQC_PATH_REQUEUE_PTO_THRESH 3

void xqc_path_requeue_unacked_on_pto(xqc_path_ctx_t *path);

xqc_bool_t xqc_path_has_working_alternative(xqc_path_ctx_t *path);

xqc_bool_t xqc_path_is_dead_with_alternative(xqc_path_ctx_t *path);

xqc_path_perf_class_t xqc_path_get_perf_class(xqc_path_ctx_t *path);

double xqc_path_recent_loss_rate(xqc_path_ctx_t *path);

double xqc_conn_recent_loss_rate(xqc_connection_t *conn);

#endif /* XQC_MULTIPATH_H */

