/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_FRAME_H_INCLUDED_
#define _XQC_FRAME_H_INCLUDED_

#include <xquic/xquic_typedef.h>

/*
 * draft-smith-quic-receive-ts-01: 
 *   enable ECN counts (if bit 0 is set in Features)
 *   enable Receive Timestamps (if bit 1 is set in Features)
 */
#define XQC_ACK_EXT_FEATURE_BIT_ENC_COUNT 1
#define XQC_ACK_EXT_FEATURE_BIT_RECV_TS   2

typedef enum {
    XQC_FRAME_PADDING,
    XQC_FRAME_PING,
    XQC_FRAME_ACK,
    XQC_FRAME_RESET_STREAM,
    XQC_FRAME_STOP_SENDING,
    XQC_FRAME_CRYPTO,
    XQC_FRAME_NEW_TOKEN,
    XQC_FRAME_STREAM,
    XQC_FRAME_MAX_DATA,
    XQC_FRAME_MAX_STREAM_DATA,
    XQC_FRAME_MAX_STREAMS,
    XQC_FRAME_DATA_BLOCKED,
    XQC_FRAME_STREAM_DATA_BLOCKED,
    XQC_FRAME_STREAMS_BLOCKED,
    XQC_FRAME_NEW_CONNECTION_ID,
    XQC_FRAME_RETIRE_CONNECTION_ID,
    XQC_FRAME_PATH_CHALLENGE,
    XQC_FRAME_PATH_RESPONSE,
    XQC_FRAME_CONNECTION_CLOSE,
    XQC_FRAME_HANDSHAKE_DONE,
    XQC_FRAME_ACK_MP,
    XQC_FRAME_PATH_ABANDON,
    XQC_FRAME_PATH_STATUS,
    XQC_FRAME_PATH_STANDBY,
    XQC_FRAME_PATH_AVAILABLE,
    XQC_FRAME_MP_NEW_CONNECTION_ID,
    XQC_FRAME_MP_RETIRE_CONNECTION_ID,
    XQC_FRAME_MAX_PATH_ID,
    XQC_FRAME_PATH_FROZEN,
    XQC_FRAME_DATAGRAM,
    XQC_FRAME_Extension,
    XQC_FRAME_SID,
    XQC_FRAME_REPAIR_SYMBOL,
    XQC_FRAME_PATHS_BLOCKED,
    XQC_FRAME_NUM,
} xqc_frame_type_t;

/* xqc_frame_type_bit_t holds bit values up to XQC_FRAME_NUM (= 33).
 * Per C11 6.7.2.2 ¶3, enum constants must be representable as int — bits
 * at shift 31+ silently truncate to 0 (or sign-flip) on MSVC, dropping
 * SID, REPAIR_SYMBOL, NUM. This breaks frame-bit checks like
 * XQC_IS_ACK_ELICITING for FEC frames on Windows builds. Use uint64_t
 * typedef + #define for portability across compilers. Same pattern as
 * xqc_conn_flag_t in xqc_conn.h. */
typedef uint64_t xqc_frame_type_bit_t;

#define XQC_FRAME_BIT_PADDING                 ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PADDING)
#define XQC_FRAME_BIT_PING                    ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PING)
#define XQC_FRAME_BIT_ACK                     ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_ACK)
#define XQC_FRAME_BIT_RESET_STREAM            ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_RESET_STREAM)
#define XQC_FRAME_BIT_STOP_SENDING            ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_STOP_SENDING)
#define XQC_FRAME_BIT_CRYPTO                  ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_CRYPTO)
#define XQC_FRAME_BIT_NEW_TOKEN               ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_NEW_TOKEN)
#define XQC_FRAME_BIT_STREAM                  ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_STREAM)
#define XQC_FRAME_BIT_MAX_DATA                ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_MAX_DATA)
#define XQC_FRAME_BIT_MAX_STREAM_DATA         ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_MAX_STREAM_DATA)
#define XQC_FRAME_BIT_MAX_STREAMS             ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_MAX_STREAMS)
#define XQC_FRAME_BIT_DATA_BLOCKED            ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_DATA_BLOCKED)
#define XQC_FRAME_BIT_STREAM_DATA_BLOCKED     ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_STREAM_DATA_BLOCKED)
#define XQC_FRAME_BIT_STREAMS_BLOCKED         ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_STREAMS_BLOCKED)
#define XQC_FRAME_BIT_NEW_CONNECTION_ID       ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_NEW_CONNECTION_ID)
#define XQC_FRAME_BIT_RETIRE_CONNECTION_ID    ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_RETIRE_CONNECTION_ID)
#define XQC_FRAME_BIT_PATH_CHALLENGE          ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATH_CHALLENGE)
#define XQC_FRAME_BIT_PATH_RESPONSE           ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATH_RESPONSE)
#define XQC_FRAME_BIT_CONNECTION_CLOSE        ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_CONNECTION_CLOSE)
#define XQC_FRAME_BIT_HANDSHAKE_DONE          ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_HANDSHAKE_DONE)
#define XQC_FRAME_BIT_ACK_MP                  ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_ACK_MP)
#define XQC_FRAME_BIT_PATH_ABANDON            ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATH_ABANDON)
#define XQC_FRAME_BIT_PATH_STATUS             ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATH_STATUS)
#define XQC_FRAME_BIT_PATH_STANDBY            ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATH_STANDBY)
#define XQC_FRAME_BIT_PATH_AVAILABLE          ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATH_AVAILABLE)
#define XQC_FRAME_BIT_MP_NEW_CONNECTION_ID    ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_MP_NEW_CONNECTION_ID)
#define XQC_FRAME_BIT_MP_RETIRE_CONNECTION_ID ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_MP_RETIRE_CONNECTION_ID)
#define XQC_FRAME_BIT_MAX_PATH_ID             ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_MAX_PATH_ID)
#define XQC_FRAME_BIT_PATH_FROZEN             ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATH_FROZEN)
#define XQC_FRAME_BIT_DATAGRAM                ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_DATAGRAM)
#define XQC_FRAME_BIT_Extension               ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_Extension)
#define XQC_FRAME_BIT_SID                     ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_SID)
#define XQC_FRAME_BIT_REPAIR_SYMBOL           ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_REPAIR_SYMBOL)
#define XQC_FRAME_BIT_PATHS_BLOCKED           ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATHS_BLOCKED)
#define XQC_FRAME_BIT_NUM                     ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_NUM)

/* Compile-time guards: regression here would silently break Windows FEC. */
_Static_assert(sizeof(xqc_frame_type_bit_t) == 8,
               "xqc_frame_type_bit_t must be 64-bit (MSVC truncates plain enum to int)");
_Static_assert(XQC_FRAME_BIT_SID == ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_SID),
               "XQC_FRAME_BIT_SID shift must survive bit-31 boundary");
_Static_assert(XQC_FRAME_BIT_REPAIR_SYMBOL == ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_REPAIR_SYMBOL),
               "XQC_FRAME_BIT_REPAIR_SYMBOL must be bit 32 (above INT_MAX)");
_Static_assert(XQC_FRAME_BIT_NUM == ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_NUM),
               "XQC_FRAME_BIT_NUM must be bit XQC_FRAME_NUM (= 33)");

/* draft-ietf-quic-multipath-21 frame bits (G-C3): pin each MP frame bit
 * to its enum constant so a stray enum reorder cannot silently shift the
 * bitmap. Loss-detection / ack-eliciting / can-in-flight macros all rely
 * on these bits; a shifted bit would drop the frame from retransmit /
 * cwnd accounting on Windows builds (where plain enum truncates) — same
 * failure mode the SID/REPAIR_SYMBOL asserts above protect against. */
_Static_assert(XQC_FRAME_BIT_ACK_MP == ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_ACK_MP),
               "XQC_FRAME_BIT_ACK_MP shift must match enum value");
_Static_assert(XQC_FRAME_BIT_PATH_ABANDON == ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATH_ABANDON),
               "XQC_FRAME_BIT_PATH_ABANDON shift must match enum value");
_Static_assert(XQC_FRAME_BIT_PATH_STATUS == ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATH_STATUS),
               "XQC_FRAME_BIT_PATH_STATUS shift must match enum value");
_Static_assert(XQC_FRAME_BIT_PATH_STANDBY == ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATH_STANDBY),
               "XQC_FRAME_BIT_PATH_STANDBY shift must match enum value");
_Static_assert(XQC_FRAME_BIT_PATH_AVAILABLE == ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATH_AVAILABLE),
               "XQC_FRAME_BIT_PATH_AVAILABLE shift must match enum value");
_Static_assert(XQC_FRAME_BIT_MP_NEW_CONNECTION_ID == ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_MP_NEW_CONNECTION_ID),
               "XQC_FRAME_BIT_MP_NEW_CONNECTION_ID shift must match enum value");
_Static_assert(XQC_FRAME_BIT_MP_RETIRE_CONNECTION_ID == ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_MP_RETIRE_CONNECTION_ID),
               "XQC_FRAME_BIT_MP_RETIRE_CONNECTION_ID shift must match enum value");
_Static_assert(XQC_FRAME_BIT_MAX_PATH_ID == ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_MAX_PATH_ID),
               "XQC_FRAME_BIT_MAX_PATH_ID shift must match enum value");
_Static_assert(XQC_FRAME_BIT_PATH_FROZEN == ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATH_FROZEN),
               "XQC_FRAME_BIT_PATH_FROZEN shift must match enum value");
/* draft-21 §4.7 PATHS_BLOCKED (G-P16, PR8 L5e): pin bitmap shift. MSVC
 * enum truncation would silently zero this bit if it lands above INT_MAX
 * (PATHS_BLOCKED is the highest pre-NUM ordinal); this guards against
 * that and against an enum reorder desyncing the bit value from the
 * shift expression. The matching frame-type-codepoint assert lives in
 * xqc_frame_parser.c (where XQC_TRANS_FRAME_TYPE_PATHS_BLOCKED is in
 * scope) so xqc_frame.h doesn't have to pull xqc_frame_parser.h. */
_Static_assert(XQC_FRAME_BIT_PATHS_BLOCKED == ((xqc_frame_type_bit_t)1ULL << XQC_FRAME_PATHS_BLOCKED),
               "XQC_FRAME_BIT_PATHS_BLOCKED shift must match enum value");
/* Enum ordering pin: MP frame ordinals must stay contiguous and within
 * INT_MAX (bit 31) so plain-int enum compilers don't truncate. If a new
 * MP frame is inserted above ACK_MP, both these asserts and the bit-31
 * boundary guards (above) need re-examination. */
_Static_assert(XQC_FRAME_ACK_MP < 31,
               "MP frame ordinals must remain below bit-31 boundary");
_Static_assert(XQC_FRAME_PATH_FROZEN < 31,
               "MP frame ordinals must remain below bit-31 boundary");


/*
 * Ack-eliciting Packet:  A QUIC packet that contains frames other than
      ACK, PADDING, and CONNECTION_CLOSE.  These cause a recipient to
      send an acknowledgment

      Connection close signals, including packets that contain
      CONNECTION_CLOSE frames, are not sent again when packet loss is
      detected, but as described in Section 10.
 */
#define XQC_IS_ACK_ELICITING(types) ((types) & ~(XQC_FRAME_BIT_ACK | XQC_FRAME_BIT_ACK_MP| XQC_FRAME_BIT_PADDING | XQC_FRAME_BIT_CONNECTION_CLOSE))

/*
 * https://tools.ietf.org/html/draft-ietf-quic-recovery-24#section-3
 * Packets containing frames besides ACK or CONNECTION_CLOSE frames
      count toward congestion control limits and are considered in-
      flight.

   PADDING frames cause packets to contribute toward bytes in flight
      without directly causing an acknowledgment to be sent.
 */
#define XQC_CAN_IN_FLIGHT(types) ((types) & ~(XQC_FRAME_BIT_ACK | XQC_FRAME_BIT_ACK_MP | XQC_FRAME_BIT_CONNECTION_CLOSE))


/*
 * PING and PADDING frames contain no information, so lost PING or
 *     PADDING frames do not require repair
 */
#define XQC_NEED_REPAIR(types) ((types) & ~(XQC_FRAME_BIT_ACK| XQC_FRAME_BIT_PADDING | XQC_FRAME_BIT_PING | XQC_FRAME_BIT_CONNECTION_CLOSE | XQC_FRAME_BIT_DATAGRAM | XQC_FRAME_BIT_SID | XQC_FRAME_BIT_REPAIR_SYMBOL))


const char *xqc_frame_type_2_str(xqc_engine_t *engine, xqc_frame_type_bit_t type_bit);

unsigned int xqc_stream_frame_header_size(xqc_stream_id_t stream_id, uint64_t offset, size_t length);

unsigned int xqc_crypto_frame_header_size(uint64_t offset, size_t length);

xqc_int_t xqc_insert_stream_frame(xqc_connection_t *conn, xqc_stream_t *stream, xqc_stream_frame_t *new_frame);

xqc_int_t xqc_process_frames(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_padding_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_stream_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_crypto_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_ack_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

/* draft-smith-quic-receive-ts-01: QUIC Extended Acknowledgement for Reporting Packet Receive Timestamps */
xqc_int_t xqc_process_ack_ext_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_ping_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_new_conn_id_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_retire_conn_id_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_conn_close_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_reset_stream_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_stop_sending_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_data_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_stream_data_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_streams_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_max_data_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_max_stream_data_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_max_streams_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_new_token_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_handshake_done_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_path_challenge_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_path_response_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_ack_mp_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_path_ack_ecn_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_path_abandon_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_path_status_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_datagram_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_sid_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_repair_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_mp_new_conn_id_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_mp_retire_conn_id_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_max_path_id_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_paths_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

xqc_int_t xqc_process_path_cids_blocked_frame(xqc_connection_t *conn, xqc_packet_in_t *packet_in);

#endif /* _XQC_FRAME_H_INCLUDED_ */
