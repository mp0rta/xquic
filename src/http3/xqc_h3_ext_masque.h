/**
 * MASQUE protocol helpers for HTTP/3 Extended CONNECT.
 *
 * Provides:
 *   - HTTP Datagram framing (RFC 9297 + RFC 9298)
 *   - Capsule Protocol codec (RFC 9297 Section 3.2)
 *   - CONNECT-IP capsule types (RFC 9484)
 *
 * All functions are stateless (buffer-in, buffer-out) and do not depend on
 * connection or path objects, making them safe for use with multipath QUIC.
 */

#ifndef _XQC_H3_EXT_MASQUE_H_INCLUDED_
#define _XQC_H3_EXT_MASQUE_H_INCLUDED_

#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>

/* ── Capsule type constants (RFC 9297 / RFC 9484) ── */

#define XQC_H3_CAPSULE_DATAGRAM              0x00
#define XQC_H3_CAPSULE_ADDRESS_ASSIGN        0x01
#define XQC_H3_CAPSULE_ADDRESS_REQUEST       0x02
#define XQC_H3_CAPSULE_ROUTE_ADVERTISEMENT   0x03


/* ── HTTP Datagram framing (RFC 9297 + RFC 9298) ── */

/**
 * Frame a UDP payload into an HTTP Datagram buffer.
 *
 * Prepends [Quarter-Stream-ID : varint][Context-ID=0 : varint] to the payload.
 * Quarter-Stream-ID = stream_id / 4 (RFC 9297).
 *
 * @param out        output buffer
 * @param outlen     output buffer capacity
 * @param written    [out] total bytes written (0 on error)
 * @param stream_id  QUIC stream ID of the H3 request
 * @param payload    raw UDP/IP payload (may be NULL if paylen == 0)
 * @param paylen     length of the payload
 * @return XQC_OK on success, negative error code on failure
 */
xqc_int_t xqc_h3_ext_masque_frame_udp(
    uint8_t *out, size_t outlen, size_t *written,
    uint64_t stream_id, const uint8_t *payload, size_t paylen);

/**
 * Unframe an HTTP Datagram received via QUIC DATAGRAM.
 *
 * Parses [Quarter-Stream-ID][Context-ID] and returns a pointer to the payload.
 *
 * @param buf                received datagram buffer
 * @param buflen             length of the buffer
 * @param quarter_stream_id  [out] decoded quarter-stream-ID
 * @param context_id         [out] decoded context ID
 * @param payload            [out] pointer to the payload within buf
 * @param payload_len        [out] length of the payload
 * @return XQC_OK on success, negative error code on failure
 */
xqc_int_t xqc_h3_ext_masque_unframe_udp(
    const uint8_t *buf, size_t buflen,
    uint64_t *quarter_stream_id, uint64_t *context_id,
    const uint8_t **payload, size_t *payload_len);

/**
 * Calculate the maximum UDP/IP payload size for a single HTTP Datagram.
 *
 * @param dgram_mss  the MSS from xqc_h3_ext_datagram_get_mss()
 * @param stream_id  the QUIC stream ID of the H3 request
 * @return maximum payload size, or 0 if MSS is too small
 */
size_t xqc_h3_ext_masque_udp_mss(size_t dgram_mss, uint64_t stream_id);


/* ── Capsule Protocol (RFC 9297 Section 3.2) ── */

/**
 * Encode a capsule: [Type : varint][Length : varint][Payload].
 *
 * @param out      output buffer
 * @param outlen   output buffer capacity
 * @param written  [out] total bytes written
 * @param type     capsule type
 * @param payload  capsule value (may be NULL if paylen == 0)
 * @param paylen   length of the capsule value
 * @return XQC_OK on success, negative error code on failure
 */
xqc_int_t xqc_h3_ext_capsule_encode(
    uint8_t *out, size_t outlen, size_t *written,
    uint64_t type, const uint8_t *payload, size_t paylen);

/**
 * Decode a capsule header and return a pointer to the payload.
 *
 * Caller must verify that the buffer contains at least bytes_consumed bytes
 * of valid data (payload may extend beyond a truncated buffer).
 *
 * @param buf            input buffer
 * @param buflen         length of the input buffer
 * @param type           [out] capsule type
 * @param payload        [out] pointer to capsule value within buf
 * @param payload_len    [out] declared length of capsule value
 * @param bytes_consumed [out] total capsule size (header + payload_len)
 * @return XQC_OK on success, negative error code on failure
 */
xqc_int_t xqc_h3_ext_capsule_decode(
    const uint8_t *buf, size_t buflen,
    uint64_t *type, const uint8_t **payload, size_t *payload_len,
    size_t *bytes_consumed);


/* ── CONNECT-IP capsule types (RFC 9484) ── */

/**
 * Parse an ADDRESS_ASSIGN capsule payload (RFC 9484 Section 4.7.1).
 *
 * Payload: [Request ID : varint][IP Version : 1][IP Addr : 4/16][Prefix : 1]
 *
 * @param payload      capsule payload (NOT the full capsule)
 * @param paylen       payload length
 * @param request_id   [out] request identifier
 * @param ip_version   [out] 4 or 6
 * @param ip_addr      [out] IP address (4 or 16 bytes)
 * @param ip_addr_len  [out] 4 (IPv4) or 16 (IPv6)
 * @param prefix_len   [out] prefix length
 * @return XQC_OK on success, negative error code on failure
 */
xqc_int_t xqc_h3_ext_connectip_parse_address_assign(
    const uint8_t *payload, size_t paylen,
    uint64_t *request_id, uint8_t *ip_version,
    uint8_t *ip_addr, size_t *ip_addr_len, uint8_t *prefix_len,
    size_t *bytes_consumed);

/**
 * Build an ADDRESS_REQUEST capsule payload (RFC 9484 Section 4.7.2).
 *
 * Same wire format as ADDRESS_ASSIGN.
 * To request any IPv4 address: ip_addr={0,0,0,0}, prefix_len=0.
 *
 * @param buf          output buffer for the payload (NOT the full capsule)
 * @param buflen       output buffer capacity
 * @param written      [out] payload bytes written
 * @param request_id   unique request identifier
 * @param ip_version   4 or 6
 * @param ip_addr      preferred IP address (or all-zeros for any)
 * @param prefix_len   requested prefix length
 * @return XQC_OK on success, negative error code on failure
 */
xqc_int_t xqc_h3_ext_connectip_build_address_request(
    uint8_t *buf, size_t buflen, size_t *written,
    uint64_t request_id, uint8_t ip_version,
    const uint8_t *ip_addr, uint8_t prefix_len);

/**
 * Parse a single ROUTE_ADVERTISEMENT entry (RFC 9484 Section 4.7.3).
 *
 * Entry: [IP Version : 1][Start IP : 4/16][End IP : 4/16][Protocol : 1]
 * Call in a loop, advancing by bytes_consumed each iteration.
 *
 * @param payload        input buffer (at current parse position)
 * @param paylen         remaining bytes
 * @param ip_version     [out] 4 or 6
 * @param start_ip       [out] start of IP range (4 or 16 bytes)
 * @param end_ip         [out] end of IP range (4 or 16 bytes)
 * @param ip_addr_len    [out] 4 or 16
 * @param ip_protocol    [out] IP protocol number (0 = all)
 * @param bytes_consumed [out] bytes consumed for this entry
 * @return XQC_OK on success, negative error code on failure
 */
xqc_int_t xqc_h3_ext_connectip_parse_route_advertisement(
    const uint8_t *payload, size_t paylen,
    uint8_t *ip_version, uint8_t *start_ip, uint8_t *end_ip,
    size_t *ip_addr_len, uint8_t *ip_protocol, size_t *bytes_consumed);

/**
 * Validate IP packet version and minimum header length (RFC 9484 Section 4.6).
 */
xqc_int_t xqc_h3_ext_masque_validate_ip_packet(
    const uint8_t *payload, size_t payload_len);

/**
 * Validate a full ROUTE_ADVERTISEMENT capsule payload (RFC 9484 §4.7.3).
 * Verifies ordering (IP version ASC, protocol ASC) and non-overlapping ranges.
 *
 * @param payload  capsule payload (sequence of ROUTE_ADVERTISEMENT entries)
 * @param paylen   payload length (0 is valid = no routes)
 * @return XQC_OK if valid, -XQC_EPARAM if malformed or misordered
 */
xqc_int_t xqc_h3_ext_connectip_validate_route_advertisement(
    const uint8_t *payload, size_t paylen);

/**
 * Check that IPv6 tunnel MTU meets the minimum of 1280 (RFC 9484 §7.2).
 *
 * @param tunnel_mtu  the effective MTU of the IP tunnel
 * @return XQC_OK if >= 1280, -XQC_EPARAM otherwise
 */
xqc_int_t xqc_h3_ext_masque_check_ipv6_mtu(size_t tunnel_mtu);

#endif /* _XQC_H3_EXT_MASQUE_H_INCLUDED_ */
