/**
 * MASQUE common utilities for CONNECT-UDP / CONNECT-IP test clients.
 *
 * This header is a compatibility wrapper around the xquic library's
 * MASQUE API (src/http3/xqc_h3_ext_masque.h).  It provides the original
 * masque_* function names so that existing test code continues to compile.
 *
 * IP checksum and ICMP echo helpers remain here (test-only utilities).
 */

#ifndef MASQUE_COMMON_H
#define MASQUE_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "src/http3/xqc_h3_ext_masque.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

/* ──────────────────────────────────────────────────────────── */
/*  Varint helpers (thin wrappers around xquic's varint API)    */
/* ──────────────────────────────────────────────────────────── */

static inline size_t
masque_varint_len(uint64_t value)
{
    return xqc_put_varint_len(value);
}

static inline size_t
masque_varint_encode(uint8_t *buf, size_t buflen, uint64_t value)
{
    size_t len = xqc_put_varint_len(value);
    if (buflen < len) {
        return 0;
    }
    xqc_put_varint(buf, value);
    return len;
}

static inline size_t
masque_varint_decode(const uint8_t *buf, size_t buflen, uint64_t *value)
{
    if (buflen == 0) {
        return 0;
    }
    int n = xqc_vint_read(buf, buf + buflen, value);
    if (n < 0) {
        return 0;
    }
    return (size_t)n;
}

/* ──────────────────────────────────────────────────────────── */
/*  HTTP Datagram framing wrappers                              */
/* ──────────────────────────────────────────────────────────── */

static inline size_t
masque_frame_udp_datagram(uint8_t *out, size_t outlen,
                          uint64_t stream_id,
                          const uint8_t *payload, size_t paylen)
{
    size_t written = 0;
    xqc_int_t rc = xqc_h3_ext_masque_frame_udp(
        out, outlen, &written, stream_id, payload, paylen);
    return rc == XQC_OK ? written : 0;
}

static inline int
masque_unframe_udp_datagram(const uint8_t *buf, size_t buflen,
                            uint64_t *quarter_stream_id, uint64_t *context_id,
                            size_t *payload_offset, size_t *payload_len)
{
    const uint8_t *payload_ptr = NULL;
    xqc_int_t rc = xqc_h3_ext_masque_unframe_udp(
        buf, buflen, quarter_stream_id, context_id,
        &payload_ptr, payload_len);
    if (rc != XQC_OK) {
        return -1;
    }
    *payload_offset = (size_t)(payload_ptr - buf);
    return 0;
}

static inline size_t
masque_udp_mss(size_t mss, uint64_t stream_id)
{
    return xqc_h3_ext_masque_udp_mss(mss, stream_id);
}

/* ──────────────────────────────────────────────────────────── */
/*  Capsule Protocol wrappers                                   */
/* ──────────────────────────────────────────────────────────── */

#define MASQUE_CAPSULE_DATAGRAM             XQC_H3_CAPSULE_DATAGRAM
#define MASQUE_CAPSULE_ADDRESS_ASSIGN       XQC_H3_CAPSULE_ADDRESS_ASSIGN
#define MASQUE_CAPSULE_ADDRESS_REQUEST      XQC_H3_CAPSULE_ADDRESS_REQUEST
#define MASQUE_CAPSULE_ROUTE_ADVERTISEMENT  XQC_H3_CAPSULE_ROUTE_ADVERTISEMENT

static inline size_t
masque_capsule_encode(uint8_t *out, size_t outlen,
                      uint64_t type,
                      const uint8_t *payload, size_t paylen)
{
    size_t written = 0;
    xqc_int_t rc = xqc_h3_ext_capsule_encode(
        out, outlen, &written, type, payload, paylen);
    return rc == XQC_OK ? written : 0;
}

static inline int
masque_capsule_decode(const uint8_t *buf, size_t buflen,
                      uint64_t *type,
                      size_t *payload_offset, size_t *payload_len)
{
    const uint8_t *payload_ptr = NULL;
    size_t bytes_consumed = 0;
    xqc_int_t rc = xqc_h3_ext_capsule_decode(
        buf, buflen, type, &payload_ptr, payload_len, &bytes_consumed);
    if (rc != XQC_OK) {
        return -1;
    }
    *payload_offset = (size_t)(payload_ptr - buf);
    return 0;
}

/* ──────────────────────────────────────────────────────────── */
/*  CONNECT-IP capsule wrappers                                 */
/* ──────────────────────────────────────────────────────────── */

static inline int
masque_parse_address_assign(const uint8_t *payload, size_t paylen,
                            uint64_t *request_id,
                            uint8_t *ip_version,
                            uint8_t *ip_addr, size_t *ip_addr_len,
                            uint8_t *prefix_len)
{
    size_t consumed = 0;
    xqc_int_t rc = xqc_h3_ext_connectip_parse_address_assign(
        payload, paylen, request_id, ip_version,
        ip_addr, ip_addr_len, prefix_len, &consumed);
    return rc == XQC_OK ? 0 : -1;
}

static inline size_t
masque_build_address_request(uint8_t *buf, size_t buflen,
                              uint64_t request_id, uint8_t ip_version,
                              const uint8_t *ip_addr, uint8_t prefix_len)
{
    size_t written = 0;
    xqc_int_t rc = xqc_h3_ext_connectip_build_address_request(
        buf, buflen, &written, request_id, ip_version, ip_addr, prefix_len);
    return rc == XQC_OK ? written : 0;
}

static inline int
masque_parse_route_advertisement(const uint8_t *payload, size_t paylen,
                                  uint8_t *ip_version,
                                  uint8_t *start_ip, uint8_t *end_ip,
                                  size_t *ip_addr_len, uint8_t *ip_protocol,
                                  size_t *bytes_consumed)
{
    xqc_int_t rc = xqc_h3_ext_connectip_parse_route_advertisement(
        payload, paylen, ip_version, start_ip, end_ip,
        ip_addr_len, ip_protocol, bytes_consumed);
    return rc == XQC_OK ? 0 : -1;
}

/* ──────────────────────────────────────────────────────────── */
/*  Test-only utilities (NOT in the library)                    */
/* ──────────────────────────────────────────────────────────── */

/**
 * IPv4 header / ICMP checksum (RFC 1071).
 * Computes the ones' complement of the ones' complement sum.
 */
static inline uint16_t
masque_ip_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint16_t)data[i] << 8) | data[i + 1];
    }
    if (len & 1) {
        sum += (uint16_t)data[len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/**
 * Build a minimal IPv4 ICMP Echo Request packet.
 * Returns the total packet length (32), or 0 on error.
 */
static inline size_t
masque_build_icmp_echo(uint8_t *buf, size_t buflen,
                       const uint8_t src_ip[4], const uint8_t dst_ip[4])
{
    const size_t ip_hdr_len = 20;
    const size_t icmp_len = 12;  /* 8 header + 4 data */
    const size_t total = ip_hdr_len + icmp_len;

    if (buflen < total) {
        return 0;
    }
    memset(buf, 0, total);

    /* IPv4 header */
    buf[0] = 0x45;              /* Version=4, IHL=5 (20 bytes) */
    buf[1] = 0x00;              /* DSCP/ECN */
    buf[2] = (uint8_t)(total >> 8);
    buf[3] = (uint8_t)(total & 0xFF);
    buf[4] = 0x00; buf[5] = 0x01; /* Identification */
    buf[6] = 0x00; buf[7] = 0x00; /* Flags + Fragment Offset */
    buf[8] = 64;                /* TTL */
    buf[9] = 1;                 /* Protocol: ICMP */
    memcpy(buf + 12, src_ip, 4);
    memcpy(buf + 16, dst_ip, 4);

    uint16_t ip_cksum = masque_ip_checksum(buf, ip_hdr_len);
    buf[10] = (uint8_t)(ip_cksum >> 8);
    buf[11] = (uint8_t)(ip_cksum & 0xFF);

    /* ICMP Echo Request */
    uint8_t *icmp = buf + ip_hdr_len;
    icmp[0] = 8;                /* Type: Echo Request */
    icmp[1] = 0;                /* Code */
    icmp[4] = 0x00; icmp[5] = 0x01; /* Identifier */
    icmp[6] = 0x00; icmp[7] = 0x01; /* Sequence Number */
    icmp[8] = 'T'; icmp[9] = 'E'; icmp[10] = 'S'; icmp[11] = 'T';

    uint16_t icmp_cksum = masque_ip_checksum(icmp, icmp_len);
    icmp[2] = (uint8_t)(icmp_cksum >> 8);
    icmp[3] = (uint8_t)(icmp_cksum & 0xFF);

    return total;
}

#endif /* MASQUE_COMMON_H */
