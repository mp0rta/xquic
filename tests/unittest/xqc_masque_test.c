/**
 * Unit tests for MASQUE common utilities (masque_common.h).
 * Tests varint encoding/decoding, HTTP Datagram framing, and MSS calculation.
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include "tests/masque_common.h"

/* ── Varint encode/decode round-trip ── */

static void
test_varint_len(void)
{
    /* 1-byte: 0..63 */
    CU_ASSERT_EQUAL(masque_varint_len(0), 1);
    CU_ASSERT_EQUAL(masque_varint_len(63), 1);

    /* 2-byte: 64..16383 */
    CU_ASSERT_EQUAL(masque_varint_len(64), 2);
    CU_ASSERT_EQUAL(masque_varint_len(16383), 2);

    /* 4-byte: 16384..1073741823 */
    CU_ASSERT_EQUAL(masque_varint_len(16384), 4);
    CU_ASSERT_EQUAL(masque_varint_len(1073741823ULL), 4);

    /* 8-byte: 1073741824.. */
    CU_ASSERT_EQUAL(masque_varint_len(1073741824ULL), 8);
    CU_ASSERT_EQUAL(masque_varint_len(4611686018427387903ULL), 8);
}

static void
test_varint_roundtrip(void)
{
    uint64_t test_values[] = {
        0, 1, 63, 64, 16383, 16384,
        1073741823ULL, 1073741824ULL,
        4611686018427387903ULL,  /* max varint */
    };
    size_t nvalues = sizeof(test_values) / sizeof(test_values[0]);

    uint8_t buf[8];
    for (size_t i = 0; i < nvalues; i++) {
        uint64_t val = test_values[i];
        size_t expected_len = masque_varint_len(val);

        memset(buf, 0xFF, sizeof(buf));
        size_t enc_len = masque_varint_encode(buf, sizeof(buf), val);
        CU_ASSERT_EQUAL(enc_len, expected_len);

        uint64_t decoded = 0;
        size_t dec_len = masque_varint_decode(buf, sizeof(buf), &decoded);
        CU_ASSERT_EQUAL(dec_len, expected_len);
        CU_ASSERT_EQUAL(decoded, val);
    }
}

static void
test_varint_buffer_underflow(void)
{
    uint8_t buf[8];

    /* encode: buffer too small */
    CU_ASSERT_EQUAL(masque_varint_encode(buf, 0, 0), 0);
    CU_ASSERT_EQUAL(masque_varint_encode(buf, 1, 64), 0);   /* needs 2 bytes */
    CU_ASSERT_EQUAL(masque_varint_encode(buf, 3, 16384), 0); /* needs 4 bytes */
    CU_ASSERT_EQUAL(masque_varint_encode(buf, 7, 1073741824ULL), 0); /* needs 8 */

    /* decode: empty buffer */
    uint64_t val = 0xDEAD;
    CU_ASSERT_EQUAL(masque_varint_decode(buf, 0, &val), 0);

    /* decode: buffer shorter than indicated length */
    buf[0] = 0x40; /* 2-byte prefix, but only 1 byte provided */
    CU_ASSERT_EQUAL(masque_varint_decode(buf, 1, &val), 0);
}

/* ── UDP datagram framing ── */

static void
test_udp_framing_roundtrip(void)
{
    const uint8_t payload[] = "Hello MASQUE!";
    size_t paylen = sizeof(payload) - 1; /* exclude NUL */
    uint8_t framed[256];

    /* stream_id=0 → quarter_id=0 (1-byte varint) */
    size_t flen = masque_frame_udp_datagram(framed, sizeof(framed),
                                             0, payload, paylen);
    CU_ASSERT(flen > 0);
    CU_ASSERT_EQUAL(flen, 1 + 1 + paylen); /* qid(1) + ctx(1) + payload */

    uint64_t qid, ctx;
    size_t poff, plen;
    int rc = masque_unframe_udp_datagram(framed, flen, &qid, &ctx, &poff, &plen);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(qid, 0);
    CU_ASSERT_EQUAL(ctx, 0);
    CU_ASSERT_EQUAL(plen, paylen);
    CU_ASSERT(memcmp(framed + poff, payload, paylen) == 0);

    /* stream_id=4 → quarter_id=1 */
    flen = masque_frame_udp_datagram(framed, sizeof(framed),
                                      4, payload, paylen);
    CU_ASSERT(flen > 0);
    rc = masque_unframe_udp_datagram(framed, flen, &qid, &ctx, &poff, &plen);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(qid, 1);

    /* large stream_id=1024 → quarter_id=256 (2-byte varint) */
    flen = masque_frame_udp_datagram(framed, sizeof(framed),
                                      1024, payload, paylen);
    CU_ASSERT(flen > 0);
    CU_ASSERT_EQUAL(flen, 2 + 1 + paylen); /* qid(2) + ctx(1) + payload */
    rc = masque_unframe_udp_datagram(framed, flen, &qid, &ctx, &poff, &plen);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(qid, 256);
}

static void
test_udp_framing_errors(void)
{
    const uint8_t payload[] = "test";
    uint8_t framed[4]; /* too small */

    /* buffer too small for framing */
    size_t flen = masque_frame_udp_datagram(framed, 2, 0, payload, 4);
    CU_ASSERT_EQUAL(flen, 0);

    /* unframe: truncated buffer (only quarter_id, no context_id) */
    uint8_t trunc[1] = {0x00};
    uint64_t qid, ctx;
    size_t poff, plen;
    int rc = masque_unframe_udp_datagram(trunc, 1, &qid, &ctx, &poff, &plen);
    /* should fail: only 1 byte = quarter_id OK, but no room for context_id */
    CU_ASSERT_EQUAL(rc, -1);

    /* unframe: empty buffer */
    rc = masque_unframe_udp_datagram(trunc, 0, &qid, &ctx, &poff, &plen);
    CU_ASSERT_EQUAL(rc, -1);
}

/* ── MSS calculation ── */

static void
test_udp_mss(void)
{
    /* stream_id=0 → quarter_id=0 → varint_len=1, overhead=2 */
    CU_ASSERT_EQUAL(masque_udp_mss(1200, 0), 1198);

    /* stream_id=1024 → quarter_id=256 → varint_len=2, overhead=3 */
    CU_ASSERT_EQUAL(masque_udp_mss(1200, 1024), 1197);

    /* mss == overhead → 0 */
    CU_ASSERT_EQUAL(masque_udp_mss(2, 0), 0);

    /* mss < overhead → 0 */
    CU_ASSERT_EQUAL(masque_udp_mss(1, 0), 0);
    CU_ASSERT_EQUAL(masque_udp_mss(0, 0), 0);
}

/* ── Capsule Protocol ── */

static void
test_capsule_roundtrip(void)
{
    const uint8_t payload[] = "IP packet data";
    size_t paylen = sizeof(payload) - 1;
    uint8_t buf[256];

    /* encode DATAGRAM capsule (type=0) */
    size_t enc_len = masque_capsule_encode(buf, sizeof(buf),
                                            MASQUE_CAPSULE_DATAGRAM,
                                            payload, paylen);
    CU_ASSERT(enc_len > 0);
    CU_ASSERT_EQUAL(enc_len, 1 + 1 + paylen); /* type(1) + len(1) + payload */

    uint64_t type;
    size_t poff, plen;
    int rc = masque_capsule_decode(buf, enc_len, &type, &poff, &plen);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(type, MASQUE_CAPSULE_DATAGRAM);
    CU_ASSERT_EQUAL(plen, paylen);
    CU_ASSERT(memcmp(buf + poff, payload, paylen) == 0);

    /* encode ADDRESS_ASSIGN capsule (type=1) */
    enc_len = masque_capsule_encode(buf, sizeof(buf),
                                     MASQUE_CAPSULE_ADDRESS_ASSIGN,
                                     payload, paylen);
    CU_ASSERT(enc_len > 0);
    rc = masque_capsule_decode(buf, enc_len, &type, &poff, &plen);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(type, MASQUE_CAPSULE_ADDRESS_ASSIGN);
    CU_ASSERT_EQUAL(plen, paylen);

    /* empty payload capsule */
    enc_len = masque_capsule_encode(buf, sizeof(buf),
                                     MASQUE_CAPSULE_ROUTE_ADVERTISEMENT,
                                     NULL, 0);
    CU_ASSERT(enc_len > 0);
    CU_ASSERT_EQUAL(enc_len, 2); /* type(1) + len=0(1) */
    rc = masque_capsule_decode(buf, enc_len, &type, &poff, &plen);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(type, MASQUE_CAPSULE_ROUTE_ADVERTISEMENT);
    CU_ASSERT_EQUAL(plen, 0);
}

static void
test_capsule_errors(void)
{
    uint8_t buf[4];

    /* buffer too small for encode */
    CU_ASSERT_EQUAL(masque_capsule_encode(buf, 1, 0, (const uint8_t *)"x", 1), 0);

    /* decode: empty buffer */
    uint64_t type;
    size_t poff, plen;
    CU_ASSERT_EQUAL(masque_capsule_decode(buf, 0, &type, &poff, &plen), -1);

    /* decode: only type byte, no length */
    buf[0] = 0x01;
    CU_ASSERT_EQUAL(masque_capsule_decode(buf, 1, &type, &poff, &plen), -1);

    /* encode: paylen > 0 but payload is NULL */
    CU_ASSERT_EQUAL(masque_capsule_encode(buf, sizeof(buf), 0, NULL, 5), 0);
}

static void
test_address_assign_parse(void)
{
    /* Build an ADDRESS_ASSIGN payload:
     * request_id=0 (1 byte), ip_version=4 (1 byte),
     * ip_addr=10.0.0.1 (4 bytes), prefix_len=32 (1 byte) */
    uint8_t payload[7];
    payload[0] = 0x00;  /* request_id = 0 */
    payload[1] = 4;     /* IPv4 */
    payload[2] = 10;    /* 10.0.0.1 */
    payload[3] = 0;
    payload[4] = 0;
    payload[5] = 1;
    payload[6] = 32;    /* /32 */

    uint64_t req_id;
    uint8_t ip_ver, ip_addr[16], pfx_len;
    size_t ip_addr_len;
    int rc = masque_parse_address_assign(payload, sizeof(payload),
                                          &req_id, &ip_ver,
                                          ip_addr, &ip_addr_len, &pfx_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(req_id, 0);
    CU_ASSERT_EQUAL(ip_ver, 4);
    CU_ASSERT_EQUAL(ip_addr_len, 4);
    CU_ASSERT_EQUAL(ip_addr[0], 10);
    CU_ASSERT_EQUAL(ip_addr[1], 0);
    CU_ASSERT_EQUAL(ip_addr[2], 0);
    CU_ASSERT_EQUAL(ip_addr[3], 1);
    CU_ASSERT_EQUAL(pfx_len, 32);

    /* IPv6 test: request_id=1, ip_version=6, ::1/128 */
    uint8_t payload6[19];
    payload6[0] = 0x01;  /* request_id = 1 */
    payload6[1] = 6;     /* IPv6 */
    memset(payload6 + 2, 0, 15);
    payload6[17] = 1;    /* ::1 */
    payload6[18] = 128;  /* /128 */

    rc = masque_parse_address_assign(payload6, sizeof(payload6),
                                      &req_id, &ip_ver,
                                      ip_addr, &ip_addr_len, &pfx_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(req_id, 1);
    CU_ASSERT_EQUAL(ip_ver, 6);
    CU_ASSERT_EQUAL(ip_addr_len, 16);
    CU_ASSERT_EQUAL(pfx_len, 128);

    /* truncated payload: missing prefix_len */
    rc = masque_parse_address_assign(payload, 6, &req_id, &ip_ver,
                                      ip_addr, &ip_addr_len, &pfx_len);
    CU_ASSERT_EQUAL(rc, -1);

    /* invalid IP version */
    payload[1] = 5;
    rc = masque_parse_address_assign(payload, sizeof(payload),
                                      &req_id, &ip_ver,
                                      ip_addr, &ip_addr_len, &pfx_len);
    CU_ASSERT_EQUAL(rc, -1);
}

/* ── ADDRESS_REQUEST builder ── */

static void
test_address_request_build(void)
{
    uint8_t buf[64];

    /* RFC 9484 §4.7.2: request_id MUST NOT be zero */
    uint8_t any_ip[4] = {0, 0, 0, 0};
    size_t len = masque_build_address_request(buf, sizeof(buf), 0, 4, any_ip, 0);
    CU_ASSERT_EQUAL(len, 0); /* rejected: request_id == 0 */

    /* Build IPv4 request for any address with valid request_id */
    len = masque_build_address_request(buf, sizeof(buf), 1, 4, any_ip, 0);
    CU_ASSERT(len > 0);
    CU_ASSERT_EQUAL(len, 1 + 1 + 4 + 1); /* req_id(1) + ip_ver(1) + addr(4) + pfx(1) */

    /* Verify by parsing back with masque_parse_address_assign (same wire format) */
    uint64_t req_id;
    uint8_t ip_ver, ip_addr[16], pfx_len;
    size_t ip_addr_len;
    int rc = masque_parse_address_assign(buf, len,
                                          &req_id, &ip_ver,
                                          ip_addr, &ip_addr_len, &pfx_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(req_id, 1);
    CU_ASSERT_EQUAL(ip_ver, 4);
    CU_ASSERT_EQUAL(ip_addr_len, 4);
    CU_ASSERT_EQUAL(ip_addr[0], 0);
    CU_ASSERT_EQUAL(ip_addr[1], 0);
    CU_ASSERT_EQUAL(ip_addr[2], 0);
    CU_ASSERT_EQUAL(ip_addr[3], 0);
    CU_ASSERT_EQUAL(pfx_len, 0);

    /* Build IPv4 request for specific address */
    uint8_t specific_ip[4] = {192, 168, 1, 100};
    len = masque_build_address_request(buf, sizeof(buf), 42, 4, specific_ip, 32);
    CU_ASSERT(len > 0);
    rc = masque_parse_address_assign(buf, len,
                                      &req_id, &ip_ver,
                                      ip_addr, &ip_addr_len, &pfx_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(req_id, 42);
    CU_ASSERT_EQUAL(ip_ver, 4);
    CU_ASSERT_EQUAL(ip_addr[0], 192);
    CU_ASSERT_EQUAL(ip_addr[1], 168);
    CU_ASSERT_EQUAL(ip_addr[2], 1);
    CU_ASSERT_EQUAL(ip_addr[3], 100);
    CU_ASSERT_EQUAL(pfx_len, 32);

    /* Build IPv6 request */
    uint8_t ipv6_addr[16] = {0};
    len = masque_build_address_request(buf, sizeof(buf), 1, 6, ipv6_addr, 0);
    CU_ASSERT(len > 0);
    CU_ASSERT_EQUAL(len, 1 + 1 + 16 + 1); /* req_id(1) + ip_ver(1) + addr(16) + pfx(1) */
    rc = masque_parse_address_assign(buf, len,
                                      &req_id, &ip_ver,
                                      ip_addr, &ip_addr_len, &pfx_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(ip_ver, 6);
    CU_ASSERT_EQUAL(ip_addr_len, 16);

    /* Capsule encode/decode round-trip */
    uint8_t capsule_buf[128];
    uint8_t req_payload[32];
    size_t req_len = masque_build_address_request(req_payload, sizeof(req_payload),
                                                    1, 4, any_ip, 0);
    CU_ASSERT(req_len > 0);
    size_t cap_len = masque_capsule_encode(capsule_buf, sizeof(capsule_buf),
                                            MASQUE_CAPSULE_ADDRESS_REQUEST,
                                            req_payload, req_len);
    CU_ASSERT(cap_len > 0);

    uint64_t cap_type;
    size_t pay_off, pay_len;
    rc = masque_capsule_decode(capsule_buf, cap_len, &cap_type, &pay_off, &pay_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(cap_type, MASQUE_CAPSULE_ADDRESS_REQUEST);
    CU_ASSERT_EQUAL(pay_len, req_len);

    /* Error: invalid IP version */
    CU_ASSERT_EQUAL(masque_build_address_request(buf, sizeof(buf), 0, 5, any_ip, 0), 0);

    /* Error: buffer too small */
    CU_ASSERT_EQUAL(masque_build_address_request(buf, 3, 0, 4, any_ip, 0), 0);
}

/* ── ROUTE_ADVERTISEMENT parser ── */

static void
test_route_advertisement_parse(void)
{
    /* Build a single IPv4 route entry:
     * [IP Version=4][Start IP: 0.0.0.0][End IP: 255.255.255.255][Protocol=0] */
    uint8_t route[10];
    route[0] = 4;                          /* IPv4 */
    route[1] = 0; route[2] = 0; route[3] = 0; route[4] = 0;          /* start: 0.0.0.0 */
    route[5] = 255; route[6] = 255; route[7] = 255; route[8] = 255;  /* end: 255.255.255.255 */
    route[9] = 0;                          /* protocol: all */

    uint8_t ip_ver, start_ip[16], end_ip[16], ip_proto;
    size_t addr_len, consumed;
    int rc = masque_parse_route_advertisement(route, sizeof(route),
                                               &ip_ver, start_ip, end_ip,
                                               &addr_len, &ip_proto, &consumed);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(ip_ver, 4);
    CU_ASSERT_EQUAL(addr_len, 4);
    CU_ASSERT_EQUAL(start_ip[0], 0);
    CU_ASSERT_EQUAL(start_ip[3], 0);
    CU_ASSERT_EQUAL(end_ip[0], 255);
    CU_ASSERT_EQUAL(end_ip[3], 255);
    CU_ASSERT_EQUAL(ip_proto, 0);
    CU_ASSERT_EQUAL(consumed, 10);

    /* Build two IPv4 entries back-to-back */
    uint8_t routes[20];
    /* Entry 1: 10.0.0.0 - 10.0.0.255, proto=1 (ICMP) */
    routes[0] = 4;
    routes[1] = 10; routes[2] = 0; routes[3] = 0; routes[4] = 0;
    routes[5] = 10; routes[6] = 0; routes[7] = 0; routes[8] = 255;
    routes[9] = 1;
    /* Entry 2: 192.168.0.0 - 192.168.255.255, proto=6 (TCP) */
    routes[10] = 4;
    routes[11] = 192; routes[12] = 168; routes[13] = 0; routes[14] = 0;
    routes[15] = 192; routes[16] = 168; routes[17] = 255; routes[18] = 255;
    routes[19] = 6;

    /* Parse entry 1 */
    rc = masque_parse_route_advertisement(routes, sizeof(routes),
                                           &ip_ver, start_ip, end_ip,
                                           &addr_len, &ip_proto, &consumed);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(ip_ver, 4);
    CU_ASSERT_EQUAL(start_ip[0], 10);
    CU_ASSERT_EQUAL(end_ip[3], 255);
    CU_ASSERT_EQUAL(ip_proto, 1);
    CU_ASSERT_EQUAL(consumed, 10);

    /* Parse entry 2 */
    rc = masque_parse_route_advertisement(routes + consumed, sizeof(routes) - consumed,
                                           &ip_ver, start_ip, end_ip,
                                           &addr_len, &ip_proto, &consumed);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(ip_ver, 4);
    CU_ASSERT_EQUAL(start_ip[0], 192);
    CU_ASSERT_EQUAL(start_ip[1], 168);
    CU_ASSERT_EQUAL(end_ip[0], 192);
    CU_ASSERT_EQUAL(end_ip[1], 168);
    CU_ASSERT_EQUAL(ip_proto, 6);

    /* IPv6 entry: [ver=6][start: 16 bytes][end: 16 bytes][proto=0] = 34 bytes */
    uint8_t route6[34];
    route6[0] = 6;
    memset(route6 + 1, 0, 16);            /* start: :: */
    memset(route6 + 17, 0xFF, 16);        /* end: ffff:...:ffff */
    route6[33] = 0;
    rc = masque_parse_route_advertisement(route6, sizeof(route6),
                                           &ip_ver, start_ip, end_ip,
                                           &addr_len, &ip_proto, &consumed);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(ip_ver, 6);
    CU_ASSERT_EQUAL(addr_len, 16);
    CU_ASSERT_EQUAL(start_ip[0], 0);
    CU_ASSERT_EQUAL(end_ip[0], 0xFF);
    CU_ASSERT_EQUAL(consumed, 34);
}

static void
test_route_advertisement_errors(void)
{
    uint8_t ip_ver, start_ip[16], end_ip[16], ip_proto;
    size_t addr_len, consumed;

    /* Empty buffer */
    int rc = masque_parse_route_advertisement(NULL, 0,
                                               &ip_ver, start_ip, end_ip,
                                               &addr_len, &ip_proto, &consumed);
    CU_ASSERT_EQUAL(rc, -1);

    /* Invalid IP version */
    uint8_t bad_ver[10] = {5, 0,0,0,0, 255,255,255,255, 0};
    rc = masque_parse_route_advertisement(bad_ver, sizeof(bad_ver),
                                           &ip_ver, start_ip, end_ip,
                                           &addr_len, &ip_proto, &consumed);
    CU_ASSERT_EQUAL(rc, -1);

    /* Truncated IPv4 entry (missing end IP + proto) */
    uint8_t trunc[6] = {4, 10, 0, 0, 0, 10};
    rc = masque_parse_route_advertisement(trunc, sizeof(trunc),
                                           &ip_ver, start_ip, end_ip,
                                           &addr_len, &ip_proto, &consumed);
    CU_ASSERT_EQUAL(rc, -1);

    /* Truncated IPv6 entry */
    uint8_t trunc6[10] = {6, 0,0,0,0, 0,0,0,0, 0};
    rc = masque_parse_route_advertisement(trunc6, sizeof(trunc6),
                                           &ip_ver, start_ip, end_ip,
                                           &addr_len, &ip_proto, &consumed);
    CU_ASSERT_EQUAL(rc, -1);
}

/* ── IP checksum ── */

static void
test_ip_checksum(void)
{
    /* RFC 1071 example: a known IP header with pre-computed checksum.
     * We zero out the checksum field, compute, and verify. */
    uint8_t hdr[20] = {
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, /* checksum zeroed */
        0xac, 0x10, 0x0a, 0x63,  /* src: 172.16.10.99 */
        0xac, 0x10, 0x0a, 0x0c,  /* dst: 172.16.10.12 */
    };
    uint16_t cksum = masque_ip_checksum(hdr, 20);
    /* Set the checksum in the header and verify the total is 0 */
    hdr[10] = (uint8_t)(cksum >> 8);
    hdr[11] = (uint8_t)(cksum & 0xFF);
    CU_ASSERT_EQUAL(masque_ip_checksum(hdr, 20), 0);

    /* Empty data → checksum should be 0xFFFF */
    CU_ASSERT_EQUAL(masque_ip_checksum(hdr, 0), 0xFFFF);

    /* Odd-length data */
    uint8_t odd[3] = {0x01, 0x02, 0x03};
    uint16_t odd_cksum = masque_ip_checksum(odd, 3);
    /* Verify round-trip: sum of data + checksum should be 0 */
    uint32_t verify = 0x0102 + 0x0300 + odd_cksum;
    while (verify >> 16) {
        verify = (verify & 0xFFFF) + (verify >> 16);
    }
    CU_ASSERT_EQUAL((uint16_t)~verify, 0);
}

/* ── ICMP echo builder ── */

static void
test_icmp_echo_build(void)
{
    uint8_t pkt[64];
    uint8_t src[4] = {10, 0, 0, 2};
    uint8_t dst[4] = {10, 0, 0, 1};

    /* Build ICMP echo */
    size_t len = masque_build_icmp_echo(pkt, sizeof(pkt), src, dst);
    CU_ASSERT_EQUAL(len, 32);  /* 20 IP + 12 ICMP */

    /* Verify IPv4 header fields */
    CU_ASSERT_EQUAL(pkt[0], 0x45);         /* version=4, IHL=5 */
    CU_ASSERT_EQUAL(pkt[8], 64);           /* TTL */
    CU_ASSERT_EQUAL(pkt[9], 1);            /* Protocol: ICMP */
    CU_ASSERT_EQUAL(pkt[2], 0);            /* Total length MSB */
    CU_ASSERT_EQUAL(pkt[3], 32);           /* Total length LSB */

    /* Verify source and destination IPs */
    CU_ASSERT(memcmp(pkt + 12, src, 4) == 0);
    CU_ASSERT(memcmp(pkt + 16, dst, 4) == 0);

    /* Verify IP header checksum is correct (sum with checksum should be 0) */
    CU_ASSERT_EQUAL(masque_ip_checksum(pkt, 20), 0);

    /* Verify ICMP header */
    CU_ASSERT_EQUAL(pkt[20], 8);           /* Type: Echo Request */
    CU_ASSERT_EQUAL(pkt[21], 0);           /* Code */

    /* Verify ICMP checksum is correct */
    CU_ASSERT_EQUAL(masque_ip_checksum(pkt + 20, 12), 0);

    /* Verify ICMP payload is "TEST" */
    CU_ASSERT_EQUAL(pkt[28], 'T');
    CU_ASSERT_EQUAL(pkt[29], 'E');
    CU_ASSERT_EQUAL(pkt[30], 'S');
    CU_ASSERT_EQUAL(pkt[31], 'T');

    /* Different IPs should produce different checksums */
    uint8_t pkt2[64];
    uint8_t src2[4] = {192, 168, 1, 100};
    uint8_t dst2[4] = {8, 8, 8, 8};
    size_t len2 = masque_build_icmp_echo(pkt2, sizeof(pkt2), src2, dst2);
    CU_ASSERT_EQUAL(len2, 32);
    CU_ASSERT_EQUAL(masque_ip_checksum(pkt2, 20), 0);
    CU_ASSERT_EQUAL(masque_ip_checksum(pkt2 + 20, 12), 0);
    /* IP checksums differ (different addresses) */
    CU_ASSERT(memcmp(pkt + 10, pkt2 + 10, 2) != 0);
    /* But ICMP checksums are the same (same ICMP payload/type) */
    CU_ASSERT(memcmp(pkt + 22, pkt2 + 22, 2) == 0);

    /* Buffer too small → 0 */
    CU_ASSERT_EQUAL(masque_build_icmp_echo(pkt, 31, src, dst), 0);
    CU_ASSERT_EQUAL(masque_build_icmp_echo(pkt, 0, src, dst), 0);
}

/* ── Capsule chaining (multiple capsules back-to-back) ── */

static void
test_capsule_chaining(void)
{
    uint8_t buf[512];
    size_t off = 0;

    /* Encode ADDRESS_ASSIGN capsule (type=1) */
    uint8_t assign_payload[7] = {0x00, 4, 10, 0, 0, 2, 32};
    size_t n = masque_capsule_encode(buf + off, sizeof(buf) - off,
                                      MASQUE_CAPSULE_ADDRESS_ASSIGN,
                                      assign_payload, sizeof(assign_payload));
    CU_ASSERT(n > 0);
    off += n;

    /* Encode ROUTE_ADVERTISEMENT capsule (type=3) */
    uint8_t route_payload[10] = {4, 0,0,0,0, 255,255,255,255, 0};
    n = masque_capsule_encode(buf + off, sizeof(buf) - off,
                               MASQUE_CAPSULE_ROUTE_ADVERTISEMENT,
                               route_payload, sizeof(route_payload));
    CU_ASSERT(n > 0);
    off += n;

    /* Now decode both capsules sequentially */
    size_t parse_off = 0;
    uint64_t type;
    size_t pay_off, pay_len;

    /* Decode capsule 1 */
    int rc = masque_capsule_decode(buf + parse_off, off - parse_off,
                                    &type, &pay_off, &pay_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(type, MASQUE_CAPSULE_ADDRESS_ASSIGN);
    CU_ASSERT_EQUAL(pay_len, 7);

    /* Verify ADDRESS_ASSIGN payload */
    uint64_t req_id;
    uint8_t ip_ver, ip_addr[16], pfx_len;
    size_t ip_addr_len;
    rc = masque_parse_address_assign(buf + parse_off + pay_off, pay_len,
                                      &req_id, &ip_ver, ip_addr, &ip_addr_len, &pfx_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(ip_addr[3], 2);
    CU_ASSERT_EQUAL(pfx_len, 32);

    parse_off += pay_off + pay_len;

    /* Decode capsule 2 */
    rc = masque_capsule_decode(buf + parse_off, off - parse_off,
                                &type, &pay_off, &pay_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(type, MASQUE_CAPSULE_ROUTE_ADVERTISEMENT);
    CU_ASSERT_EQUAL(pay_len, 10);

    /* Verify ROUTE_ADVERTISEMENT payload */
    uint8_t r_ver, start_ip[16], end_ip[16], r_proto;
    size_t r_addr_len, consumed;
    rc = masque_parse_route_advertisement(buf + parse_off + pay_off, pay_len,
                                           &r_ver, start_ip, end_ip,
                                           &r_addr_len, &r_proto, &consumed);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(r_ver, 4);
    CU_ASSERT_EQUAL(end_ip[0], 255);
}

/* ── Large capsule payload (2-byte varint length) ── */

static void
test_capsule_large_payload(void)
{
    /* Payload of 100 bytes → length varint = 2 bytes (100 >= 64) */
    uint8_t payload[100];
    memset(payload, 0xAB, sizeof(payload));
    uint8_t buf[256];

    size_t enc_len = masque_capsule_encode(buf, sizeof(buf),
                                            MASQUE_CAPSULE_DATAGRAM,
                                            payload, sizeof(payload));
    CU_ASSERT(enc_len > 0);
    /* type(1) + length(2) + payload(100) = 103 */
    CU_ASSERT_EQUAL(enc_len, 1 + 2 + 100);

    uint64_t type;
    size_t pay_off, pay_len;
    int rc = masque_capsule_decode(buf, enc_len, &type, &pay_off, &pay_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(type, MASQUE_CAPSULE_DATAGRAM);
    CU_ASSERT_EQUAL(pay_len, 100);
    CU_ASSERT(memcmp(buf + pay_off, payload, 100) == 0);
}

/* ── Unknown capsule type (should decode fine) ── */

static void
test_capsule_unknown_type(void)
{
    uint8_t buf[32];
    uint8_t payload[] = "unknown";
    size_t enc_len = masque_capsule_encode(buf, sizeof(buf),
                                            0xFF,  /* unknown type */
                                            payload, sizeof(payload) - 1);
    CU_ASSERT(enc_len > 0);

    uint64_t type;
    size_t pay_off, pay_len;
    int rc = masque_capsule_decode(buf, enc_len, &type, &pay_off, &pay_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(type, 0xFF);
    CU_ASSERT_EQUAL(pay_len, 7);
}

/* ── Empty-payload datagram framing ── */

static void
test_udp_framing_empty_payload(void)
{
    uint8_t framed[16];

    /* Frame empty UDP payload */
    size_t flen = masque_frame_udp_datagram(framed, sizeof(framed),
                                             0, NULL, 0);
    /* Should succeed: just qid + ctx, no payload */
    CU_ASSERT_EQUAL(flen, 2);  /* qid(1) + ctx(1) */

    uint64_t qid, ctx;
    size_t poff, plen;
    int rc = masque_unframe_udp_datagram(framed, flen, &qid, &ctx, &poff, &plen);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(qid, 0);
    CU_ASSERT_EQUAL(ctx, 0);
    CU_ASSERT_EQUAL(plen, 0);
}

/* ── Capsule with truncated payload (declared length > available) ── */

static void
test_capsule_truncated_payload(void)
{
    /* Build a valid capsule then truncate it */
    uint8_t payload[20];
    memset(payload, 0xCC, sizeof(payload));
    uint8_t buf[64];
    size_t enc_len = masque_capsule_encode(buf, sizeof(buf),
                                            MASQUE_CAPSULE_DATAGRAM,
                                            payload, sizeof(payload));
    CU_ASSERT(enc_len > 0);

    /* Decode should succeed (it trusts the length field) */
    uint64_t type;
    size_t pay_off, pay_len;
    int rc = masque_capsule_decode(buf, enc_len, &type, &pay_off, &pay_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(pay_len, 20);

    /* If we give it a buffer shorter than header + declared payload length,
     * the decoder now correctly rejects it (RFC 9297 §3.3 bounds check) */
    rc = masque_capsule_decode(buf, 3, &type, &pay_off, &pay_len);
    CU_ASSERT_EQUAL(rc, -1);
}

/* ── ADDRESS_ASSIGN: various truncation points ── */

static void
test_address_assign_truncation_variants(void)
{
    uint64_t req_id;
    uint8_t ip_ver, ip_addr[16], pfx_len;
    size_t ip_addr_len;

    /* Empty payload */
    CU_ASSERT_EQUAL(masque_parse_address_assign(NULL, 0,
        &req_id, &ip_ver, ip_addr, &ip_addr_len, &pfx_len), -1);

    /* Only request_id, no ip_version */
    uint8_t p1[1] = {0x00};
    CU_ASSERT_EQUAL(masque_parse_address_assign(p1, 1,
        &req_id, &ip_ver, ip_addr, &ip_addr_len, &pfx_len), -1);

    /* request_id + ip_version but no address */
    uint8_t p2[2] = {0x00, 4};
    CU_ASSERT_EQUAL(masque_parse_address_assign(p2, 2,
        &req_id, &ip_ver, ip_addr, &ip_addr_len, &pfx_len), -1);

    /* request_id + ip_version + partial IPv4 address (3 bytes) */
    uint8_t p3[5] = {0x00, 4, 10, 0, 0};
    CU_ASSERT_EQUAL(masque_parse_address_assign(p3, 5,
        &req_id, &ip_ver, ip_addr, &ip_addr_len, &pfx_len), -1);

    /* request_id + ip_version + full IPv4 but no prefix */
    uint8_t p4[6] = {0x00, 4, 10, 0, 0, 1};
    CU_ASSERT_EQUAL(masque_parse_address_assign(p4, 6,
        &req_id, &ip_ver, ip_addr, &ip_addr_len, &pfx_len), -1);

    /* Correct minimal IPv4 */
    uint8_t p5[7] = {0x00, 4, 10, 0, 0, 1, 32};
    CU_ASSERT_EQUAL(masque_parse_address_assign(p5, 7,
        &req_id, &ip_ver, ip_addr, &ip_addr_len, &pfx_len), 0);

    /* Large request_id (2-byte varint = 100) */
    uint8_t p6[8];
    p6[0] = 0x40;  /* 2-byte varint prefix */
    p6[1] = 100;   /* request_id = 100 */
    p6[2] = 4;     /* IPv4 */
    p6[3] = 172; p6[4] = 16; p6[5] = 0; p6[6] = 1;
    p6[7] = 24;    /* /24 */
    CU_ASSERT_EQUAL(masque_parse_address_assign(p6, 8,
        &req_id, &ip_ver, ip_addr, &ip_addr_len, &pfx_len), 0);
    CU_ASSERT_EQUAL(req_id, 100);
    CU_ASSERT_EQUAL(ip_addr[0], 172);
    CU_ASSERT_EQUAL(pfx_len, 24);
}

/* ── Full capsule-wrapped ADDRESS_ASSIGN decode ── */

static void
test_capsule_address_assign_full(void)
{
    /* Simulate what connect-ip-go sends:
     * capsule(type=1, payload=ADDRESS_ASSIGN(req_id=0, IPv4=10.0.0.2/32)) */
    uint8_t assign_payload[7] = {0x00, 4, 10, 0, 0, 2, 32};
    uint8_t capsule[32];
    size_t cap_len = masque_capsule_encode(capsule, sizeof(capsule),
                                            MASQUE_CAPSULE_ADDRESS_ASSIGN,
                                            assign_payload, sizeof(assign_payload));
    CU_ASSERT(cap_len > 0);

    /* Decode capsule header */
    uint64_t type;
    size_t pay_off, pay_len;
    int rc = masque_capsule_decode(capsule, cap_len, &type, &pay_off, &pay_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(type, 1);

    /* Decode address assign payload */
    uint64_t req_id;
    uint8_t ip_ver, ip_addr[16], pfx_len;
    size_t ip_addr_len;
    rc = masque_parse_address_assign(capsule + pay_off, pay_len,
                                      &req_id, &ip_ver, ip_addr, &ip_addr_len, &pfx_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(req_id, 0);
    CU_ASSERT_EQUAL(ip_ver, 4);
    CU_ASSERT_EQUAL(ip_addr[0], 10);
    CU_ASSERT_EQUAL(ip_addr[1], 0);
    CU_ASSERT_EQUAL(ip_addr[2], 0);
    CU_ASSERT_EQUAL(ip_addr[3], 2);
    CU_ASSERT_EQUAL(pfx_len, 32);
}

/* ── CONNECT-IP datagram framing (IP packet in HTTP Datagram) ── */

static void
test_connect_ip_datagram_roundtrip(void)
{
    /* Build ICMP echo → frame as HTTP Datagram → unframe → verify IP packet */
    uint8_t src[4] = {10, 0, 0, 2};
    uint8_t dst[4] = {10, 0, 0, 1};
    uint8_t ip_pkt[64];
    size_t ip_len = masque_build_icmp_echo(ip_pkt, sizeof(ip_pkt), src, dst);
    CU_ASSERT_EQUAL(ip_len, 32);

    /* Frame as HTTP Datagram (stream_id=0) */
    uint8_t dgram[128];
    size_t dgram_len = masque_frame_udp_datagram(dgram, sizeof(dgram),
                                                   0, ip_pkt, ip_len);
    CU_ASSERT(dgram_len > 0);
    CU_ASSERT_EQUAL(dgram_len, 1 + 1 + 32); /* qid(1) + ctx(1) + ip_pkt(32) */

    /* Unframe */
    uint64_t qid, ctx;
    size_t pay_off, pay_len;
    int rc = masque_unframe_udp_datagram(dgram, dgram_len,
                                          &qid, &ctx, &pay_off, &pay_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(qid, 0);
    CU_ASSERT_EQUAL(ctx, 0);
    CU_ASSERT_EQUAL(pay_len, 32);

    /* Verify the unframed payload is the original IP packet */
    CU_ASSERT(memcmp(dgram + pay_off, ip_pkt, ip_len) == 0);

    /* Verify the IP packet is still valid */
    CU_ASSERT_EQUAL(masque_ip_checksum(dgram + pay_off, 20), 0);
    CU_ASSERT_EQUAL(masque_ip_checksum(dgram + pay_off + 20, 12), 0);
}

/* ── Entry point ── */

void
xqc_test_masque(void)
{
    test_varint_len();
    test_varint_roundtrip();
    test_varint_buffer_underflow();
    test_udp_framing_roundtrip();
    test_udp_framing_errors();
    test_udp_framing_empty_payload();
    test_udp_mss();
    test_capsule_roundtrip();
    test_capsule_errors();
    test_capsule_chaining();
    test_capsule_large_payload();
    test_capsule_unknown_type();
    test_capsule_truncated_payload();
    test_address_assign_parse();
    test_address_assign_truncation_variants();
    test_capsule_address_assign_full();
    test_address_request_build();
    test_route_advertisement_parse();
    test_route_advertisement_errors();
    test_ip_checksum();
    test_icmp_echo_build();
    test_connect_ip_datagram_roundtrip();
}
