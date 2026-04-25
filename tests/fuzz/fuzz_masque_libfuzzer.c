#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "src/http3/xqc_h3_ext_masque.h"

#define XQC_FUZZ_OUT_MAX 4096

static uint64_t
xqc_fuzz_load_u64(const uint8_t *data, size_t len)
{
    uint64_t v = 0;
    size_t n = len < 8 ? len : 8;

    for (size_t i = 0; i < n; i++) {
        v = (v << 8) | data[i];
    }

    return v;
}

static void
xqc_fuzz_capsule_decode_only(const uint8_t *data, size_t len)
{
    uint64_t type = 0;
    const uint8_t *payload = NULL;
    size_t payload_len = 0, consumed = 0;

    xqc_int_t rc = xqc_h3_ext_capsule_decode(data, len, &type, &payload, &payload_len, &consumed);
    if (rc == XQC_OK) {
        assert(payload >= data);
        assert(payload <= data + len);
        assert(consumed <= len);
        assert((size_t)(payload - data) <= consumed);
        assert(payload_len <= consumed);
        (void)type;
    }
}

static void
xqc_fuzz_capsule_roundtrip(const uint8_t *data, size_t len)
{
    uint8_t out[XQC_FUZZ_OUT_MAX];
    uint64_t type = xqc_fuzz_load_u64(data, len) & ((1ULL << 62) - 1);
    const uint8_t *payload = data;
    size_t payload_len = len;
    size_t written = 0;

    if (payload_len > XQC_FUZZ_OUT_MAX - 16) {
        payload_len = XQC_FUZZ_OUT_MAX - 16;
    }

    xqc_int_t rc = xqc_h3_ext_capsule_encode(out, sizeof(out), &written, type, payload, payload_len);
    if (rc != XQC_OK) {
        return;
    }

    assert(written <= sizeof(out));

    uint64_t decoded_type = 0;
    const uint8_t *decoded_payload = NULL;
    size_t decoded_len = 0, consumed = 0;
    rc = xqc_h3_ext_capsule_decode(out, written, &decoded_type, &decoded_payload, &decoded_len, &consumed);
    assert(rc == XQC_OK);
    assert(decoded_type == type);
    assert(decoded_payload >= out);
    assert(decoded_payload <= out + written);
    assert(decoded_len == payload_len);
    assert(consumed == written);
    assert(memcmp(decoded_payload, payload, payload_len) == 0);
}

static void
xqc_fuzz_udp_unframe_only(const uint8_t *data, size_t len)
{
    uint64_t quarter_id = 0, context_id = 0;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;

    xqc_int_t rc = xqc_h3_ext_masque_unframe_udp(data, len, &quarter_id, &context_id, &payload, &payload_len);
    if (rc == XQC_OK) {
        assert(payload >= data);
        assert(payload <= data + len);
        assert((size_t)(payload - data) <= len);
        assert(payload_len <= len - (size_t)(payload - data));
        (void)quarter_id;
        (void)context_id;
    }
}

static void
xqc_fuzz_udp_roundtrip(const uint8_t *data, size_t len)
{
    uint8_t out[XQC_FUZZ_OUT_MAX];
    size_t written = 0;
    uint64_t stream_id = xqc_fuzz_load_u64(data, len) & ((1ULL << 62) - 1);
    const uint8_t *payload = data;
    size_t payload_len = len;

    if (payload_len > XQC_FUZZ_OUT_MAX - 16) {
        payload_len = XQC_FUZZ_OUT_MAX - 16;
    }

    xqc_int_t rc = xqc_h3_ext_masque_frame_udp(out, sizeof(out), &written, stream_id, payload, payload_len);
    if (rc != XQC_OK) {
        return;
    }

    assert(written <= sizeof(out));

    uint64_t quarter_id = 0, context_id = 0;
    const uint8_t *decoded_payload = NULL;
    size_t decoded_len = 0;
    rc = xqc_h3_ext_masque_unframe_udp(out, written, &quarter_id, &context_id, &decoded_payload, &decoded_len);
    assert(rc == XQC_OK);
    assert(quarter_id == (stream_id / 4));
    assert(context_id == 0);
    assert(decoded_payload >= out);
    assert(decoded_payload <= out + written);
    assert(decoded_len == payload_len);
    assert(memcmp(decoded_payload, payload, payload_len) == 0);
}

static void
xqc_fuzz_address_assign_parse(const uint8_t *data, size_t len)
{
    uint64_t request_id = 0;
    uint8_t ip_version = 0, ip_addr[16], prefix_len = 0;
    size_t ip_addr_len = 0, consumed = 0;

    xqc_int_t rc = xqc_h3_ext_connectip_parse_address_assign(
        data, len, &request_id, &ip_version, ip_addr, &ip_addr_len, &prefix_len, &consumed);

    if (rc != XQC_OK) {
        return;
    }

    assert(consumed <= len);
    assert(ip_version == 4 || ip_version == 6);
    assert(ip_addr_len == 4 || ip_addr_len == 16);
    assert((ip_version == 4 && ip_addr_len == 4) || (ip_version == 6 && ip_addr_len == 16));

    if (request_id != 0) {
        uint8_t out[64];
        size_t written = 0;
        rc = xqc_h3_ext_connectip_build_address_request(
            out, sizeof(out), &written, request_id, ip_version, ip_addr, prefix_len);
        if (rc == XQC_OK) {
            uint64_t req2 = 0;
            uint8_t ver2 = 0, addr2[16], pfx2 = 0;
            size_t addr2_len = 0, consumed2 = 0;
            rc = xqc_h3_ext_connectip_parse_address_assign(
                out, written, &req2, &ver2, addr2, &addr2_len, &pfx2, &consumed2);
            assert(rc == XQC_OK);
            assert(consumed2 == written);
            assert(req2 == request_id);
            assert(ver2 == ip_version);
            assert(addr2_len == ip_addr_len);
            assert(pfx2 == prefix_len);
            assert(memcmp(addr2, ip_addr, ip_addr_len) == 0);
        }
    }
}

static void
xqc_fuzz_route_advertisement_parse(const uint8_t *data, size_t len)
{
    uint8_t ip_version = 0, start_ip[16], end_ip[16], ip_protocol = 0;
    size_t ip_addr_len = 0, consumed = 0;

    xqc_int_t rc = xqc_h3_ext_connectip_parse_route_advertisement(
        data, len, &ip_version, start_ip, end_ip, &ip_addr_len, &ip_protocol, &consumed);

    if (rc == XQC_OK) {
        assert(consumed > 0);
        assert(consumed <= len);
        assert(ip_version == 4 || ip_version == 6);
        assert(ip_addr_len == 4 || ip_addr_len == 16);
        (void)ip_protocol;
    }
}

static void
xqc_fuzz_route_advertisement_validate(const uint8_t *data, size_t len)
{
    xqc_int_t rc = xqc_h3_ext_connectip_validate_route_advertisement(data, len);
    if (rc != XQC_OK) {
        return;
    }

    const uint8_t *p = data;
    size_t remaining = len;

    while (remaining > 0) {
        uint8_t ip_version = 0, start_ip[16], end_ip[16], ip_protocol = 0;
        size_t ip_addr_len = 0, consumed = 0;
        rc = xqc_h3_ext_connectip_parse_route_advertisement(
            p, remaining, &ip_version, start_ip, end_ip, &ip_addr_len, &ip_protocol, &consumed);
        assert(rc == XQC_OK);
        assert(consumed > 0);
        assert(consumed <= remaining);

        p += consumed;
        remaining -= consumed;
    }
}

static void
xqc_fuzz_ip_packet_validate(const uint8_t *data, size_t len)
{
    xqc_int_t rc = xqc_h3_ext_masque_validate_ip_packet(data, len);
    if (rc == XQC_OK) {
        uint8_t version = (data[0] >> 4) & 0x0F;
        assert(version == 4 || version == 6);
        if (version == 4) {
            assert(len >= 20);
        } else {
            assert(len >= 40);
        }
    }
}

static void
xqc_fuzz_ipv6_mtu_check(const uint8_t *data, size_t len)
{
    size_t mtu = (size_t)(xqc_fuzz_load_u64(data, len) & 0x1FFFu);
    xqc_int_t rc = xqc_h3_ext_masque_check_ipv6_mtu(mtu);
    if (mtu < 1280) {
        assert(rc != XQC_OK);
    } else {
        assert(rc == XQC_OK);
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == NULL) {
        return 0;
    }

    if (size == 0) {
        xqc_fuzz_ipv6_mtu_check(data, size);
        return 0;
    }

    uint8_t mode = data[0] % 8;
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    switch (mode) {
    case 0:
        xqc_fuzz_udp_unframe_only(payload, payload_len);
        break;
    case 1:
        xqc_fuzz_udp_roundtrip(payload, payload_len);
        break;
    case 2:
        xqc_fuzz_capsule_decode_only(payload, payload_len);
        break;
    case 3:
        xqc_fuzz_capsule_roundtrip(payload, payload_len);
        break;
    case 4:
        xqc_fuzz_address_assign_parse(payload, payload_len);
        break;
    case 5:
        xqc_fuzz_route_advertisement_parse(payload, payload_len);
        xqc_fuzz_route_advertisement_validate(payload, payload_len);
        break;
    case 6:
        xqc_fuzz_ip_packet_validate(payload, payload_len);
        break;
    case 7:
    default:
        xqc_fuzz_ipv6_mtu_check(payload, payload_len);
        break;
    }

    return 0;
}

