/**
 * @copyright Copyright (c) 2026, mp0rta
 */

#include <CUnit/CUnit.h>
#include <stdlib.h>
#include <string.h>
#include "xquic/xquic.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_packet_out.h"       /* XQC_MAX_PACKET_OUT_SIZE */
#include "src/transport/xqc_transport_params.h" /* XQC_DEFAULT_INIT_MAX_PATH_ID */
#include "src/congestion_control/xqc_bbr.h"     /* xqc_bbr_cb */
#include "xqc_set_conn_settings_test.h"

/* Stand-in for an xqc_engine_t whose only used field is
 * default_conn_settings. calloc-zeroed; never touched by the SUT. */
static xqc_engine_t *
make_zero_engine(void)
{
    xqc_engine_t *e = calloc(1, sizeof(*e));
    CU_ASSERT_PTR_NOT_NULL_FATAL(e);
    return e;
}

/* The 15 fields below are the subset of xqc_conn_settings_t that
 * mqvpn (the primary downstream consumer) populates today. Each
 * picks a non-default sentinel value so a missing copy line in
 * xqc_server_set_conn_settings would zero the field and trip an
 * assertion. */
void
xqc_test_server_set_conn_settings_propagation(void)
{
    xqc_engine_t *e = make_zero_engine();

    xqc_conn_settings_t in;
    memset(&in, 0, sizeof(in));

    /* --- direct-copy fields (always assigned verbatim) --- */
    in.pacing_on = 1;
    in.mp_ping_on = 1;
    in.enable_multipath = 1;
    in.so_sndbuf = 4 * 1024 * 1024;
    in.sndq_packets_used_max = 4096;
    in.max_datagram_frame_size = 1500;
    in.cong_ctrl_callback = xqc_bbr_cb; /* defined header, address only */
    in.cc_params.customize_on = 1;      /* nested struct, sub-field probe */
    in.cc_params.init_cwnd = 32;

    /* --- conditional fields (>0 wins, else untouched) --- */
    in.idle_time_out = 60 * 1000;
    in.init_idle_time_out = 10 * 1000;

    /* --- special fields --- */
    in.max_pkt_out_size = 1300;          /* below cap → verbatim copy */
    in.proto_version = XQC_VERSION_V1;   /* valid → wins over engine default */
    in.init_max_path_id = 16;            /* non-zero → wins over default */
    in.max_path_id_grant_max_value = 32; /* direct copy */
    in.defer_dgram_flush = 1;            /* direct copy */

    xqc_server_set_conn_settings(e, &in);

    /* direct */
    CU_ASSERT_EQUAL(e->default_conn_settings.pacing_on, 1);
    CU_ASSERT_EQUAL(e->default_conn_settings.mp_ping_on, 1);
    CU_ASSERT_EQUAL(e->default_conn_settings.enable_multipath, 1);
    CU_ASSERT_EQUAL(e->default_conn_settings.so_sndbuf, 4 * 1024 * 1024);
    CU_ASSERT_EQUAL(e->default_conn_settings.sndq_packets_used_max, 4096);
    CU_ASSERT_EQUAL(e->default_conn_settings.max_datagram_frame_size, 1500);
    CU_ASSERT_EQUAL(memcmp(&e->default_conn_settings.cong_ctrl_callback, &xqc_bbr_cb,
                           sizeof(xqc_cong_ctrl_callback_t)),
                    0);
    CU_ASSERT_EQUAL(e->default_conn_settings.cc_params.customize_on, 1);
    CU_ASSERT_EQUAL(e->default_conn_settings.cc_params.init_cwnd, 32);

    /* conditional */
    CU_ASSERT_EQUAL(e->default_conn_settings.idle_time_out, 60 * 1000);
    CU_ASSERT_EQUAL(e->default_conn_settings.init_idle_time_out, 10 * 1000);

    /* special */
    CU_ASSERT_EQUAL(e->default_conn_settings.max_pkt_out_size, 1300);
    CU_ASSERT_EQUAL(e->default_conn_settings.proto_version, XQC_VERSION_V1);
    CU_ASSERT_EQUAL(e->default_conn_settings.init_max_path_id, 16);
    CU_ASSERT_EQUAL(e->default_conn_settings.max_path_id_grant_max_value, 32);
    /* This one was missing for a while: the copier is field-by-field, so an
     * appended setting nobody adds a line for reaches every server connection
     * as 0 while the API call still reports success. Nothing else catches it
     * — the client path assigns the whole struct so it cannot notice, and a
     * downstream builder test only proves the input side. */
    CU_ASSERT_EQUAL(e->default_conn_settings.defer_dgram_flush, 1);

    free(e);
}

/* When the conditional / sanitised fields are zero (or invalid),
 * xqc_server_set_conn_settings must apply its documented defaults
 * rather than zeroing the engine's existing value. */
void
xqc_test_server_set_conn_settings_zero_defaults(void)
{
    xqc_engine_t *e = make_zero_engine();

    /* Seed an engine-side prior value for max_pkt_out_size so we can
     * tell "unchanged" from "zeroed". */
    e->default_conn_settings.max_pkt_out_size = 1200;

    xqc_conn_settings_t in;
    memset(&in, 0, sizeof(in));

    /* All zero / invalid: each special branch should keep engine prior
     * or substitute its documented default. */
    in.max_pkt_out_size = 0;                /* falsy → engine prior preserved */
    in.proto_version = XQC_IDRAFT_INIT_VER; /* invalid → engine prior preserved */
    in.init_max_path_id = 0;                /* 0 → XQC_DEFAULT_INIT_MAX_PATH_ID */

    xqc_server_set_conn_settings(e, &in);

    CU_ASSERT_EQUAL(e->default_conn_settings.max_pkt_out_size, 1200);
    CU_ASSERT_EQUAL(e->default_conn_settings.proto_version, XQC_IDRAFT_INIT_VER);
    CU_ASSERT_EQUAL(e->default_conn_settings.init_max_path_id,
                    XQC_DEFAULT_INIT_MAX_PATH_ID);

    free(e);
}

/* max_pkt_out_size is clamped to XQC_MAX_PACKET_OUT_SIZE — overshoot
 * must be reduced, not propagated. */
void
xqc_test_server_set_conn_settings_clamp(void)
{
    xqc_engine_t *e = make_zero_engine();

    xqc_conn_settings_t in;
    memset(&in, 0, sizeof(in));
    in.max_pkt_out_size = XQC_MAX_PACKET_OUT_SIZE + 100;

    xqc_server_set_conn_settings(e, &in);

    CU_ASSERT_EQUAL(e->default_conn_settings.max_pkt_out_size, XQC_MAX_PACKET_OUT_SIZE);

    free(e);
}
