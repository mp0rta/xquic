/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * BBR's cwnd compensation for RTT variation.
 */

#include <CUnit/CUnit.h>
#include <string.h>

#include "xquic/xquic.h"
#include "src/congestion_control/xqc_bbr.h"
#include "src/congestion_control/xqc_sample.h"
#include "src/congestion_control/xqc_window_filter.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_send_ctl.h"
#include "xqc_common_test.h"
#include "xqc_bbr_test.h"

#define BBR_TEST_BW         1250000 /* bytes per second */
#define BBR_TEST_MIN_RTT_US 20000
#define BBR_TEST_SRTT_US    80000

/*
 * Leave DRAIN on one ACK, nothing in flight, of a path whose RTT has swung
 * to 4x its min_rtt; return the cwnd. The cwnd starts far above the target,
 * so the ACK sets it to the target.
 */
static uint64_t
bbr_test_cwnd(uint32_t cc_flags)
{
    xqc_conn_settings_t    settings;
    xqc_conn_ssl_config_t  ssl_config;
    xqc_engine_t          *engine;
    xqc_connection_t      *conn;
    xqc_send_ctl_t        *ctl;
    xqc_bbr_t             *bbr;
    xqc_sample_t           sampler;
    const xqc_cid_t       *cid;
    xqc_usec_t             now;
    uint64_t               cwnd;

    engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.cong_ctrl_callback = xqc_bbr_cb;
    settings.cc_params.cc_optimization_flags = cc_flags;

    memset(&ssl_config, 0, sizeof(ssl_config));
    cid = xqc_connect(engine, &settings, NULL, 0, "", 0, &ssl_config,
                      NULL, 0, "transport", NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cid);
    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    ctl = conn->conn_initial_path->path_send_ctl;
    bbr = (xqc_bbr_t *)ctl->ctl_cong;
    now = xqc_monotonic_timestamp();

    bbr->mode = BBR_DRAIN;
    bbr->full_bandwidth_reached = TRUE;
    xqc_win_filter_reset(&bbr->bandwidth, bbr->round_cnt, BBR_TEST_BW);
    bbr->min_rtt = BBR_TEST_MIN_RTT_US;
    bbr->min_rtt_stamp = now;
    bbr->probe_rtt_min_us = BBR_TEST_MIN_RTT_US;
    bbr->probe_rtt_min_us_stamp = now;
    bbr->congestion_window = 64 * 1024 * 1024;

    memset(&sampler, 0, sizeof(sampler));
    sampler.send_ctl = ctl;
    sampler.now = now;
    sampler.po_sent_time = now - BBR_TEST_SRTT_US; /* after recovery_start_time: not a recovery ACK */
    sampler.acked = 1200;
    sampler.rtt = BBR_TEST_SRTT_US;
    sampler.srtt = BBR_TEST_SRTT_US;
    xqc_bbr_cb.xqc_cong_ctl_on_ack_multiple_pkts(bbr, &sampler);

    CU_ASSERT_EQUAL(bbr->mode, BBR_PROBE_BW);
    cwnd = xqc_bbr_cb.xqc_cong_ctl_get_cwnd(bbr);
    xqc_engine_destroy(engine);
    return cwnd;
}

/*
 * With the flag, a path whose RTT swings past twice its min_rtt gets
 * bw x (srtt - min_rtt) on top of its target cwnd. Without it the cwnd is
 * sized for the luckiest RTT sample, which holds a jittery link below its
 * rate.
 */
void
xqc_test_bbr_rttvar_compensation(void)
{
    uint64_t base = bbr_test_cwnd(XQC_BBR_FLAG_NONE);
    uint64_t comp = bbr_test_cwnd(XQC_BBR_FLAG_RTTVAR_COMPENSATION);

    CU_ASSERT_EQUAL(comp - base, (uint64_t)BBR_TEST_BW
                    * (BBR_TEST_SRTT_US - BBR_TEST_MIN_RTT_US) / 1000000);
}
