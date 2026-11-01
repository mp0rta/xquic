#!/bin/bash
#
# fork.core endpoint case-test group: cases this fork carries and upstream does
# not. They live in their own group so that upstream merges never touch them.
# Each case starts its own server, so any of them can run alone.


ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT_DIR}/case_test/lib/common.sh"

case_test_group "fork.core"

# 900: the library-side verification rejects the self-signed cert:
# cert_verify_failed_notify fires exactly once, with X509 error 18, and the
# connection is still rejected.
case_fork_core_cert_verify_failed_notify_reject()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
clear_log
echo -e "cert_verify_failed_notify on a rejected cert ...\c"
${CLIENT_BIN} -l d -t 1 -E -1 -x 900 > stdlog
result=`grep -c "cert_verify_failed_notify|" stdlog`
result18=`grep -c "cert_verify_failed_notify|x509_err:18|" stdlog`
# the notify only reports: the connection must still close on the rejection
# (CRYPTO_ERROR 0x112, as case 703 pins)
rejected=`grep -c "conn_err:274" stdlog`
if [ "$result" -eq 1 ] && [ "$result18" -eq 1 ] && [ "$rejected" -gt 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "cert_verify_failed_notify_reject" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "cert_verify_failed_notify_reject" "fail"
fi
}

# 901: self-signed allowed, the handshake succeeds: no notify.
case_fork_core_cert_verify_failed_notify_accept()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
clear_log
echo -e "cert_verify_failed_notify absent on an accepted cert ...\c"
${CLIENT_BIN} -s 1024 -l d -t 1 -E -1 -x 901 > stdlog
passed=`grep ">>>>>>>> pass:1" stdlog`
result=`grep -c "cert_verify_failed_notify|" stdlog`
if [ -n "$passed" ] && [ "$result" -eq 0 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "cert_verify_failed_notify_accept" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "cert_verify_failed_notify_accept" "fail"
fi
}

case_fork_core_NAT_rebinding_IP_change_cwnd_reset()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e -M > /dev/null
clear_log
echo -e "NAT rebinding IP change cwnd reset ...\c"
case_test_sudo ${CLIENT_BIN} -s 102400 -l d -t 3 -M -i lo -i lo -E -n 2 -x 105 > stdlog
result=`grep ">>>>>>>> pass:0" stdlog`
errlog=`grep_err_log`
rebind=`grep "|path:0|REBINDING|validate NAT rebinding addr|" slog`
# RFC 9000 §9.4 ¶1 MUST: IP changed -> reset; assert srtt=initial_rtt to catch
# impls that reset cwnd but forget RTT.
cwnd_reset=`grep "|path:0|MIGRATION|cwnd_rtt_reset|srtt:250000|" slog`
if [ -z "$errlog" ] && [ "$rebind" != "" ] && [ "$cwnd_reset" != "" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "NAT_rebinding_IP_change_cwnd_reset" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "NAT_rebinding_IP_change_cwnd_reset" "fail"
fi
grep_err_log
}

case_fork_core_NAT_rebinding_port_only_retain()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e -M > /dev/null
clear_log
echo -e "NAT rebinding port-only retain ...\c"
case_test_sudo ${CLIENT_BIN} -s 102400 -l d -t 3 -M -i lo -i lo -E -n 2 -x 106 > stdlog
result=`grep ">>>>>>>> pass:0" stdlog`
errlog=`grep_err_log`
rebind=`grep "|path:0|REBINDING|validate NAT rebinding addr|" slog`
# RFC 9000 §9.4 paragraph 1 carve-out: port-only change MAY retain.
# Negative assertion: cwnd_rtt_reset MUST NOT appear.
cwnd_reset=`grep "|path:0|MIGRATION|cwnd_rtt_reset|" slog`
if [ -z "$errlog" ] && [ "$rebind" != "" ] && [ -z "$cwnd_reset" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "NAT_rebinding_port_only_retain" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "NAT_rebinding_port_only_retain" "fail"
fi
grep_err_log
}

case_fork_core_MP_datagrams_leave_silently_failed_path()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e -M -Q 65535 -U 1 > /dev/null
clear_log
echo -e "MP datagrams leave a silently failed path ...\c"
case_test_sudo ${CLIENT_BIN} -l d -t 3 -M -i lo -i lo -x 1300 -Q 65535 -U 1 -T 1 -e 1000 --epoch_timeout 20000 > stdlog
result=`grep "\[dgram\]|silent_path|sent:" stdlog`
max_gap=`echo "$result" | sed -n 's/.*|max_gap_ms:\([0-9]*\)|.*/\1/p'`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:1" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$max_gap" ] && [ "$max_gap" -lt 1000 ] && [ -n "$cli_res" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_datagrams_leave_silently_failed_path" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MP_datagrams_leave_silently_failed_path" "fail"
fi
grep_err_log
}

case_fork_core_MP_datagrams_resume_after_all_paths_failed_silently()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e -M -Q 65535 -U 1 > /dev/null
clear_log
echo -e "MP datagrams resume after every path failed silently ...\c"
case_test_sudo ${CLIENT_BIN} -l d -t 3 -M -i lo -i lo -x 1301 -Q 65535 -U 1 -T 1 -e 1000 --epoch_timeout 20000 > stdlog
result=`grep "\[dgram\]|silent_path|sent:" stdlog`
resume=`echo "$result" | sed -n 's/.*|resume_ms:\([0-9]*\)|.*/\1/p'`
cli_res=`grep -E "xqc_conn_destroy.*mp_enable:1" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$resume" ] && [ "$resume" -lt 2000 ] && [ -n "$cli_res" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_datagrams_resume_after_all_paths_failed_silently" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "MP_datagrams_resume_after_all_paths_failed_silently" "fail"
fi
grep_err_log
}

# 727 happy path: default cap, lossy echo transfer completes and the cap
# machinery stays quiet (no buffered-count rejections logged).
# -t is an idle limit, longer than the server PTO after a lossy first handshake.
case_fork_core_stream_reassembly_cap_happy()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e > /dev/null
clear_log
echo -e "stream reassembly cap happy path ...\c"
result=`${CLIENT_BIN} -s 2048000 -l d -t 30 -E -d 300 -x 727|grep ">>>>>>>> pass:1"`
cap_hit=`grep "stream frame buffered count exceed" slog`
if [ -n "$result" ] && [ -z "$cap_hit" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "stream_reassembly_cap_happy" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "stream_reassembly_cap_happy" "fail"
fi
}

# 728 abnormal path: the server shrinks the reassembly cap to 16, the
# client-side drop rate forces cap rejections; the transfer must still
# complete and the server must not report a packet processing failure.
case_fork_core_stream_reassembly_cap_pressure_recovery()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e -x 728 > /dev/null
clear_log
echo -e "stream reassembly cap pressure recovery ...\c"
result=`${CLIENT_BIN} -s 65536 -l d -t 12 -E -d 150 -x 728|grep ">>>>>>>> pass:1"`
cap_hit=`grep "stream frame buffered count exceed" slog`
fatal=`grep "fail to process packets" slog`
if [ -n "$result" ] && [ -n "$cap_hit" ] && [ -z "$fatal" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "stream_reassembly_cap_pressure_recovery" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "stream_reassembly_cap_pressure_recovery" "fail"
fi
}

# 735 happy path: both ends set max_pkt_out_size to its cap, 1436. The
# datagram MSS is 1420 and a 1 MB datagram echo completes with full
# 1452-byte UDP payloads and none larger, so no ACK is added to a full
# packet.
case_fork_core_max_pkt_out_size_at_cap()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server stdbuf -oL ${SERVER_BIN} -l e -Q 65535 -e -U 1 -x 735 > svr_stdlog
clear_log
echo -e "max_pkt_out_size at its cap ...\c"
${CLIENT_BIN} -l e -T 1 -s 1048576 -U 1 -Q 65535 -E -x 735 > stdlog
cli_mss=`grep "\[dgram-735\]|1RTT|updated_mss:1420|" stdlog`
svr_mss=`grep -a "\[dgram-735\]|1RTT|initial_mss:1420|" svr_stdlog`
echo_ok=`grep "\[dgram\]|echo_check|same_content:yes|" stdlog`
cli_max=`grep "\[udp-735\]|max|size:1452|" stdlog`
svr_max=`grep -a "\[udp-735\]|max|size:1452|" svr_stdlog`
oversize=`grep -a "\[udp-735\]|oversize|" stdlog svr_stdlog`
errlog=`grep_err_log`
if [ -n "$cli_mss" ] && [ -n "$svr_mss" ] && [ -n "$echo_ok" ] \
    && [ -n "$cli_max" ] && [ -n "$svr_max" ] && [ -z "$oversize" ] \
    && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "max_pkt_out_size_at_cap" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "max_pkt_out_size_at_cap" "fail"
fi
}

# 736 abnormal path: both ends ask for max_pkt_out_size 1500, above the cap.
# It is clamped to 1436, so the MSS is 1420, a 1421-byte datagram is refused
# with EDGRAM_TOO_LARGE, and no UDP payload exceeds 1452.
case_fork_core_max_pkt_out_size_above_cap()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server stdbuf -oL ${SERVER_BIN} -l e -Q 65535 -e -U 1 -x 736 > svr_stdlog
clear_log
echo -e "max_pkt_out_size above its cap ...\c"
${CLIENT_BIN} -l d -T 1 -s 4800 -U 1 -Q 65535 -E -x 736 > stdlog
cli_mss=`grep "\[dgram-735\]|1RTT|updated_mss:1420|" stdlog`
svr_mss=`grep -a "\[dgram-735\]|1RTT|initial_mss:1420|" svr_stdlog`
refused=`grep "datagram_is_too_large" clog`
oversized=`grep "oversized_datagram|recorded_mss:1421|send_size:1421|" stdlog`
oversize=`grep -a "\[udp-735\]|oversize|" stdlog svr_stdlog`
errlog=`grep_err_log`
if [ -n "$cli_mss" ] && [ -n "$svr_mss" ] && [ -n "$refused" ] \
    && [ -n "$oversized" ] && [ -z "$oversize" ] && [ -z "$errlog" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "max_pkt_out_size_above_cap" "pass"
else
    echo ">>>>>>>> pass:0"
    case_print_result "max_pkt_out_size_above_cap" "fail"
fi
}

# 802 happy path: the client writes its only request before its second path
# is validated, and that path then carries no data. The end-of-pass check
# marks it app-limited (RFC 9002 Section 7.8); the write-time check never
# runs while it is active.
case_fork_core_MP_idle_path_marked_app_limited_after_send()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e -M > /dev/null
clear_log
echo -e "MP idle path marked app-limited after the send step ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 1 -E -T 1 -M -i lo -i lo -x 802 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
marked=`grep "xqc_sample_check_app_limited_after_send|path:1|applimit:" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$marked" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_idle_path_marked_app_limited_after_send" "pass"
else
    echo ">>>>>>>> pass:0 (result:${result:+y} marked:${marked:+y} errlog:${errlog:+y})"
    case_print_result "MP_idle_path_marked_app_limited_after_send" "fail"
fi
grep_err_log
}

# 803 abnormal path: everything the client sends on its second path is lost,
# so the path never validates and is abandoned at its validation deadline.
# The end-of-pass check marks the initial path but never the path that did
# not become active, and every echo completes on the initial path.
case_fork_core_MP_unvalidated_path_never_marked_app_limited()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e -M > /dev/null
clear_log
echo -e "MP unvalidated path never marked app-limited ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024 -l d -t 3 -E -T 1 -M -i lo -i lo -x 803 -e 8 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
failed=`grep ">>>>>>>> pass:0" stdlog`
abandoned=`grep "|G-P3 validation timeout|path_id:1|" clog`
marked0=`grep "xqc_sample_check_app_limited_after_send|path:0|applimit:" clog`
marked1=`grep "xqc_sample_check_app_limited_after_send|path:1|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -z "$failed" ] \
    && [ -n "$abandoned" ] && [ -n "$marked0" ] && [ -z "$marked1" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "MP_unvalidated_path_never_marked_app_limited" "pass"
else
    echo ">>>>>>>> pass:0 (result:${result:+y} failed:${failed:+y} abandoned:${abandoned:+y}" \
        "marked0:${marked0:+y} marked1:${marked1:+y} errlog:${errlog:+y})"
    case_print_result "MP_unvalidated_path_never_marked_app_limited" "fail"
fi
grep_err_log
}

# RFC 9000 Section 14.4: the loss of a PMTU probe SHOULD NOT trigger a
# congestion control reaction. The client path drops every datagram above
# 1300 bytes, which only PMTUD probes exceed.
# 804 happy path: the probes are lost, the transfer completes, and no packet
# is marked lost, so no congestion event starts.
case_fork_core_lost_pmtud_probe_no_congestion_event()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e --pmtud 1 > /dev/null
clear_log
echo -e "lost PMTUD probes start no congestion event ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024000 -l d -t 1 -E --pmtud 1 -x 804 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
probe_lost=`grep "|PMTUD probe lost|" clog`
marked=`grep "|mark lost|" clog`
cc_event=`grep "|OnLostDetection|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$probe_lost" ] \
    && [ -z "$marked" ] && [ -z "$cc_event" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "lost_pmtud_probe_no_congestion_event" "pass"
else
    echo ">>>>>>>> pass:0 (result:${result:+y} probe_lost:${probe_lost:+y}" \
        "marked:${marked:+y} cc_event:${cc_event:+y} errlog:${errlog:+y})"
    case_print_result "lost_pmtud_probe_no_congestion_event" "fail"
fi
grep_err_log
}

# 805 abnormal path: the same path also drops one ordinary full-size packet.
# That packet is still marked lost and starts a congestion event, next to
# the probes that do not.
case_fork_core_lost_data_packet_congestion_event()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e --pmtud 1 > /dev/null
clear_log
echo -e "a lost data packet still starts a congestion event ...\c"
case_test_sudo ${CLIENT_BIN} -s 1024000 -l d -t 1 -E --pmtud 1 -x 805 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
probe_lost=`grep "|PMTUD probe lost|" clog`
marked=`grep "|mark lost|" clog`
cc_event=`grep "|OnLostDetection|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$probe_lost" ] \
    && [ -n "$marked" ] && [ -n "$cc_event" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "lost_data_packet_congestion_event" "pass"
else
    echo ">>>>>>>> pass:0 (result:${result:+y} probe_lost:${probe_lost:+y}" \
        "marked:${marked:+y} cc_event:${cc_event:+y} errlog:${errlog:+y})"
    case_print_result "lost_data_packet_congestion_event" "fail"
fi
grep_err_log
}

# 806, RFC 8899 Section 4.3: after 300 datagrams above 1300 bytes got through,
# the client path drops every one of them. The black hole must be detected,
# the packet size go back to the base and the lost stream packets be split
# into packets that fit: the transfer completes and the echo matches.
case_fork_core_pmtud_blackhole_stream_split()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e --pmtud 1 > /dev/null
clear_log
echo -e "PMTUD black hole mid-transfer, stream data split ...\c"
case_test_sudo ${CLIENT_BIN} -s 20480000 -l d -t 10 -E --pmtud 1 -x 806 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
blackhole=`grep "|PMTUD black hole|.*|back to:1200|" clog`
split=`grep "|split lost packet|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$blackhole" ] && [ -n "$split" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "pmtud_blackhole_stream_split" "pass"
else
    echo ">>>>>>>> pass:0 (result:${result:+y} blackhole:${blackhole:+y}" \
        "split:${split:+y} errlog:${errlog:+y})"
    case_print_result "pmtud_blackhole_stream_split" "fail"
fi
grep_err_log
}

# 807: the path carries only 1260 bytes, less than the base size (1298),
# from the start. The black hole at the base size is confirmed while the
# small packets get through, so the size goes down to the floor (1200),
# the search finds what fits, and the transfer completes.
case_fork_core_pmtud_path_below_base()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e --pmtud 1 > /dev/null
clear_log
echo -e "PMTUD path smaller than the base size ...\c"
case_test_sudo ${CLIENT_BIN} -s 10240000 -l d -t 10 -E --pmtud 1 -x 807 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
floor=`grep "|PMTUD black hole|.*|back to:1200|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$floor" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "pmtud_path_below_base" "pass"
else
    echo ">>>>>>>> pass:0 (result:${result:+y} floor:${floor:+y} errlog:${errlog:+y})"
    case_print_result "pmtud_path_below_base" "fail"
fi
grep_err_log
}

# 808: an outage at the base size loses packets of every size, the probes
# sent during it included: it is not a black hole and the size stays at the
# base.
case_fork_core_pmtud_outage_stays_at_base()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e --pmtud 1 > /dev/null
clear_log
echo -e "PMTUD outage does not go below the base size ...\c"
case_test_sudo ${CLIENT_BIN} -s 10240000 -l d -t 10 -E --pmtud 1 -x 808 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
floor=`grep "|PMTUD black hole|.*|back to:1200|" clog`
# the path was suspect during the outage: probes at the base size were lost
probed=`grep -c "|PMTUD probe lost|.*|size:1298|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -z "$floor" ] && [ "$probed" -ge 2 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "pmtud_outage_stays_at_base" "pass"
else
    echo ">>>>>>>> pass:0 (result:${result:+y} floor:${floor:+y} probed:$probed errlog:${errlog:+y})"
    case_print_result "pmtud_outage_stays_at_base" "fail"
fi
grep_err_log
}

# 809: the second path carries only 1300 bytes from the start. Its
# PATH_CHALLENGE is expanded to 1200 bytes (RFC 9000 Section 8.2.1), not to
# the size of the first path, so it validates, and the transfer completes.
case_fork_core_pmtud_smaller_second_path_validates()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e --pmtud 1 -M > /dev/null
clear_log
echo -e "PMTUD second path smaller than the first validates ...\c"
case_test_sudo ${CLIENT_BIN} -s 10240000 -l d -t 10 -E --pmtud 1 -M -i lo -i lo -x 809 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
validated=`grep "|path validated|path_id:1|" clog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$validated" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "pmtud_smaller_second_path_validates" "pass"
else
    echo ">>>>>>>> pass:0 (result:${result:+y} validated:${validated:+y} errlog:${errlog:+y})"
    case_print_result "pmtud_smaller_second_path_validates" "fail"
fi
grep_err_log
}

# 810: the same second path, added one second in, once the first path has
# grown: it starts from the base size, the connection goes back down to it
# and searches again, and the transfer completes.
case_fork_core_pmtud_new_path_starts_at_base()
{
rm -rf tp_localhost test_session xqc_token
case_test_start_server ${SERVER_BIN} -l d -e --pmtud 1 -M > /dev/null
clear_log
echo -e "PMTUD new path starts from the base size ...\c"
case_test_sudo ${CLIENT_BIN} -s 20480000 -l d -t 15 -E --pmtud 1 -M -i lo -i lo -x 810 > stdlog
result=`grep ">>>>>>>> pass:1" stdlog`
validated=`grep "|path validated|path_id:1|" clog`
newpath=`grep "|PMTUD|new path|path:1|size:1298|" clog | grep -v "|was:1298|"`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$result" ] && [ -n "$validated" ] && [ -n "$newpath" ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "pmtud_new_path_starts_at_base" "pass"
else
    echo ">>>>>>>> pass:0 (result:${result:+y} validated:${validated:+y} newpath:${newpath:+y} errlog:${errlog:+y})"
    case_print_result "pmtud_new_path_starts_at_base" "fail"
fi
grep_err_log
}

# 811: size-specific black-hole recovery with bidirectional datagrams.
case_fork_core_pmtud_path_shrinks_by_8_bytes()
{
case_test_start_server ${SERVER_BIN} -l d -e -Q 65535 -U 1 --pmtud 1 > /dev/null
rm -rf tp_localhost test_session xqc_token
clear_log
echo -e "PMTUD path shrinks by 8 bytes ...\c"
case_test_sudo ${CLIENT_BIN} -s 51200000 -l d -t 15 -E -Q 65535 -U 1 -T 1 --pmtud 1 -x 811 > stdlog
blackhole=`grep "|PMTUD black hole|" clog`
dropped=`grep -c "\[case 811\] dropped" stdlog`
errlog=`grep_err_log`
if [ -z "$errlog" ] && [ -n "$blackhole" ] && [ "$dropped" -lt 100 ]; then
    echo ">>>>>>>> pass:1"
    case_print_result "pmtud_path_shrinks_by_8_bytes" "pass"
else
    echo ">>>>>>>> pass:0 (blackhole:${blackhole:+y} dropped:${dropped} errlog:${errlog:+y})"
    case_print_result "pmtud_path_shrinks_by_8_bytes" "fail"
fi
grep_err_log
}

case_test_case "cert_verify_failed_notify_reject" --id 900 --mode self-reporting --run case_fork_core_cert_verify_failed_notify_reject
case_test_case "cert_verify_failed_notify_accept" --id 901 --mode self-reporting --run case_fork_core_cert_verify_failed_notify_accept
case_test_case "NAT_rebinding_IP_change_cwnd_reset" --id native --mode self-reporting --run case_fork_core_NAT_rebinding_IP_change_cwnd_reset
case_test_case "NAT_rebinding_port_only_retain" --id native --mode self-reporting --run case_fork_core_NAT_rebinding_port_only_retain
case_test_case "MP_datagrams_leave_silently_failed_path" --id 1300 --mode self-reporting --run case_fork_core_MP_datagrams_leave_silently_failed_path
case_test_case "MP_datagrams_resume_after_all_paths_failed_silently" --id 1301 --mode self-reporting --run case_fork_core_MP_datagrams_resume_after_all_paths_failed_silently
case_test_case "stream_reassembly_cap_happy" --id 727 --mode self-reporting --run case_fork_core_stream_reassembly_cap_happy
case_test_case "stream_reassembly_cap_pressure_recovery" --id 728 --mode self-reporting --run case_fork_core_stream_reassembly_cap_pressure_recovery
case_test_case "max_pkt_out_size_at_cap" --id 735 --mode self-reporting --run case_fork_core_max_pkt_out_size_at_cap
case_test_case "max_pkt_out_size_above_cap" --id 736 --mode self-reporting --run case_fork_core_max_pkt_out_size_above_cap
case_test_case "MP_idle_path_marked_app_limited_after_send" --id 802 --mode self-reporting --run case_fork_core_MP_idle_path_marked_app_limited_after_send
case_test_case "MP_unvalidated_path_never_marked_app_limited" --id 803 --mode self-reporting --run case_fork_core_MP_unvalidated_path_never_marked_app_limited
case_test_case "lost_pmtud_probe_no_congestion_event" --id 804 --mode self-reporting --run case_fork_core_lost_pmtud_probe_no_congestion_event
case_test_case "lost_data_packet_congestion_event" --id 805 --mode self-reporting --run case_fork_core_lost_data_packet_congestion_event
case_test_case "pmtud_blackhole_stream_split" --id 806 --mode self-reporting --run case_fork_core_pmtud_blackhole_stream_split
case_test_case "pmtud_path_below_base" --id 807 --mode self-reporting --run case_fork_core_pmtud_path_below_base
case_test_case "pmtud_outage_stays_at_base" --id 808 --mode self-reporting --run case_fork_core_pmtud_outage_stays_at_base
case_test_case "pmtud_smaller_second_path_validates" --id 809 --mode self-reporting --run case_fork_core_pmtud_smaller_second_path_validates
case_test_case "pmtud_new_path_starts_at_base" --id 810 --mode self-reporting --run case_fork_core_pmtud_new_path_starts_at_base

case_test_case "pmtud_path_shrinks_by_8_bytes" --id 811 --mode self-reporting --run case_fork_core_pmtud_path_shrinks_by_8_bytes

if case_test_is_discovery; then
    case_test_run
    exit 0
fi

case_test_enter_work_dir
trap 'case_test_stop_server; case_test_cleanup_udp_port' EXIT

case_test_run
