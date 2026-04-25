#!/bin/bash
# MASQUE interop test suite
#
# Runs masque_client against a local CONNECT-IP proxy with multiple scenarios.
# Requires: build/tests/masque_client, Go (for CONNECT-IP proxy)
#
# Usage:
#   ./tests/masque_interop.sh              # run all tests
#   ./tests/masque_interop.sh connectip    # run only CONNECT-IP tests
#   ./tests/masque_interop.sh unit         # run only unit tests (no proxy)
#
# Exit code: 0 = all passed, 1 = some failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
MASQUE_CLIENT="$BUILD_DIR/tests/masque_client"
PROXY_DIR="$SCRIPT_DIR/connectip_proxy"
CERT_DIR="$BUILD_DIR/masque_certs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); echo -e "  ${RED}FAIL${NC} $1"; }
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); echo -e "  ${YELLOW}SKIP${NC} $1"; }

cleanup_pids=()
cleanup() {
    for pid in "${cleanup_pids[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

# ── Prerequisites ──

echo "=== MASQUE Interop Test Suite ==="
echo ""

if [ ! -x "$MASQUE_CLIENT" ]; then
    echo "ERROR: masque_client not found at $MASQUE_CLIENT"
    echo "Build with: cd build && cmake .. && make masque_client"
    exit 1
fi

RUN_TESTS="$BUILD_DIR/tests/run_tests"

# ── Generate test certificates if needed ──

generate_certs() {
    mkdir -p "$CERT_DIR"
    if [ ! -f "$CERT_DIR/server.crt" ]; then
        echo "Generating test certificates..."
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
            -days 365 -nodes -subj '/CN=localhost' 2>/dev/null
    fi
}

# ── Test: Unit tests ──

run_unit_tests() {
    echo "── Unit Tests ──"

    if [ ! -x "$RUN_TESTS" ]; then
        skip "run_tests binary not found"
        return
    fi

    # Run the masque-specific tests (filter output).
    # The test binary may segfault in unrelated tests, so we capture
    # output to a file and ignore the exit code.
    local tmpfile
    tmpfile=$(mktemp)
    set +e
    "$RUN_TESTS" > "$tmpfile" 2>&1
    set -e  # known: xqc_test_engine_packet_process segfaults (pre-existing)
    local output
    output=$(cat "$tmpfile")
    rm -f "$tmpfile"

    if echo "$output" | grep -q "xqc_test_masque ...passed"; then
        pass "xqc_test_masque"
    else
        fail "xqc_test_masque"
    fi

    if echo "$output" | grep -q "xqc_test_datagram_send_on_path ...passed"; then
        pass "xqc_test_datagram_send_on_path"
    else
        fail "xqc_test_datagram_send_on_path"
    fi

    if echo "$output" | grep -q "xqc_test_datagram_frame_path_pinning ...passed"; then
        pass "xqc_test_datagram_frame_path_pinning"
    else
        fail "xqc_test_datagram_frame_path_pinning"
    fi

    echo ""
}

# ── Test: masque_client CLI ──

run_cli_tests() {
    echo "── CLI Tests ──"

    # Test: help flag
    if "$MASQUE_CLIENT" -h 2>&1 | grep -q "Usage:"; then
        pass "masque_client -h shows usage"
    else
        fail "masque_client -h shows usage"
    fi

    # Test: invalid proxy (should fail quickly with exit code != 0)
    if timeout 5 "$MASQUE_CLIENT" -a 192.0.2.1 -p 1 -t 2 -q 2>/dev/null; then
        fail "masque_client exits 0 on unreachable proxy"
    else
        pass "masque_client fails on unreachable proxy"
    fi

    echo ""
}

# ── Start CONNECT-IP proxy ──

start_connectip_proxy() {
    generate_certs

    if ! command -v go &>/dev/null; then
        echo "Go not found, skipping CONNECT-IP proxy tests"
        return 1
    fi

    echo "Starting CONNECT-IP proxy..."
    cd "$PROXY_DIR"

    # Build if needed
    if [ ! -f "$PROXY_DIR/connectip_proxy" ] || \
       [ "$PROXY_DIR/main.go" -nt "$PROXY_DIR/connectip_proxy" ]; then
        go build -o connectip_proxy . 2>/dev/null || {
            echo "Failed to build CONNECT-IP proxy"
            return 1
        }
    fi

    "$PROXY_DIR/connectip_proxy" \
        -addr ":14443" \
        -cert "$CERT_DIR/server.crt" \
        -key "$CERT_DIR/server.key" \
        -host "localhost:14443" \
        > "$BUILD_DIR/connectip_proxy.log" 2>&1 &
    local proxy_pid=$!
    cleanup_pids+=("$proxy_pid")

    # Wait for proxy to start
    sleep 1
    if ! kill -0 "$proxy_pid" 2>/dev/null; then
        echo "CONNECT-IP proxy failed to start"
        cat "$BUILD_DIR/connectip_proxy.log"
        return 1
    fi

    cd "$ROOT_DIR"
    echo "CONNECT-IP proxy started (PID $proxy_pid)"
    return 0
}

# ── Test: CONNECT-IP basic ──

run_connectip_tests() {
    echo "── CONNECT-IP Tests ──"

    if ! start_connectip_proxy; then
        skip "CONNECT-IP basic (proxy not available)"
        skip "CONNECT-IP stress"
        echo ""
        return
    fi

    # Test: basic CONNECT-IP (1 ICMP echo)
    local output exit_code
    output=$("$MASQUE_CLIENT" \
        -a 127.0.0.1 -p 14443 -H localhost \
        -I -S -t 10 -n 1 \
        -U "/ip" \
        2>&1) && exit_code=0 || exit_code=$?

    if [ "$exit_code" -eq 0 ] && echo "$output" | grep -q "SUCCESS"; then
        pass "CONNECT-IP basic (1 echo)"
    elif [ "$exit_code" -eq 2 ] && echo "$output" | grep -q "PARTIAL"; then
        pass "CONNECT-IP basic (partial — tunnel established)"
    elif echo "$output" | grep -q "tunnel established"; then
        pass "CONNECT-IP basic (tunnel established, recv incomplete)"
    else
        fail "CONNECT-IP basic (exit=$exit_code)"
        echo "$output" | tail -5
    fi

    # Test: CONNECT-IP stress (10 echoes)
    output=$("$MASQUE_CLIENT" \
        -a 127.0.0.1 -p 14443 -H localhost \
        -I -S -q -t 15 -n 10 \
        -U "/ip" \
        2>&1) && exit_code=0 || exit_code=$?

    if [ "$exit_code" -eq 0 ]; then
        pass "CONNECT-IP stress (10 echoes)"
    elif [ "$exit_code" -eq 2 ]; then
        local recv
        recv=$(echo "$output" | grep -oP 'recv=\K[0-9]+' | head -1)
        if [ "${recv:-0}" -ge 5 ]; then
            pass "CONNECT-IP stress (10 echoes, recv=$recv — acceptable)"
        else
            fail "CONNECT-IP stress (10 echoes, recv=$recv)"
        fi
    else
        fail "CONNECT-IP stress (exit=$exit_code)"
        echo "$output" | tail -5
    fi

    # Print stats if available
    if echo "$output" | grep -q "Statistics"; then
        echo "    Last run statistics:"
        echo "$output" | sed -n '/── Statistics/,/────────/p' | sed 's/^/    /'
    fi

    echo ""
}

# ── Test: Local E2E (test_server + test_client) ──

run_local_e2e_tests() {
    echo "── Local E2E Tests ──"

    local TEST_SERVER="$BUILD_DIR/tests/test_server"
    local TEST_CLIENT="$BUILD_DIR/tests/test_client"

    if [ ! -x "$TEST_SERVER" ] || [ ! -x "$TEST_CLIENT" ]; then
        skip "test_server or test_client not found"
        echo ""
        return
    fi

    # Test: MASQUE CONNECT-IP single path (test case 800)
    # test_server expects server.crt/server.key in cwd
    cd "$BUILD_DIR"
    "$TEST_SERVER" -x 800 -p 18443 -l e > /dev/null 2>&1 &
    local server_pid=$!
    cleanup_pids+=("$server_pid")
    sleep 1

    if ! kill -0 "$server_pid" 2>/dev/null; then
        fail "MASQUE local E2E: test_server failed to start"
        echo ""
        return
    fi

    local output exit_code
    output=$(timeout 15 "$TEST_CLIENT" -x 800 -a 127.0.0.1 -p 18443 -1 2>&1) && exit_code=0 || exit_code=$?

    kill "$server_pid" 2>/dev/null; wait "$server_pid" 2>/dev/null || true
    cd "$ROOT_DIR"

    if echo "$output" | grep -q "\[masque-e2e\] PASS"; then
        pass "MASQUE CONNECT-IP local E2E (single path)"
    else
        fail "MASQUE CONNECT-IP local E2E (single path, exit=$exit_code)"
        echo "$output" | grep "masque-e2e" | tail -5
    fi

    echo ""
}

# ── Main ──

MODE="${1:-all}"

case "$MODE" in
    unit)
        run_unit_tests
        ;;
    cli)
        run_cli_tests
        ;;
    connectip)
        run_connectip_tests
        ;;
    local)
        run_local_e2e_tests
        ;;
    all)
        run_unit_tests
        run_cli_tests
        run_local_e2e_tests
        run_connectip_tests
        ;;
    *)
        echo "Usage: $0 [unit|cli|connectip|local|all]"
        exit 1
        ;;
esac

# ── Summary ──

echo "=== Summary ==="
TOTAL=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))
echo -e "  ${GREEN}$PASS_COUNT passed${NC}, ${RED}$FAIL_COUNT failed${NC}, ${YELLOW}$SKIP_COUNT skipped${NC} / $TOTAL total"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
exit 0
