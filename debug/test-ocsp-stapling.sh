#!/bin/bash

# OCSP Stapling Integration Test
# Tests that OCSP hooks work correctly in both TLS 1.2 and TLS 1.3

set -e

# Configuration
SERVER_PORT=14443
SERVER_PID=""
TIMEOUT=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        log_info "Stopping test server (PID: $SERVER_PID)..."
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    
    # Clean up any remaining processes
    pkill -f "tls-ocsp-test" 2>/dev/null || true
}

# Set up trap for cleanup
trap cleanup EXIT

# Start the test server
start_server() {
    local tls_version="$1"
    
    log_info "Starting OCSP test server for TLS $tls_version..."
    
    local version_flag=""
    if [[ "$tls_version" == "1.2" ]]; then
        version_flag="--tls12"
    elif [[ "$tls_version" == "1.3" ]]; then
        version_flag="--tls13"
    fi
    
    # Start server in background
    stack exec tls-ocsp-test -- --port $SERVER_PORT $version_flag --verbose \
        > "server-$tls_version.log" 2>&1 &
    
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 3
    
    # Check if server is running
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        log_error "Server failed to start"
        cat "server-$tls_version.log"
        return 1
    fi
    
    log_success "Server started (PID: $SERVER_PID)"
}

# Test TLS connection with OpenSSL
test_tls_connection() {
    local tls_version="$1"
    local test_name="TLS $tls_version OCSP Stapling"
    
    log_info "Testing $test_name..."
    
    local openssl_version=""
    if [[ "$tls_version" == "1.2" ]]; then
        openssl_version="-tls1_2"
    elif [[ "$tls_version" == "1.3" ]]; then
        openssl_version="-tls1_3"
    fi
    
    # Run OpenSSL client test
    local output_file="client-$tls_version.log"
    
    # Test with OCSP status request
    echo -e "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | \
        timeout $TIMEOUT openssl s_client \
            -connect localhost:$SERVER_PORT \
            $openssl_version \
            -status \
            -verify_return_error \
            -CAfile "../test-certs/ca.crt" \
            > "$output_file" 2>&1
    
    local client_exit_code=$?
    
    # Analyze results
    local hook_called=false
    local ocsp_delivered=false
    local clean_handshake=false
    
    # Check server logs for hook calls OR check if OCSP response contains our test data
    if grep -q "OCSP HOOK CALLED" "server-$tls_version.log" || grep -q "Produced At: Jul  5 06:17:23 2025" "$output_file"; then
        hook_called=true
    fi
    
    # Check client output for OCSP response
    if grep -q "OCSP response:" "$output_file"; then
        ocsp_delivered=true
    fi
    
    # Check for clean handshake (no critical alerts or errors)
    if grep -qE "(alert.*fatal|error|fail)" "$output_file"; then
        clean_handshake=false
    else
        clean_handshake=true
    fi
    
    # Report results
    echo
    echo "=== $test_name Results ==="
    
    if $hook_called; then
        log_success "✓ OCSP hook was called"
    else
        log_error "✗ OCSP hook was NOT called"
    fi
    
    if $ocsp_delivered; then
        log_success "✓ OCSP response was delivered to client"
    else
        log_error "✗ OCSP response was NOT delivered"
    fi
    
    if $clean_handshake; then
        log_success "✓ Clean TLS handshake (no fatal alerts/errors)"
    else
        log_error "✗ TLS handshake had critical errors"
    fi
    
    # Overall test result
    if $hook_called && $ocsp_delivered; then
        log_success "✓ $test_name: PASSED"
        return 0
    else
        log_error "✗ $test_name: FAILED"
        echo
        echo "Server log excerpt:"
        tail -10 "server-$tls_version.log" || true
        echo
        echo "Client log excerpt:"
        tail -10 "$output_file" || true
        return 1
    fi
}

# Run a single test
run_single_test() {
    local tls_version="$1"
    
    log_info "=== Testing TLS $tls_version ==="
    
    # Start server for this TLS version
    start_server "$tls_version"
    
    # Run the test
    if test_tls_connection "$tls_version"; then
        log_success "TLS $tls_version test PASSED"
        local result=0
    else
        log_error "TLS $tls_version test FAILED"
        local result=1
    fi
    
    # Stop server
    if [[ -n "$SERVER_PID" ]]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
        SERVER_PID=""
    fi
    
    return $result
}

# Main test function
run_all_tests() {
    log_info "Starting OCSP Stapling Integration Tests"
    log_info "========================================="
    
    # Build the test server
    log_info "Building OCSP test server..."
    stack build tls-debug:tls-ocsp-test
    
    # Run tests
    local failed_tests=0
    
    log_info ""
    if ! run_single_test "1.2"; then
        ((failed_tests++))
    fi
    
    sleep 2
    
    log_info ""
    if ! run_single_test "1.3"; then
        ((failed_tests++))
    fi
    
    # Final results
    echo
    echo "==========================================="
    echo "OCSP Stapling Integration Test Results"
    echo "==========================================="
    
    if [[ $failed_tests -eq 0 ]]; then
        log_success "All tests PASSED! 🎉"
        log_success "OCSP stapling is working correctly in both TLS 1.2 and TLS 1.3"
        return 0
    else
        log_error "$failed_tests test(s) FAILED"
        log_error "Check the logs for details"
        return 1
    fi
}

# Check if certificates exist
if [[ ! -f "../test-certs/server.rsa.crt" || ! -f "../test-certs/server.rsa.key" || ! -f "../test-certs/ca.crt" ]]; then
    log_error "Required certificates not found. Expected files:"
    log_error "  ../test-certs/server.rsa.crt"
    log_error "  ../test-certs/server.rsa.key" 
    log_error "  ../test-certs/ca.crt"
    exit 1
fi

# Run the main test suite
run_all_tests