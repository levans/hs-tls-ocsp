#!/bin/bash

# OCSP Stapling Integration Test Suite
# 
# This script provides comprehensive testing of OCSP stapling functionality
# in the hs-tls library. It verifies that:
#
# 1. OCSP hooks are called during TLS handshakes
# 2. OCSP responses are correctly formatted and delivered
# 3. Both TLS 1.2 and TLS 1.3 handle OCSP stapling properly
# 4. OpenSSL clients accept the OCSP responses without errors

set -e

# Configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PORT=14443
SERVER_PID=""
CERT_DIR="$TEST_DIR/certs"
LOG_DIR="$TEST_DIR/logs"
TIMEOUT=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
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
    pkill -f "OCSPTestServer" 2>/dev/null || true
}

# Set up trap for cleanup
trap cleanup EXIT

# Create necessary directories
setup_directories() {
    log_info "Setting up test directories..."
    mkdir -p "$CERT_DIR"
    mkdir -p "$LOG_DIR"
}

# Generate test certificates
generate_certificates() {
    log_info "Generating test certificates..."
    
    cd "$CERT_DIR"
    
    # Generate CA key and certificate
    if [[ ! -f ca.key || ! -f ca.crt ]]; then
        log_info "Generating CA certificate..."
        openssl genrsa -out ca.key 2048
        openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/C=US/O=OCSP-Test-CA/CN=Test-CA"
    fi
    
    # Generate server key and certificate
    if [[ ! -f server.key || ! -f server.crt ]]; then
        log_info "Generating server certificate..."
        openssl genrsa -out server.key 2048
        openssl req -new -key server.key -out server.csr -subj "/C=US/O=Test-Server/CN=localhost"
        openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365
        rm server.csr
    fi
    
    cd "$TEST_DIR"
    log_success "Certificates ready"
}

# Compile the test server
compile_server() {
    log_info "Compiling OCSP test server..."
    
    cd "$TEST_DIR"
    
    # Use stack to compile if available, otherwise try cabal, finally ghc
    if command -v stack &> /dev/null && [[ -f "../../../stack.yaml" ]]; then
        log_info "Using stack to compile..."
        cd ../../..
        stack ghc -- test/integration/ocsp/OCSPTestServer.hs -o test/integration/ocsp/OCSPTestServer -threaded -rtsopts 2>&1 | tee "$TEST_DIR/$LOG_DIR/compile.log"
        cd "$TEST_DIR"
        EXECUTABLE="./OCSPTestServer"
    elif command -v cabal &> /dev/null; then
        log_info "Using cabal to compile..."
        cd ../../..
        cabal exec -- ghc test/integration/ocsp/OCSPTestServer.hs -o test/integration/ocsp/OCSPTestServer -threaded -rtsopts 2>&1 | tee "$TEST_DIR/$LOG_DIR/compile.log"
        cd "$TEST_DIR"
        EXECUTABLE="./OCSPTestServer"
    else
        log_error "Neither stack nor cabal found - cannot compile test server"
        return 1
    fi
    
    if [[ ! -f "$EXECUTABLE" ]]; then
        log_error "Failed to compile test server"
        return 1
    fi
    
    log_success "Test server compiled: $EXECUTABLE"
}

# Start the test server
start_server() {
    local tls_version="$1"
    
    log_info "Starting OCSP test server (TLS version: $tls_version)..."
    
    cd "$TEST_DIR"
    
    local version_flag=""
    if [[ "$tls_version" == "1.2" ]]; then
        version_flag="--tls12"
    elif [[ "$tls_version" == "1.3" ]]; then
        version_flag="--tls13"
    fi
    
    # Start server in background
    $EXECUTABLE --port $SERVER_PORT $version_flag --verbose \
        --certificate "$CERT_DIR/server.crt" \
        --key "$CERT_DIR/server.key" \
        > "$LOG_DIR/server-$tls_version.log" 2>&1 &
    
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 2
    
    # Check if server is running
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        log_error "Server failed to start"
        cat "$LOG_DIR/server-$tls_version.log"
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
    local output_file="$LOG_DIR/client-$tls_version.log"
    
    # Test with OCSP status request
    echo -e "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | \
        timeout $TIMEOUT openssl s_client \
            -connect localhost:$SERVER_PORT \
            $openssl_version \
            -status \
            -verify_return_error \
            -CAfile "$CERT_DIR/ca.crt" \
            > "$output_file" 2>&1
    
    local client_exit_code=$?
    
    # Analyze results
    local hook_called=false
    local ocsp_delivered=false
    local clean_handshake=false
    
    # Check server logs for hook calls
    if grep -q "OCSP HOOK CALLED" "$LOG_DIR/server-$tls_version.log"; then
        hook_called=true
    fi
    
    # Check client output for OCSP response
    if grep -q "OCSP response:" "$output_file"; then
        ocsp_delivered=true
    fi
    
    # Check for clean handshake (no alerts or errors)
    if grep -qE "(alert|error|fail)" "$output_file"; then
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
        log_success "✓ Clean TLS handshake (no alerts/errors)"
    else
        log_warning "⚠ TLS handshake had warnings/errors"
    fi
    
    # Overall test result
    if $hook_called && $ocsp_delivered && $clean_handshake; then
        log_success "✓ $test_name: PASSED"
        return 0
    else
        log_error "✗ $test_name: FAILED"
        echo
        echo "Server log excerpt:"
        tail -20 "$LOG_DIR/server-$tls_version.log" || true
        echo
        echo "Client log excerpt:"
        tail -20 "$output_file" || true
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
    
    # Setup
    setup_directories
    generate_certificates
    compile_server
    
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
        log_error "Check the logs in $LOG_DIR for details"
        return 1
    fi
}

# Help function
show_help() {
    cat << EOF
OCSP Stapling Integration Test Suite

Usage: $0 [OPTIONS]

Options:
    --help          Show this help message
    --clean         Clean up generated files and exit
    --tls12-only    Test only TLS 1.2
    --tls13-only    Test only TLS 1.3
    --port PORT     Use custom port (default: $SERVER_PORT)
    --verbose       Enable verbose output

Examples:
    $0                  # Run all tests
    $0 --tls12-only     # Test only TLS 1.2
    $0 --clean          # Clean up files

This test suite verifies that OCSP stapling works correctly by:
1. Generating test certificates
2. Starting a test server with OCSP hooks
3. Testing with OpenSSL clients
4. Verifying hook calls and OCSP delivery
EOF
}

# Clean up function
clean_up() {
    log_info "Cleaning up test files..."
    
    # Stop any running servers
    cleanup
    
    # Remove generated files
    rm -rf "$CERT_DIR"
    rm -rf "$LOG_DIR"
    rm -f "$TEST_DIR/ocsp-test.cabal"
    rm -f "$TEST_DIR/OCSPTestServer"
    rm -f "$TEST_DIR"/*.hi
    rm -f "$TEST_DIR"/*.o
    
    log_success "Cleanup complete"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --help)
            show_help
            exit 0
            ;;
        --clean)
            clean_up
            exit 0
            ;;
        --tls12-only)
            log_info "Running TLS 1.2 test only"
            setup_directories
            generate_certificates
            compile_server
            run_single_test "1.2"
            exit $?
            ;;
        --tls13-only)
            log_info "Running TLS 1.3 test only"
            setup_directories
            generate_certificates
            compile_server
            run_single_test "1.3"
            exit $?
            ;;
        --port)
            SERVER_PORT="$2"
            shift
            ;;
        --verbose)
            set -x
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
    shift
done

# Run the main test suite
run_all_tests