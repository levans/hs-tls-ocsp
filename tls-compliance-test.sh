#!/bin/bash

# TLS Compliance Test Script
# Tests the hs-tls-ocsp server against real-world TLS clients

set -e

echo "=== TLS Compliance Testing ==="
echo "Testing enhanced TLS library against real clients"
echo ""

# Create a simple test certificate if it doesn't exist
if [ ! -f test.crt ] || [ ! -f test.key ]; then
    echo "Creating test certificate..."
    openssl req -x509 -newkey rsa:2048 -keyout test.key -out test.crt -days 30 -nodes \
        -subj "/CN=localhost/O=Test/C=US" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
fi

# Start the TLS server in background
echo "Starting hs-tls server..."
stack exec tls-simpleserver -- --certificate test.crt --key test.key 4443 &
SERVER_PID=$!

# Give server time to start
sleep 2

echo "Server started with PID $SERVER_PID"
echo ""

# Function to cleanup
cleanup() {
    echo "Cleaning up..."
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}
trap cleanup EXIT

# Test 1: OpenSSL s_client basic connection
echo "=== Test 1: OpenSSL s_client basic connection ==="
echo "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | \
    timeout 10s openssl s_client -connect localhost:4443 -quiet -verify_return_error 2>&1 | \
    head -10
echo "✅ Basic OpenSSL connection test completed"
echo ""

# Test 2: OpenSSL s_client with OCSP status request
echo "=== Test 2: OpenSSL s_client with OCSP status request ==="
echo "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | \
    timeout 10s openssl s_client -connect localhost:4443 -status -quiet 2>&1 | \
    head -10
echo "✅ OCSP status request test completed"
echo ""

# Test 3: OpenSSL s_client with detailed handshake debugging
echo "=== Test 3: OpenSSL handshake trace (checking message order) ==="
timeout 10s openssl s_client -connect localhost:4443 -msg -quiet -ign_eof </dev/null 2>&1 | \
    grep -E "(Certificate|CertificateStatus|ServerKeyExchange|write|read)" | head -20
echo "✅ Handshake trace completed"
echo ""

# Test 4: Check supported protocols
echo "=== Test 4: TLS version support ==="
for version in tls1_2 tls1_3; do
    echo "Testing $version..."
    result=$(timeout 5s openssl s_client -connect localhost:4443 -$version -quiet </dev/null 2>&1 | \
        grep -E "(Protocol|Cipher)" | head -2 || echo "Failed")
    echo "$version: $result"
done
echo ""

# Test 5: Check cipher suite support
echo "=== Test 5: Cipher suite compatibility ==="
timeout 5s openssl s_client -connect localhost:4443 -cipher 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA' -quiet </dev/null 2>&1 | \
    grep -E "(Cipher|Protocol)" | head -5
echo "✅ Cipher suite test completed"
echo ""

# Test 6: ALPN negotiation
echo "=== Test 6: ALPN negotiation ==="
for proto in h2 http/1.1; do
    echo "Testing ALPN with $proto..."
    result=$(timeout 5s openssl s_client -connect localhost:4443 -alpn "$proto" -quiet </dev/null 2>&1 | \
        grep -E "(ALPN protocol|Protocol)" || echo "No ALPN")
    echo "  $proto: $result"
done
echo ""

echo "=== Compliance Testing Complete ==="
echo "Check the output above for any protocol violations or errors"