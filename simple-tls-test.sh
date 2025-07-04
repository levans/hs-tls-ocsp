#!/bin/bash

# Simple TLS handshake test
set -e

echo "=== Simple TLS Handshake Test ==="

# Create certificate if needed
if [ ! -f test.crt ] || [ ! -f test.key ]; then
    openssl req -x509 -newkey rsa:2048 -keyout test.key -out test.crt -days 30 -nodes \
        -subj "/CN=localhost/O=Test/C=US" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
fi

# Start server
echo "Starting TLS 1.2 server..."
stack exec tls-simpleserver -- --certificate test.crt --key test.key --tls12 4443 &
SERVER_PID=$!
sleep 2

cleanup() {
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}
trap cleanup EXIT

echo "Testing basic TLS 1.2 handshake..."

# Test 1: Just verify handshake completes
echo "=== Test 1: Handshake Completion ==="
if timeout 5s openssl s_client -connect localhost:4443 -tls1_2 </dev/null 2>&1 | grep -q "Verify return code: 18"; then
    echo "✅ TLS 1.2 handshake completed successfully"
else
    echo "❌ TLS 1.2 handshake failed"
fi

# Test 2: Check if we can see the protocol info
echo ""
echo "=== Test 2: Protocol Information ==="
info=$(timeout 5s openssl s_client -connect localhost:4443 -tls1_2 </dev/null 2>&1)
echo "$info" | grep -E "(Protocol|Cipher|Session-ID)" | head -3

# Test 3: Test with OCSP status request
echo ""
echo "=== Test 3: OCSP Status Request ==="
if timeout 5s openssl s_client -connect localhost:4443 -tls1_2 -status </dev/null 2>&1 | grep -q "Protocol"; then
    echo "✅ TLS 1.2 with OCSP status request completed"
else
    echo "❌ TLS 1.2 with OCSP status request failed"
fi

echo ""
echo "=== Test Complete ==="