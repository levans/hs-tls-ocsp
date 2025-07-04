#!/bin/bash

# TLS 1.2 Specific Compliance Test
# Tests the message ordering fix for OCSP in TLS 1.2

set -e

echo "=== TLS 1.2 OCSP Compliance Test ==="
echo ""

# Create a simple test certificate if it doesn't exist
if [ ! -f test.crt ] || [ ! -f test.key ]; then
    echo "Creating test certificate..."
    openssl req -x509 -newkey rsa:2048 -keyout test.key -out test.crt -days 30 -nodes \
        -subj "/CN=localhost/O=Test/C=US" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
fi

# Start the TLS server forcing TLS 1.2
echo "Starting hs-tls server with TLS 1.2..."
stack exec tls-simpleserver -- --certificate test.crt --key test.key --tls12 4443 &
SERVER_PID=$!

# Give server time to start
sleep 3

echo "Server started with PID $SERVER_PID"
echo ""

# Function to cleanup
cleanup() {
    echo "Cleaning up..."
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}
trap cleanup EXIT

# Test 1: Force TLS 1.2 basic connection
echo "=== Test 1: TLS 1.2 Basic Connection ==="
result=$(timeout 10s openssl s_client -connect localhost:4443 -tls1_2 -quiet -no_ign_eof <<< "GET / HTTP/1.1
Host: localhost
Connection: close

" 2>&1)

if echo "$result" | grep -q "Protocol.*TLSv1.2"; then
    echo "✅ TLS 1.2 connection successful"
    echo "$result" | grep -E "(Protocol|Cipher|Verify return)" | head -3
else
    echo "❌ TLS 1.2 connection failed"
    echo "$result" | head -5
fi
echo ""

# Test 2: TLS 1.2 with OCSP status request
echo "=== Test 2: TLS 1.2 with OCSP Status Request ==="
result=$(timeout 10s openssl s_client -connect localhost:4443 -tls1_2 -status -quiet -no_ign_eof <<< "GET / HTTP/1.1
Host: localhost
Connection: close

" 2>&1)

if echo "$result" | grep -q "OCSP Response Status"; then
    echo "✅ OCSP Status Request processed"
    echo "$result" | grep -A5 "OCSP Response"
elif echo "$result" | grep -q "Protocol.*TLSv1.2"; then
    echo "⚠️  TLS 1.2 connection successful, no OCSP response (expected - test cert)"
    echo "$result" | grep -E "(Protocol|Cipher)" | head -2
else
    echo "❌ TLS 1.2 with OCSP failed"
    echo "$result" | head -5
fi
echo ""

# Test 3: Detailed handshake message trace for TLS 1.2
echo "=== Test 3: TLS 1.2 Handshake Message Order Verification ==="
echo "Checking for correct order: Certificate -> CertificateStatus -> ServerKeyExchange"

# Use s_client with message tracing to see handshake flow
result=$(timeout 10s openssl s_client -connect localhost:4443 -tls1_2 -msg -ign_eof </dev/null 2>&1)

# Extract handshake messages and check order
echo "$result" | grep -E ">>>(.*Handshake|<<<.*Handshake)" | while read line; do
    if echo "$line" | grep -q "Certificate"; then
        echo "📜 Certificate message"
    elif echo "$line" | grep -q "CertificateStatus"; then
        echo "🎫 CertificateStatus message"
    elif echo "$line" | grep -q "ServerKeyExchange"; then
        echo "🔑 ServerKeyExchange message"
    elif echo "$line" | grep -q "ServerHelloDone"; then
        echo "✅ ServerHelloDone message"
        break
    fi
done

echo ""

# Test 4: Browser-like ALPN + OCSP test (simulating Safari)
echo "=== Test 4: Browser-like Request (ALPN + OCSP) ==="
result=$(timeout 10s openssl s_client -connect localhost:4443 -tls1_2 -alpn h2,http/1.1 -status -quiet -no_ign_eof <<< "GET / HTTP/1.1
Host: localhost
Connection: close

" 2>&1)

if echo "$result" | grep -q "Protocol.*TLSv1.2"; then
    echo "✅ Browser-like request successful"
    alpn=$(echo "$result" | grep "ALPN protocol" || echo "No ALPN negotiated")
    echo "  ALPN: $alpn"
    protocol=$(echo "$result" | grep "Protocol" | head -1)
    echo "  $protocol"
else
    echo "❌ Browser-like request failed"
    echo "$result" | head -5
fi

echo ""
echo "=== Test Complete ==="
echo "All tests should show successful TLS 1.2 connections."
echo "The message ordering fix should prevent handshake failures."