# OCSP Stapling Integration Tests

This directory contains comprehensive integration tests for OCSP (Online Certificate Status Protocol) stapling functionality in the hs-tls library.

## Overview

OCSP stapling allows TLS servers to provide certificate status information during the handshake, improving performance and privacy compared to clients making separate OCSP requests. This test suite verifies that:

1. **OCSP hooks are called correctly** during TLS handshakes
2. **OCSP responses are properly formatted** according to RFC 6066 and RFC 8446
3. **Both TLS 1.2 and TLS 1.3** handle OCSP stapling correctly
4. **OpenSSL clients accept responses** without protocol errors

## Test Components

### OCSPTestServer.hs

A comprehensive test server that:

- Implements the `onCertificateStatus` hook to provide OCSP responses
- Supports both TLS 1.2 and TLS 1.3 (configurable)
- Logs hook calls for verification
- Returns a valid test OCSP response
- Serves simple HTTP responses for end-to-end testing

Key features:
- Hook call counting for verification
- Verbose logging of handshake details
- Self-signed certificate support for testing
- Command-line configuration options

### run-ocsp-tests.sh

An automated test script that:

- Generates test certificates automatically
- Compiles the test server
- Runs comprehensive tests for both TLS versions
- Uses OpenSSL clients to verify OCSP delivery
- Provides detailed pass/fail reporting
- Cleans up test artifacts

## Usage

### Quick Test

Run all tests (recommended):

```bash
./run-ocsp-tests.sh
```

### Specific TLS Version

Test only TLS 1.2:
```bash
./run-ocsp-tests.sh --tls12-only
```

Test only TLS 1.3:
```bash
./run-ocsp-tests.sh --tls13-only
```

### Manual Testing

Start the server manually:
```bash
cd tls/test/integration/ocsp
ghc -package-db=../../../dist-newstyle/packagedb/ghc-* OCSPTestServer.hs
./OCSPTestServer --verbose
```

Test with OpenSSL:
```bash
# TLS 1.2
echo "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" | \
  openssl s_client -connect localhost:4443 -tls1_2 -status -CAfile certs/ca.crt

# TLS 1.3  
echo "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" | \
  openssl s_client -connect localhost:4443 -tls1_3 -status -CAfile certs/ca.crt
```

## Test Validation

The tests verify:

### 1. Hook Execution
- Server logs show "OCSP HOOK CALLED" messages
- Hook call counter increments correctly
- Hook receives correct certificate chain and SNI information

### 2. OCSP Delivery
- OpenSSL client output contains "OCSP response:" section
- Response contains valid DER-encoded OCSP data
- No "unsupported status type" or format errors

### 3. Protocol Compliance
- No TLS alerts or handshake failures
- Clean handshake completion
- Proper message sequencing in both TLS versions

### 4. TLS Version Differences
- **TLS 1.2**: OCSP delivered via separate CertificateStatus message
- **TLS 1.3**: OCSP delivered as certificate extension

## Technical Details

### OCSP Response Format

The test server returns a raw DER-encoded OCSP response. The hs-tls library handles the TLS protocol wrapping:

- **TLS 1.2**: Wraps in CertificateStatus message with 24-bit length field
- **TLS 1.3**: Wraps in certificate extension with proper encoding

### Certificate Chain

Uses self-signed certificates for testing:
- CA certificate and key for signing
- Server certificate signed by the test CA
- All certificates include appropriate extensions

### Known Limitations

- Uses self-signed certificates (expect certificate verification warnings)
- OCSP response is static (not a real OCSP responder)
- Timeout handling for test reliability

## Expected Output

### Successful Test Run

```
[INFO] Starting OCSP Stapling Integration Tests
[INFO] Setting up test directories...
[INFO] Generating test certificates...
[SUCCESS] Certificates ready
[INFO] Compiling OCSP test server...
[SUCCESS] Test server compiled

=== Testing TLS 1.2 ===
[INFO] Starting OCSP test server (TLS version: 1.2)...
[SUCCESS] Server started (PID: 12345)
[INFO] Testing TLS 1.2 OCSP Stapling...

=== TLS 1.2 OCSP Stapling Results ===
[SUCCESS] ✓ OCSP hook was called
[SUCCESS] ✓ OCSP response was delivered to client  
[SUCCESS] ✓ Clean TLS handshake (no alerts/errors)
[SUCCESS] ✓ TLS 1.2 OCSP Stapling: PASSED

=== Testing TLS 1.3 ===
[INFO] Starting OCSP test server (TLS version: 1.3)...
[SUCCESS] Server started (PID: 12346)
[INFO] Testing TLS 1.3 OCSP Stapling...

=== TLS 1.3 OCSP Stapling Results ===
[SUCCESS] ✓ OCSP hook was called
[SUCCESS] ✓ OCSP response was delivered to client
[SUCCESS] ✓ Clean TLS handshake (no alerts/errors)  
[SUCCESS] ✓ TLS 1.3 OCSP Stapling: PASSED

===========================================
OCSP Stapling Integration Test Results
===========================================
[SUCCESS] All tests PASSED! 🎉
[SUCCESS] OCSP stapling is working correctly in both TLS 1.2 and TLS 1.3
```

## Troubleshooting

### Compilation Issues

If compilation fails:
1. Ensure the hs-tls library is built: `cabal build tls`
2. Check that required dependencies are available
3. Try using `ghc` directly with explicit package database paths

### Connection Issues

If tests fail with connection errors:
1. Check that no other service is using the test port
2. Verify firewall settings allow localhost connections
3. Try a different port: `./run-ocsp-tests.sh --port 14444`

### OCSP Delivery Issues

If OCSP responses aren't delivered:
1. Check server logs for hook call messages
2. Verify certificate files are valid
3. Ensure OpenSSL version supports OCSP stapling

## Integration with CI/CD

This test suite can be integrated into continuous integration:

```bash
# In CI script
cd tls/test/integration/ocsp
./run-ocsp-tests.sh
```

The script returns appropriate exit codes for CI systems.

## References

- [RFC 6066: Transport Layer Security (TLS) Extensions](https://tools.ietf.org/html/rfc6066)
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 6960: Online Certificate Status Protocol - OCSP](https://tools.ietf.org/html/rfc6960)