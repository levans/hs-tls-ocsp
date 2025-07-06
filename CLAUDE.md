# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The `hs-tls` repository contains a pure Haskell implementation of the TLS protocol supporting TLS 1.2 and TLS 1.3 for both clients and servers. The project includes OCSP (Online Certificate Status Protocol) support and various TLS extensions.

## Key Packages

- `tls/` - Core TLS library implementation
- `tls-session-manager/` - Session management utilities
- `debug/` - Debug utilities and simple client/server examples
- `test-scripts/` - Test utilities and OpenSSL interop tools

## Build System

This project uses both Cabal and Stack for building:

### Stack (Recommended)
```bash
# Build all packages
stack build

# Build specific executables (requires devel flag)
stack build --flag tls:devel

# Run tests
stack test

# Run specific test executable
stack exec TestClient
```

### Cabal
```bash
# Build all packages
cabal build all

# Run tests
cabal test all

# Install with development tools
cabal install --enable-tests --flag tls:devel
```

### Make Targets
```bash
# Run integration tests
make tests

# Build OpenSSL test tools
make build-openssl-server
make build-openssl-client
```

## Code Formatting

The project uses Fourmolu for code formatting with settings in `fourmolu.yaml`:
```bash
fourmolu --mode inplace $(find . -name "*.hs")
```

## Testing

### Unit Tests
```bash
# Run all tests
stack test

# Run tests for specific package
stack test tls
```

### Integration Tests
```bash
# Simple TLS handshake test
./simple-tls-test.sh

# Protocol compliance verification
./protocol-verification.sh

# TLS 1.2 specific compliance
./tls12-compliance-test.sh

# Full validation suite
./final-validation.sh
```

### Test Client/Server
```bash
# Start TLS server (requires devel flag)
stack exec tls-server -- --certificate test.crt --key test.key --tls12 4443

# Connect with TLS client
stack exec tls-client -- -3 -d 127.0.0.1 443
```

## Architecture

### Core TLS Implementation (`tls/`)
- `Network.TLS` - Main public API
- `Network.TLS.Handshake.*` - Handshake protocol implementation
- `Network.TLS.Record.*` - Record layer processing
- `Network.TLS.Crypto.*` - Cryptographic operations
- `Network.TLS.Hooks` - Extension hooks for customization
- `Network.TLS.Extension` - TLS extensions including OCSP

### Session Management (`tls-session-manager/`)
- `Network.TLS.SessionManager` - In-memory session database
- `Network.TLS.SessionTicket` - Session ticket handling

### OCSP Support
The implementation includes comprehensive OCSP support:
- OCSP status request extension (RFC 6066)
- OCSP stapling for certificate validation
- Test cases in `test/OCSPHookSpec.hs`, `test/OCSPExtensionSpec.hs`

### Key Modules
- `Network.TLS.Context` - TLS context management
- `Network.TLS.Parameters` - Configuration parameters
- `Network.TLS.Credentials` - Certificate and key handling
- `Network.TLS.Cipher` - Cipher suite definitions
- `Network.TLS.Types` - Core type definitions

## Development Notes

### TLS Version Support
- TLS 1.2: Full support with all standard extensions
- TLS 1.3: Complete implementation with 0-RTT, PSK, and HelloRetryRequest
- Backward compatibility maintained for older protocol versions

### Certificate Handling
Test certificates are generated automatically by test scripts. For development:
```bash
# Generate test certificate
openssl req -x509 -newkey rsa:2048 -keyout test.key -out test.crt -days 30 -nodes \
    -subj "/CN=localhost/O=Test/C=US" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

### Debugging
- Use `tls-debug` executables for protocol debugging
- Enable logging hooks in `Network.TLS.Hooks` for detailed tracing
- Test scripts provide comprehensive protocol verification

### Common Development Patterns
- The codebase uses `Strict` and `StrictData` extensions throughout
- Error handling follows the `ErrT` monad pattern
- Cryptographic operations are abstracted through the `Crypto` modules
- Extension support is implemented via the hooks system