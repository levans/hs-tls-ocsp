# OCSP Implementation Changes Summary

This document provides a detailed summary of OCSP (Online Certificate Status Protocol) changes made to the hs-tls library, useful as a checklist for rebasing.

## Core OCSP Commits

### 1. Main OCSP Implementation (2bb4846b)
The primary commit that adds OCSP stapling support to the TLS library.

### 2. Hook Signature Fix (9ab85aed)
Fixes the OCSP hook signature to include CertificateChain and Maybe HostName parameters.

### 3. Client Protocol Implementation (bdbf60a9)
Implements client-side OCSP protocol handling for both TLS 1.2 and 1.3.

### 4. Protocol Sequencing Fixes (7e80302e, 70b90879)
Fixes protocol sequencing issues in the handshake.

### 5. Client Protocol Fixes (ab22c5f2)
Additional fixes for client protocols and comprehensive test additions.

## File-by-File Changes

### 1. **tls/Network/TLS/Extension.hs**
**Purpose**: OCSP extension handling
- Added `StatusRequest` data type and instance
- Implemented `Extension StatusRequest` with encoding/decoding
- Added `EID_StatusRequest` to `supportedExtensions`
- Added `hasStatusRequest` helper function to check if client requested OCSP

### 2. **tls/Network/TLS/Parameters.hs**
**Purpose**: OCSP hook definitions

#### Server Hook:
- Added `onCertificateStatus :: CertificateChain -> Maybe HostName -> IO (Maybe ByteString)` to `ServerHooks`
- Hook provides certificate chain and SNI for generating appropriate OCSP response
- Default implementation returns `Nothing` (no OCSP stapling)

#### Client Hook:
- Added `onServerCertificateStatus :: CertificateChain -> ByteString -> IO CertificateUsage` to `ClientHooks`
- Allows client to validate OCSP response from server
- Default implementation accepts any OCSP response

### 3. **tls/Network/TLS/Struct.hs**
**Purpose**: OCSP data structures
- Added `HandshakeType_CertificateStatus` pattern (value 22)
- Added `CertificateStatus ByteString` to `Handshake` data type
- Updated `typeOfHandshake` to handle `CertificateStatus`

### 4. **tls/Network/TLS/Packet.hs**
**Purpose**: OCSP packet encoding/decoding
- Added `decodeCertificateStatus` function
- Added `encodeHandshake'` case for `CertificateStatus`
- Encodes/decodes with status_type = 1 (OCSP) and DER-encoded response

### 5. **tls/Network/TLS/Packet13.hs**
**Purpose**: TLS 1.3 OCSP packet handling
- Minor updates to support OCSP in TLS 1.3 context

### 6. **tls/Network/TLS/Handshake/Server/ServerHello12.hs**
**Purpose**: TLS 1.2 server OCSP implementation
- Checks if client sent `status_request` extension
- Calls `onCertificateStatus` hook with certificate chain and hostname
- Sends `CertificateStatus` message after Certificate if OCSP response provided
- Validates must-staple requirement:
  - If certificate requires stapling but no response provided → error
  - If certificate requires stapling but client didn't request → error
- Protocol flow: ServerHello → Certificate → **CertificateStatus** → ServerKeyExchange

### 7. **tls/Network/TLS/Handshake/Server/ServerHello13.hs**
**Purpose**: TLS 1.3 server OCSP implementation
- Similar to TLS 1.2 but integrated into TLS 1.3 certificate extensions
- OCSP response added as extension to leaf certificate only
- Validates must-staple requirements
- Uses `ExtensionRaw EID_StatusRequest ocspDer` format

### 8. **tls/Network/TLS/Handshake/Client/TLS12.hs**
**Purpose**: TLS 1.2 client OCSP handling
- Modified `expectCertificate` to expect `CertificateStatus` if client sent `status_request`
- Added `expectCertificateStatus` function:
  - Calls `onServerCertificateStatus` hook for validation
  - Checks must-staple requirement if no status received
- Protocol flow: Certificate → **CertificateStatus** → ServerKeyExchange

### 9. **tls/Network/TLS/Handshake/Client/TLS13.hs**
**Purpose**: TLS 1.3 client OCSP handling
- Minor updates for certificate chain handling
- OCSP response handled as certificate extension (not implemented in detail)

### 10. **tls/Network/TLS/Handshake/Client/ClientHello.hs**
**Purpose**: Track OCSP request in ClientHello
- Tracks if `StatusRequest` extension was sent
- Sets `hstClientSentStatusRequest` flag for later use

### 11. **tls/Network/TLS/Handshake/State.hs**
**Purpose**: Handshake state for OCSP
- Added `hstClientSentStatusRequest` field to `HandshakeState`
- Added getter/setter functions for tracking if client requested OCSP

### 12. **tls/Network/TLS/X509.hs**
**Purpose**: Certificate validation with OCSP support
- Added `hasMustStapleExtension` function:
  - Checks for TLS Feature extension (OID 1.3.6.1.5.5.7.1.24)
  - Looks for status_request feature (value 5)
- Added `certificateChainRequiresStapling` function:
  - Only checks leaf certificate for must-staple requirement
  - Used by both client and server to enforce must-staple

## Key Implementation Details

### TLS 1.2 vs TLS 1.3 Differences

#### TLS 1.2:
- OCSP response sent as separate `CertificateStatus` handshake message
- Message sent after Certificate, before ServerKeyExchange
- Uses dedicated handshake type (22)

#### TLS 1.3:
- OCSP response included as extension in Certificate message
- Added to extensions list of leaf certificate only
- No separate handshake message

### Must-Staple Support
- Implemented RFC 7633 TLS Feature extension checking
- Both client and server validate must-staple requirements
- Errors thrown if:
  - Certificate requires stapling but no response provided
  - Certificate requires stapling but client didn't request it
  - Client requested stapling for must-staple cert but no response received

### Protocol Flow

#### TLS 1.2 Server:
1. Check if client sent `status_request` extension
2. Call `onCertificateStatus` hook with cert chain and hostname
3. If response provided, send `CertificateStatus` after `Certificate`
4. Validate must-staple requirements

#### TLS 1.2 Client:
1. Send `status_request` extension in ClientHello
2. After receiving Certificate, expect `CertificateStatus` if requested
3. Call `onServerCertificateStatus` hook for validation
4. Check must-staple if no status received

## Testing
- Comprehensive test suite added including:
  - OCSPHookSpec.hs - Hook functionality tests
  - OCSPExtensionSpec.hs - Extension encoding/decoding
  - CertificateStatusSpec.hs - Certificate status message handling
  - MustStapleSpec.hs - Must-staple validation
  - OCSPErrorSpec.hs - Error handling
  - Integration tests with OpenSSL

## Important Notes for Rebasing

1. **Hook Signature Evolution**: The hook signature changed from `IO (Maybe ByteString)` to `CertificateChain -> Maybe HostName -> IO (Maybe ByteString)` to provide necessary context.

2. **Client Implementation**: Client-side was not in the initial commit but added in bdbf60a9.

3. **Protocol Sequencing**: Ensure CertificateStatus is sent at the correct point in the handshake sequence.

4. **Must-Staple Validation**: Both client and server must validate must-staple requirements consistently.

5. **Extension Negotiation**: Client must send `status_request` for server to send OCSP response.

6. **TLS Version Handling**: Different implementation approaches for TLS 1.2 vs 1.3.