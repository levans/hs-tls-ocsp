# OCSP Rebase Checklist - 2.1.8 to 2.1.1

This checklist ensures all OCSP functionality is preserved when rebasing from tls 2.1.8 to 2.1.1.

## Pre-Rebase Checks

- [ ] Stack resolver: Must update to lts-23.25
- [ ] Cryptonite → Crypton migration if needed in 2.1.1
- [ ] Check if Extension.hs structure differs significantly between versions

## Core OCSP Components to Preserve

### 1. Extension System (`Network.TLS.Extension`)
- [ ] `StatusRequest` data type with proper encoding/decoding
- [ ] `Extension StatusRequest` instance
- [ ] `EID_StatusRequest` in supported extensions list
- [ ] `hasStatusRequest` helper function

### 2. Hook System (`Network.TLS.Parameters`)
- [ ] Server hook: `onCertificateStatus :: CertificateChain -> Maybe HostName -> IO (Maybe ByteString)`
- [ ] Client hook: `onServerCertificateStatus :: CertificateChain -> ByteString -> IO CertificateUsage`
- [ ] Default implementations (Nothing for server, accept all for client)

### 3. Data Structures (`Network.TLS.Struct`)
- [ ] `HandshakeType_CertificateStatus` = 22
- [ ] `CertificateStatus ByteString` constructor in `Handshake`
- [ ] `typeOfHandshake` case for CertificateStatus

### 4. Packet Handling
#### TLS 1.2 (`Network.TLS.Packet`)
- [ ] `decodeCertificateStatus` function
- [ ] `encodeHandshake'` case for CertificateStatus
- [ ] Proper encoding: status_type (1 byte) = 1, length (3 bytes), OCSP response

#### TLS 1.3 (`Network.TLS.Packet13`)
- [ ] Support for OCSP as certificate extension

### 5. Server Implementation
#### TLS 1.2 (`Network.TLS.Handshake.Server.ServerHello12`)
- [ ] Check client's status_request extension
- [ ] Call onCertificateStatus hook
- [ ] Send CertificateStatus after Certificate (if response provided)
- [ ] Must-staple validation
- [ ] Protocol order: Certificate → CertificateStatus → ServerKeyExchange

#### TLS 1.3 (`Network.TLS.Handshake.Server.ServerHello13`)
- [ ] Add OCSP as extension to leaf certificate only
- [ ] Format: `ExtensionRaw EID_StatusRequest ocspDer`
- [ ] Must-staple validation

### 6. Client Implementation
#### TLS 1.2 (`Network.TLS.Handshake.Client.TLS12`)
- [ ] `expectCertificateStatus` function
- [ ] Modified `expectCertificate` to handle CertificateStatus
- [ ] Call onServerCertificateStatus hook
- [ ] Must-staple checking when no status received

#### TLS 1.3 (`Network.TLS.Handshake.Client.TLS13`)
- [ ] Handle OCSP as certificate extension

### 7. Client Hello (`Network.TLS.Handshake.Client.ClientHello`)
- [ ] Track if StatusRequest was sent
- [ ] Set hstClientSentStatusRequest flag

### 8. Handshake State (`Network.TLS.Handshake.State`)
- [ ] `hstClientSentStatusRequest` field in HandshakeState
- [ ] Getter/setter functions

### 9. X.509 Validation (`Network.TLS.X509`)
- [ ] `hasMustStapleExtension` function (OID 1.3.6.1.5.5.7.1.24, value 5)
- [ ] `certificateChainRequiresStapling` function
- [ ] Only check leaf certificate for must-staple

### 10. Context Updates (`Network.TLS.Context.Internal`, `Network.TLS.State`)
- [ ] Any necessary state tracking for OCSP

## Critical Implementation Details

### TLS Version Differences
- **TLS 1.2**: OCSP as separate handshake message (type 22)
- **TLS 1.3**: OCSP as certificate extension (no separate message)

### Must-Staple Rules
1. If cert requires stapling but no response → error
2. If cert requires stapling but client didn't request → error  
3. If client requested for must-staple cert but no response → error

### DER Wrapping
- **TLS 1.2**: `[status_type:1][length:3][ocsp_response:*]`
- **TLS 1.3**: Raw DER in certificate extension

## Test Coverage
- [ ] OCSPHookSpec - Hook functionality
- [ ] OCSPExtensionSpec - Extension encoding
- [ ] CertificateStatusSpec - Message handling
- [ ] MustStapleSpec - Must-staple validation
- [ ] OCSPErrorSpec - Error conditions
- [ ] Integration tests with OpenSSL

## Post-Rebase Validation
- [ ] All tests pass
- [ ] OpenSSL interop works for both TLS 1.2 and 1.3
- [ ] Hook signatures match exactly (no regression)
- [ ] Must-staple validation works correctly
- [ ] Protocol sequencing is correct