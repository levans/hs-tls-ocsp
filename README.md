![GitHub Actions status](https://github.com/haskell-tls/hs-tls/workflows/Haskell%20CI/badge.svg)

# Haskell TLS

* `tls` :: library for TLS 1.2/1.3 server and client purely in Haskell
* `tls-session-manager` :: library for in-memory session DB and session ticket.

If the `devel` flag is specified to `tls`, `tls-client` and `tls-server` are also built.

## Usage of `tls-client`

```
Usage: quic-client [OPTION] addr port [path]
  -d           --debug                print debug info
  -v           --show-content         print downloaded content
  -l <file>    --key-log-file=<file>  a file to store negotiated secrets
  -g <groups>  --groups=<groups>      specify groups
  -e           --validate             validate server's certificate
  -R           --resumption           try session resumption
  -Z           --0rtt                 try sending early data
  -S           --hello-retry          try client hello retry
  -2           --tls12                use TLS 1.2
  -3           --tls13                use TLS 1.3

  <groups> = ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192,p256,p384,p521,x25519,x448
```

### TLS 1.3 full negotiation

```
% tls-client -3 -d 127.0.0.1 443
------------------------
Version: TLS1.3
Cipher: TLS_AES_256_GCM_SHA384
Compression: 0
Groups: X25519
Handshake mode: FullHandshake
Early data accepted: False
Result: (H) handshake ... OK
Result: (1) HTTP/1.1 transaction ... OK
```

### TLS 1.3 HelloRetryRequest (HRR)

```
% tls-client -3 -d 127.0.0.1 443 -S
------------------------
Version: TLS1.3
Cipher: TLS_AES_256_GCM_SHA384
Compression: 0
Groups: X25519
Handshake mode: HelloRetryRequest
Early data accepted: False
Result: (S) retry ... OK
```

### Resumption (PSK: Pre-Shared Key)

```
% tls-client -3 -d 127.0.0.1 443 -R
------------------------
Version: TLS1.3
Cipher: TLS_AES_256_GCM_SHA384
Compression: 0
Groups: X25519
Handshake mode: FullHandshake
Early data accepted: False
<<<< next connection >>>>
------------------------
Version: TLS1.3
Cipher: TLS_AES_256_GCM_SHA384
Compression: 0
Groups: X25519
Handshake mode: PreSharedKey
Early data accepted: False
Result: (R) TLS resumption ... OK
```

### 0-RTT on resumption

```
% tls-client -3 -d 127.0.0.1 443 -Z
------------------------
Version: TLS1.3
Cipher: TLS_AES_256_GCM_SHA384
Compression: 0
Groups: X25519
Handshake mode: FullHandshake
Early data accepted: False
<<<< next connection >>>>
------------------------
Version: TLS1.3
Cipher: TLS_AES_256_GCM_SHA384
Compression: 0
Groups: X25519
Handshake mode: RTT0
Early data accepted: True
Result: (Z) 0-RTT ... OK
```

## OCSP Stapling Support

This TLS library supports OCSP (Online Certificate Status Protocol) stapling for both TLS 1.2 and TLS 1.3, allowing servers to provide certificate revocation status during the TLS handshake.

### Hook Configuration

OCSP stapling is configured through the `onCertificateStatus` hook in `ServerHooks`:

```haskell
onCertificateStatus :: CertificateChain -> Maybe HostName -> IO (Maybe ByteString)
```

**Parameters:**
- `CertificateChain`: The complete certificate chain the server is presenting (leaf → intermediate → root)
- `Maybe HostName`: The SNI (Server Name Indication) hostname requested by the client, if any
- **Returns:** `Maybe ByteString` - raw DER-encoded OCSP response, or `Nothing` if unavailable

### How It Works

**TLS 1.2:**
1. Client sends ClientHello with `status_request` extension
2. Server calls the OCSP hook with the certificate chain and SNI
3. If hook returns `Just ocspDer`, server sends a separate `CertificateStatus` message
4. OCSP response uses 24-bit length encoding per RFC 6066

**TLS 1.3:**
1. Client sends ClientHello with `status_request` extension
2. Server calls the OCSP hook with the certificate chain and SNI
3. If hook returns `Just ocspDer`, server embeds OCSP response as a certificate extension
4. OCSP response is wrapped in `CertificateStatus` format and attached to the leaf certificate

### Example Implementation

```haskell
import Network.TLS
import qualified Data.ByteString as B
import Data.X509

-- Simple OCSP hook that serves cached responses
myOCSPHook :: CertificateChain -> Maybe HostName -> IO (Maybe B.ByteString)
myOCSPHook (CertificateChain certs) mSNI = do
    case certs of
        [] -> return Nothing
        (leafCert:_) -> do
            -- Extract identifier from leaf certificate
            let serialNumber = certSerial $ signedObject $ getSigned leafCert
            
            -- Look up cached OCSP response
            -- In production, this might query a cache, database, or OCSP responder
            mOcspResponse <- case mSNI of
                Just hostname -> lookupOCSPByHostname hostname serialNumber
                Nothing -> lookupOCSPBySerial serialNumber
                
            return mOcspResponse

-- Configure server with OCSP support
serverParams = def 
    { serverHooks = def 
        { onCertificateStatus = myOCSPHook 
        }
    , serverShared = def
        { sharedCredentials = myCredentials
        }
    }
```

### Key Points

1. **Leaf Certificate Only**: OCSP stapling applies only to the leaf (server) certificate, not intermediate certificates
2. **SNI Support**: The hook receives SNI information, enabling per-hostname OCSP responses for multi-domain servers
3. **Protocol Agnostic**: The same hook works for both TLS 1.2 and 1.3; the library handles protocol differences
4. **Optional**: If the hook returns `Nothing`, the handshake continues without OCSP stapling
5. **Must-Staple**: The library supports RFC 7633 must-staple validation if configured

### Testing OCSP

Test OCSP stapling with OpenSSL:

```bash
# TLS 1.2
openssl s_client -connect example.com:443 -tls1_2 -status

# TLS 1.3  
openssl s_client -connect example.com:443 -tls1_3 -status
```

Look for "OCSP response:" in the output to confirm stapling is working.
