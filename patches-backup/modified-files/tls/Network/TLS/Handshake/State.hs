{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.State (
    HandshakeState (..),
    HandshakeDigest (..),
    HandshakeMode13 (..),
    RTT0Status (..),
    CertReqCBdata,
    HandshakeM,
    newEmptyHandshake,
    runHandshake,

    -- * key accessors
    setPublicKey,
    setPublicPrivateKeys,
    getLocalPublicPrivateKeys,
    getRemotePublicKey,
    setServerDHParams,
    getServerDHParams,
    setServerECDHParams,
    getServerECDHParams,
    setDHPrivate,
    getDHPrivate,
    setGroupPrivate,
    getGroupPrivate,

    -- * cert accessors
    setClientCertSent,
    getClientCertSent,
    setCertReqSent,
    getCertReqSent,
    setClientCertChain,
    getClientCertChain,
    setCertReqToken,
    getCertReqToken,
    setCertReqCBdata,
    getCertReqCBdata,
    setCertReqSigAlgsCert,
    getCertReqSigAlgsCert,
    setClientSentStatusRequest,
    getClientSentStatusRequest,

    -- * digest accessors
    addHandshakeMessage,
    updateHandshakeDigest,
    getHandshakeMessages,
    getHandshakeMessagesRev,
    getHandshakeDigest,
    foldHandshakeDigest,

    -- * main secret
    setMainSecret,
    setMainSecretFromPre,

    -- * misc accessor
    getPendingCipher,
    setServerHelloParameters,
    setExtendedMainSecret,
    getExtendedMainSecret,
    setSupportedGroup,
    getSupportedGroup,
    setTLS13HandshakeMode,
    getTLS13HandshakeMode,
    setTLS13RTT0Status,
    getTLS13RTT0Status,
    setTLS13EarlySecret,
    getTLS13EarlySecret,
    setTLS13ResumptionSecret,
    getTLS13ResumptionSecret,
    setTLS13CertComp,
    getTLS13CertComp,
    setCCS13Sent,
    getCCS13Sent,
    setCCS13Recv,
    getCCS13Recv,
) where

import Control.Monad.State.Strict
import Data.ByteArray (ByteArrayAccess)
import Data.X509 (CertificateChain)

import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Crypto
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Record.State
import Network.TLS.Struct
import Network.TLS.Types
import Network.TLS.Util

data HandshakeKeyState = HandshakeKeyState
    { hksRemotePublicKey :: Maybe PubKey
    , hksLocalPublicPrivateKeys :: Maybe (PubKey, PrivKey)
    }
    deriving (Show)

data HandshakeDigest
    = HandshakeMessages [ByteString]
    | HandshakeDigestContext HashCtx
    deriving (Show)

data HandshakeState = HandshakeState
    { hstClientVersion :: Version
    , hstClientRandom :: ClientRandom
    , hstServerRandom :: Maybe ServerRandom
    , hstMainSecret :: Maybe ByteString
    , hstKeyState :: HandshakeKeyState
    , hstServerDHParams :: Maybe ServerDHParams
    , hstDHPrivate :: Maybe DHPrivate
    , hstServerECDHParams :: Maybe ServerECDHParams
    , hstGroupPrivate :: Maybe GroupPrivate
    , hstHandshakeDigest :: HandshakeDigest
    , hstHandshakeMessages :: [ByteString]
    , hstCertReqToken :: Maybe ByteString
    -- ^ Set to Just-value when a TLS13 certificate request is received
    , hstCertReqCBdata :: Maybe CertReqCBdata
    -- ^ Set to Just-value when a certificate request is received
    , hstCertReqSigAlgsCert :: Maybe [HashAndSignatureAlgorithm]
    -- ^ In TLS 1.3, these are separate from the certificate
    -- issuer signature algorithm hints in the callback data.
    -- In TLS 1.2 the same list is overloaded for both purposes.
    -- Not present in TLS 1.1 and earlier
    , hstClientCertSent :: Bool
    -- ^ Set to true when a client certificate chain was sent
    , hstCertReqSent :: Bool
    -- ^ Set to true when a certificate request was sent.  This applies
    -- only to requests sent during handshake (not post-handshake).
    , hstClientCertChain :: Maybe CertificateChain
    , hstPendingTxState :: Maybe RecordState
    , hstPendingRxState :: Maybe RecordState
    , hstPendingCipher :: Maybe Cipher
    , hstPendingCompression :: Compression
    , hstExtendedMainSecret :: Bool
    , hstSupportedGroup :: Maybe Group
    , hstTLS13HandshakeMode :: HandshakeMode13
    , hstTLS13RTT0Status :: RTT0Status
    , hstTLS13EarlySecret :: Maybe (BaseSecret EarlySecret) -- xxx
    , hstTLS13ResumptionSecret :: Maybe (BaseSecret ResumptionSecret)
    , hstTLS13CertComp :: Bool
    , hstCCS13Sent :: Bool
    , hstCCS13Recv :: Bool
    , hstClientSentStatusRequest :: Bool
    -- ^ True if client sent status_request extension in ClientHello
    }
    deriving (Show)

-- | When we receive a CertificateRequest from a server, a just-in-time
--    callback is issued to the application to obtain a suitable certificate.
--    Somewhat unfortunately, the callback parameters don't abstract away the
--    details of the TLS 1.2 Certificate Request message, which combines the
--    legacy @certificate_types@ and new @supported_signature_algorithms@
--    parameters is a rather subtle way.
--
--    TLS 1.2 also (again unfortunately, in the opinion of the author of this
--    comment) overloads the signature algorithms parameter to constrain not only
--    the algorithms used in TLS, but also the algorithms used by issuing CAs in
--    the X.509 chain.  Best practice is to NOT treat such that restriction as a
--    MUST, but rather take it as merely a preference, when a choice exists.  If
--    the best chain available does not match the provided signature algorithm
--    list, go ahead and use it anyway, it will probably work, and the server may
--    not even care about the issuer CAs at all, it may be doing DANE or have
--    explicit mappings for the client's public key, ...
--
--    The TLS 1.3 @CertificateRequest@ message, drops @certificate_types@ and no
--    longer overloads @supported_signature_algorithms@ to cover X.509.  It also
--    includes a new opaque context token that the client must echo back, which
--    makes certain client authentication replay attacks more difficult.  We will
--    store that context separately, it does not need to be presented in the user
--    callback.  The certificate signature algorithms preferred by the peer are
--    now in the separate @signature_algorithms_cert@ extension, but we cannot
--    report these to the application callback without an API change.  The good
--    news is that filtering the X.509 signature types is generally unnecessary,
--    unwise and difficult.  So we just ignore this extension.
--
--    As a result, the information we provide to the callback is no longer a
--    verbatim copy of the certificate request payload.  In the case of TLS 1.3
--    The 'CertificateType' list is synthetically generated from the server's
--    @signature_algorithms@ extension, and the @signature_algorithms_certs@
--    extension is ignored.
--
--    Since the original TLS 1.2 'CertificateType' has no provision for the newer
--    certificate types that have appeared in TLS 1.3 we're adding some synthetic
--    values that have no equivalent values in the TLS 1.2 'CertificateType' as
--    defined in the IANA
--    <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-2
--    TLS ClientCertificateType Identifiers> registry.  These values are inferred
--    from the TLS 1.3 @signature_algorithms@ extension, and will allow clients to
--    present Ed25519 and Ed448 certificates when these become supported.
type CertReqCBdata =
    ( [CertificateType]
    , Maybe [HashAndSignatureAlgorithm]
    , [DistinguishedName]
    )

newtype HandshakeM a = HandshakeM {runHandshakeM :: State HandshakeState a}
    deriving (Functor, Applicative, Monad)

instance MonadState HandshakeState HandshakeM where
    put x = HandshakeM (put x)
    get = HandshakeM get
    state f = HandshakeM (state f)

-- create a new empty handshake state
newEmptyHandshake :: Version -> ClientRandom -> HandshakeState
newEmptyHandshake ver crand =
    HandshakeState
        { hstClientVersion = ver
        , hstClientRandom = crand
        , hstServerRandom = Nothing
        , hstMainSecret = Nothing
        , hstKeyState = HandshakeKeyState Nothing Nothing
        , hstServerDHParams = Nothing
        , hstDHPrivate = Nothing
        , hstServerECDHParams = Nothing
        , hstGroupPrivate = Nothing
        , hstHandshakeDigest = HandshakeMessages []
        , hstHandshakeMessages = []
        , hstCertReqToken = Nothing
        , hstCertReqCBdata = Nothing
        , hstCertReqSigAlgsCert = Nothing
        , hstClientCertSent = False
        , hstCertReqSent = False
        , hstClientCertChain = Nothing
        , hstPendingTxState = Nothing
        , hstPendingRxState = Nothing
        , hstPendingCipher = Nothing
        , hstPendingCompression = nullCompression
        , hstExtendedMainSecret = False
        , hstSupportedGroup = Nothing
        , hstTLS13HandshakeMode = FullHandshake
        , hstTLS13RTT0Status = RTT0None
        , hstTLS13EarlySecret = Nothing
        , hstTLS13ResumptionSecret = Nothing
        , hstTLS13CertComp = False
        , hstCCS13Sent = False
        , hstCCS13Recv = False
        , hstClientSentStatusRequest = False
        }

runHandshake :: HandshakeState -> HandshakeM a -> (a, HandshakeState)
runHandshake hst f = runState (runHandshakeM f) hst

setPublicKey :: PubKey -> HandshakeM ()
setPublicKey pk = modify (\hst -> hst{hstKeyState = setPK (hstKeyState hst)})
  where
    setPK hks = hks{hksRemotePublicKey = Just pk}

setPublicPrivateKeys :: (PubKey, PrivKey) -> HandshakeM ()
setPublicPrivateKeys keys = modify (\hst -> hst{hstKeyState = setKeys (hstKeyState hst)})
  where
    setKeys hks = hks{hksLocalPublicPrivateKeys = Just keys}

getRemotePublicKey :: HandshakeM PubKey
getRemotePublicKey = fromJust <$> gets (hksRemotePublicKey . hstKeyState)

getLocalPublicPrivateKeys :: HandshakeM (PubKey, PrivKey)
getLocalPublicPrivateKeys =
    fromJust <$> gets (hksLocalPublicPrivateKeys . hstKeyState)

setServerDHParams :: ServerDHParams -> HandshakeM ()
setServerDHParams shp = modify (\hst -> hst{hstServerDHParams = Just shp})

getServerDHParams :: HandshakeM ServerDHParams
getServerDHParams = fromJust <$> gets hstServerDHParams

setServerECDHParams :: ServerECDHParams -> HandshakeM ()
setServerECDHParams shp = modify (\hst -> hst{hstServerECDHParams = Just shp})

getServerECDHParams :: HandshakeM ServerECDHParams
getServerECDHParams = fromJust <$> gets hstServerECDHParams

setDHPrivate :: DHPrivate -> HandshakeM ()
setDHPrivate shp = modify (\hst -> hst{hstDHPrivate = Just shp})

getDHPrivate :: HandshakeM DHPrivate
getDHPrivate = fromJust <$> gets hstDHPrivate

getGroupPrivate :: HandshakeM GroupPrivate
getGroupPrivate = fromJust <$> gets hstGroupPrivate

setGroupPrivate :: GroupPrivate -> HandshakeM ()
setGroupPrivate shp = modify (\hst -> hst{hstGroupPrivate = Just shp})

setExtendedMainSecret :: Bool -> HandshakeM ()
setExtendedMainSecret b = modify (\hst -> hst{hstExtendedMainSecret = b})

getExtendedMainSecret :: HandshakeM Bool
getExtendedMainSecret = gets hstExtendedMainSecret

setSupportedGroup :: Group -> HandshakeM ()
setSupportedGroup g = modify (\hst -> hst{hstSupportedGroup = Just g})

getSupportedGroup :: HandshakeM (Maybe Group)
getSupportedGroup = gets hstSupportedGroup

-- | Type to show which handshake mode is used in TLS 1.3.
data HandshakeMode13
    = -- | Full handshake is used.
      FullHandshake
    | -- | Full handshake is used with hello retry request.
      HelloRetryRequest
    | -- | Server authentication is skipped.
      PreSharedKey
    | -- | Server authentication is skipped and early data is sent.
      RTT0
    deriving (Show, Eq)

setTLS13HandshakeMode :: HandshakeMode13 -> HandshakeM ()
setTLS13HandshakeMode s = modify (\hst -> hst{hstTLS13HandshakeMode = s})

getTLS13HandshakeMode :: HandshakeM HandshakeMode13
getTLS13HandshakeMode = gets hstTLS13HandshakeMode

data RTT0Status
    = RTT0None
    | RTT0Sent
    | RTT0Accepted
    | RTT0Rejected
    deriving (Show, Eq)

setTLS13RTT0Status :: RTT0Status -> HandshakeM ()
setTLS13RTT0Status s = modify (\hst -> hst{hstTLS13RTT0Status = s})

getTLS13RTT0Status :: HandshakeM RTT0Status
getTLS13RTT0Status = gets hstTLS13RTT0Status

setTLS13EarlySecret :: BaseSecret EarlySecret -> HandshakeM ()
setTLS13EarlySecret secret = modify (\hst -> hst{hstTLS13EarlySecret = Just secret})

getTLS13EarlySecret :: HandshakeM (Maybe (BaseSecret EarlySecret))
getTLS13EarlySecret = gets hstTLS13EarlySecret

setTLS13ResumptionSecret :: BaseSecret ResumptionSecret -> HandshakeM ()
setTLS13ResumptionSecret secret = modify (\hst -> hst{hstTLS13ResumptionSecret = Just secret})

getTLS13ResumptionSecret :: HandshakeM (Maybe (BaseSecret ResumptionSecret))
getTLS13ResumptionSecret = gets hstTLS13ResumptionSecret

setTLS13CertComp :: Bool -> HandshakeM ()
setTLS13CertComp comp = modify (\hst -> hst{hstTLS13CertComp = comp})

getTLS13CertComp :: HandshakeM Bool
getTLS13CertComp = gets hstTLS13CertComp

setCCS13Sent :: Bool -> HandshakeM ()
setCCS13Sent sent = modify (\hst -> hst{hstCCS13Sent = sent})

getCCS13Sent :: HandshakeM Bool
getCCS13Sent = gets hstCCS13Sent

setCCS13Recv :: Bool -> HandshakeM ()
setCCS13Recv sent = modify (\hst -> hst{hstCCS13Recv = sent})

getCCS13Recv :: HandshakeM Bool
getCCS13Recv = gets hstCCS13Recv

setCertReqSent :: Bool -> HandshakeM ()
setCertReqSent b = modify (\hst -> hst{hstCertReqSent = b})

getCertReqSent :: HandshakeM Bool
getCertReqSent = gets hstCertReqSent

setClientCertSent :: Bool -> HandshakeM ()
setClientCertSent b = modify (\hst -> hst{hstClientCertSent = b})

getClientCertSent :: HandshakeM Bool
getClientCertSent = gets hstClientCertSent

setClientCertChain :: CertificateChain -> HandshakeM ()
setClientCertChain b = modify (\hst -> hst{hstClientCertChain = Just b})

getClientCertChain :: HandshakeM (Maybe CertificateChain)
getClientCertChain = gets hstClientCertChain

setClientSentStatusRequest :: Bool -> HandshakeM ()
setClientSentStatusRequest b = modify (\hst -> hst{hstClientSentStatusRequest = b})

getClientSentStatusRequest :: HandshakeM Bool
getClientSentStatusRequest = gets hstClientSentStatusRequest

--
setCertReqToken :: Maybe ByteString -> HandshakeM ()
setCertReqToken token = modify $ \hst -> hst{hstCertReqToken = token}

getCertReqToken :: HandshakeM (Maybe ByteString)
getCertReqToken = gets hstCertReqToken

--
setCertReqCBdata :: Maybe CertReqCBdata -> HandshakeM ()
setCertReqCBdata d = modify (\hst -> hst{hstCertReqCBdata = d})

getCertReqCBdata :: HandshakeM (Maybe CertReqCBdata)
getCertReqCBdata = gets hstCertReqCBdata

-- Dead code, until we find some use for the extension
setCertReqSigAlgsCert :: Maybe [HashAndSignatureAlgorithm] -> HandshakeM ()
setCertReqSigAlgsCert as = modify $ \hst -> hst{hstCertReqSigAlgsCert = as}

getCertReqSigAlgsCert :: HandshakeM (Maybe [HashAndSignatureAlgorithm])
getCertReqSigAlgsCert = gets hstCertReqSigAlgsCert

--
getPendingCipher :: HandshakeM Cipher
getPendingCipher = fromJust <$> gets hstPendingCipher

addHandshakeMessage :: ByteString -> HandshakeM ()
addHandshakeMessage content = modify $ \hs -> hs{hstHandshakeMessages = content : hstHandshakeMessages hs}

getHandshakeMessages :: HandshakeM [ByteString]
getHandshakeMessages = gets (reverse . hstHandshakeMessages)

getHandshakeMessagesRev :: HandshakeM [ByteString]
getHandshakeMessagesRev = gets hstHandshakeMessages

updateHandshakeDigest :: ByteString -> HandshakeM ()
updateHandshakeDigest content = modify $ \hs ->
    hs
        { hstHandshakeDigest = case hstHandshakeDigest hs of
            HandshakeMessages bytes -> HandshakeMessages (content : bytes)
            HandshakeDigestContext hashCtx -> HandshakeDigestContext $ hashUpdate hashCtx content
        }

-- | Compress the whole transcript with the specified function.  Function @f@
-- takes the handshake digest as input and returns an encoded handshake message
-- to replace the transcript with.
foldHandshakeDigest :: Hash -> (ByteString -> ByteString) -> HandshakeM ()
foldHandshakeDigest hashAlg f = modify $ \hs ->
    case hstHandshakeDigest hs of
        HandshakeMessages bytes ->
            let hashCtx = foldl hashUpdate (hashInit hashAlg) $ reverse bytes
                folded = f (hashFinal hashCtx)
             in hs
                    { hstHandshakeDigest = HandshakeMessages [folded]
                    , hstHandshakeMessages = [folded]
                    }
        HandshakeDigestContext hashCtx ->
            let folded = f (hashFinal hashCtx)
                hashCtx' = hashUpdate (hashInit hashAlg) folded
             in hs
                    { hstHandshakeDigest = HandshakeDigestContext hashCtx'
                    , hstHandshakeMessages = [folded]
                    }

getSessionHash :: HandshakeM ByteString
getSessionHash = gets $ \hst ->
    case hstHandshakeDigest hst of
        HandshakeDigestContext hashCtx -> hashFinal hashCtx
        HandshakeMessages _ -> error "un-initialized session hash"

getHandshakeDigest :: Version -> Role -> HandshakeM ByteString
getHandshakeDigest ver role = gets gen
  where
    gen hst = case hstHandshakeDigest hst of
        HandshakeDigestContext hashCtx ->
            let msecret = fromJust $ hstMainSecret hst
                cipher = fromJust $ hstPendingCipher hst
             in generateFinished ver cipher msecret hashCtx
        HandshakeMessages _ ->
            error "un-initialized handshake digest"
    generateFinished
        | role == ClientRole = generateClientFinished
        | otherwise = generateServerFinished

-- | Generate the main secret from the pre-main secret.
setMainSecretFromPre
    :: ByteArrayAccess preMain
    => Version
    -- ^ chosen transmission version
    -> Role
    -- ^ the role (Client or Server) of the generating side
    -> preMain
    -- ^ the pre-main secret
    -> HandshakeM ByteString
setMainSecretFromPre ver role preMainSecret = do
    ems <- getExtendedMainSecret
    secret <- if ems then get >>= genExtendedSecret else genSecret <$> get
    setMainSecret ver role secret
    return secret
  where
    genSecret hst =
        generateMainSecret
            ver
            (fromJust $ hstPendingCipher hst)
            preMainSecret
            (hstClientRandom hst)
            (fromJust $ hstServerRandom hst)
    genExtendedSecret hst =
        generateExtendedMainSecret
            ver
            (fromJust $ hstPendingCipher hst)
            preMainSecret
            <$> getSessionHash

-- | Set main secret and as a side effect generate the key block
-- with all the right parameters, and setup the pending tx/rx state.
setMainSecret :: Version -> Role -> ByteString -> HandshakeM ()
setMainSecret ver role mainSecret = modify $ \hst ->
    let (pendingTx, pendingRx) = computeKeyBlock hst mainSecret ver role
     in hst
            { hstMainSecret = Just mainSecret
            , hstPendingTxState = Just pendingTx
            , hstPendingRxState = Just pendingRx
            }

computeKeyBlock
    :: HandshakeState -> ByteString -> Version -> Role -> (RecordState, RecordState)
computeKeyBlock hst mainSecret ver cc = (pendingTx, pendingRx)
  where
    cipher = fromJust $ hstPendingCipher hst
    keyblockSize = cipherKeyBlockSize cipher

    bulk = cipherBulk cipher
    digestSize =
        if hasMAC (bulkF bulk)
            then hashDigestSize (cipherHash cipher)
            else 0
    keySize = bulkKeySize bulk
    ivSize = bulkIVSize bulk
    kb =
        generateKeyBlock
            ver
            cipher
            (hstClientRandom hst)
            (fromJust $ hstServerRandom hst)
            mainSecret
            keyblockSize

    (cMACSecret, sMACSecret, cWriteKey, sWriteKey, cWriteIV, sWriteIV) =
        fromJust $
            partition6 kb (digestSize, digestSize, keySize, keySize, ivSize, ivSize)

    cstClient =
        CryptState
            { cstKey = bulkInit bulk (BulkEncrypt `orOnServer` BulkDecrypt) cWriteKey
            , cstIV = cWriteIV
            , cstMacSecret = cMACSecret
            }
    cstServer =
        CryptState
            { cstKey = bulkInit bulk (BulkDecrypt `orOnServer` BulkEncrypt) sWriteKey
            , cstIV = sWriteIV
            , cstMacSecret = sMACSecret
            }
    msClient = MacState{msSequence = 0}
    msServer = MacState{msSequence = 0}

    pendingTx =
        RecordState
            { stCryptState = if cc == ClientRole then cstClient else cstServer
            , stMacState = if cc == ClientRole then msClient else msServer
            , stCryptLevel = CryptMainSecret
            , stCipher = Just cipher
            , stCompression = hstPendingCompression hst
            }
    pendingRx =
        RecordState
            { stCryptState = if cc == ClientRole then cstServer else cstClient
            , stMacState = if cc == ClientRole then msServer else msClient
            , stCryptLevel = CryptMainSecret
            , stCipher = Just cipher
            , stCompression = hstPendingCompression hst
            }

    orOnServer f g = if cc == ClientRole then f else g

setServerHelloParameters
    :: Version
    -- ^ chosen version
    -> ServerRandom
    -> Cipher
    -> Compression
    -> HandshakeM ()
setServerHelloParameters ver sran cipher compression = do
    modify $ \hst ->
        hst
            { hstServerRandom = Just sran
            , hstPendingCipher = Just cipher
            , hstPendingCompression = compression
            , hstHandshakeDigest = updateDigest $ hstHandshakeDigest hst
            }
  where
    hashAlg = getHash ver cipher
    updateDigest (HandshakeMessages bytes) = HandshakeDigestContext $ foldl hashUpdate (hashInit hashAlg) $ reverse bytes
    updateDigest (HandshakeDigestContext _) = error "cannot initialize digest with another digest"

-- The TLS12 Hash is cipher specific, and some TLS12 algorithms use SHA384
-- instead of the default SHA256.
getHash :: Version -> Cipher -> Hash
getHash ver ciph
    | ver < TLS12 = SHA1_MD5
    | maybe True (< TLS12) (cipherMinVer ciph) = SHA256
    | otherwise = cipherHash ciph
