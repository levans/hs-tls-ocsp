{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.ServerHello13 (
    sendServerHello13,
) where

import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.Serialize (runPut, putWord8)

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Credentials
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.Server.Common
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.Session
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Wire (putOpaque24)
import Network.TLS.X509

-- | Encode OCSP response in CertificateStatus format for TLS 1.3 extensions
-- In TLS 1.3, OCSP responses in Certificate extensions must use the same format as TLS 1.2 CertificateStatus
encodeCertificateStatusForExtension :: B.ByteString -> B.ByteString
encodeCertificateStatusForExtension ocspDer = runPut $ do
    putWord8 0x01      -- status_type = 1 (OCSP)
    putOpaque24 ocspDer -- length (3 bytes) + OCSP DER data

sendServerHello13
    :: ServerParams
    -> Context
    -> KeyShareEntry
    -> (Cipher, Hash, Bool)
    -> CH
    -> IO
        ( SecretTriple ApplicationSecret
        , ClientTrafficSecret HandshakeSecret
        , Bool
        , Bool
        )
sendServerHello13 sparams ctx clientKeyShare (usedCipher, usedHash, rtt0) CH{..} = do
    newSession ctx >>= \ss -> usingState_ ctx $ do
        setSession ss
        setTLS13ClientSupportsPHA supportsPHA
    usingHState ctx $ setSupportedGroup $ keyShareEntryGroup clientKeyShare
    srand <- setServerParameter
    -- ALPN is used in choosePSK
    protoExt <- applicationProtocol ctx chExtensions sparams
    (psk, binderInfo, is0RTTvalid) <- choosePSK
    earlyKey <- calculateEarlySecret ctx choice (Left psk) True
    let earlySecret = pairBase earlyKey
        clientEarlySecret = pairClient earlyKey
    extensions <- checkBinder earlySecret binderInfo
    hrr <- usingState_ ctx getTLS13HRR
    let authenticated = isJust binderInfo
        rtt0OK = authenticated && not hrr && rtt0 && rtt0accept && is0RTTvalid
    extraCreds <-
        usingState_ ctx getClientSNI >>= onServerNameIndication (serverHooks sparams)
    let allCreds =
            filterCredentials (isCredentialAllowed TLS13 chExtensions) $
                extraCreds `mappend` sharedCredentials (ctxShared ctx)
    ----------------------------------------------------------------
    established <- ctxEstablished ctx
    if established /= NotEstablished
        then
            if rtt0OK
                then do
                    usingHState ctx $ setTLS13HandshakeMode RTT0
                    usingHState ctx $ setTLS13RTT0Status RTT0Accepted
                else do
                    usingHState ctx $ setTLS13HandshakeMode PreSharedKey
                    usingHState ctx $ setTLS13RTT0Status RTT0Rejected
        else when authenticated $ usingHState ctx $ setTLS13HandshakeMode PreSharedKey
    -- else : FullHandshake or HelloRetryRequest
    mCredInfo <-
        if authenticated then return Nothing else decideCredentialInfo allCreds
    (ecdhe, keyShare) <- makeServerKeyShare ctx clientKeyShare
    ensureRecvComplete ctx
    (clientHandshakeSecret, handSecret) <- runPacketFlight ctx $ do
        sendServerHello keyShare srand extensions
        sendChangeCipherSpec13 ctx
        ----------------------------------------------------------------
        handKey <- liftIO $ calculateHandshakeSecret ctx choice earlySecret ecdhe
        let serverHandshakeSecret = triServer handKey
            clientHandshakeSecret = triClient handKey
            handSecret = triBase handKey
        liftIO $ do
            if rtt0OK && not (ctxQUICMode ctx)
                then setRxRecordState ctx usedHash usedCipher clientEarlySecret
                else setRxRecordState ctx usedHash usedCipher clientHandshakeSecret
            setTxRecordState ctx usedHash usedCipher serverHandshakeSecret
            let mEarlySecInfo
                    | rtt0OK = Just $ EarlySecretInfo usedCipher clientEarlySecret
                    | otherwise = Nothing
                handSecInfo = HandshakeSecretInfo usedCipher (clientHandshakeSecret, serverHandshakeSecret)
            contextSync ctx $ SendServerHello chExtensions mEarlySecInfo handSecInfo
        ----------------------------------------------------------------
        sendExtensions rtt0OK protoExt
        case mCredInfo of
            Nothing -> return ()
            Just (cred, hashSig) -> sendCertAndVerify cred hashSig
        let ServerTrafficSecret shs = serverHandshakeSecret
        rawFinished <- makeFinished ctx usedHash shs
        loadPacket13 ctx $ Handshake13 [rawFinished]
        return (clientHandshakeSecret, handSecret)
    ----------------------------------------------------------------
    hChSf <- transcriptHash ctx
    appKey <- calculateApplicationSecret ctx choice handSecret hChSf
    let clientApplicationSecret0 = triClient appKey
        serverApplicationSecret0 = triServer appKey
    setTxRecordState ctx usedHash usedCipher serverApplicationSecret0
    let appSecInfo = ApplicationSecretInfo (clientApplicationSecret0, serverApplicationSecret0)
    contextSync ctx $ SendServerFinished appSecInfo
    ----------------------------------------------------------------
    if rtt0OK
        then setEstablished ctx (EarlyDataAllowed rtt0max)
        else
            when (established == NotEstablished) $
                setEstablished ctx (EarlyDataNotAllowed 3) -- hardcoding
    return (appKey, clientHandshakeSecret, authenticated, rtt0OK)
  where
    choice = makeCipherChoice TLS13 usedCipher

    setServerParameter = do
        srand <-
            serverRandom ctx TLS13 $ supportedVersions $ serverSupported sparams
        usingState_ ctx $ setVersion TLS13
        failOnEitherError $ usingHState ctx $ setHelloParameters13 usedCipher
        return srand

    supportsPHA = case extensionLookup EID_PostHandshakeAuth chExtensions
        >>= extensionDecode MsgTClientHello of
        Just PostHandshakeAuth -> True
        Nothing -> False

    choosePSK = case extensionLookup EID_PreSharedKey chExtensions
        >>= extensionDecode MsgTClientHello of
        Just (PreSharedKeyClientHello (PskIdentity identity obfAge : _) bnds@(bnd : _)) -> do
            when (null dhModes) $
                throwCore $
                    Error_Protocol "no psk_key_exchange_modes extension" MissingExtension
            if PSK_DHE_KE `elem` dhModes
                then do
                    let len = sum (map (\x -> B.length x + 1) bnds) + 2
                        mgr = sharedSessionManager $ serverShared sparams
                    -- sessionInvalidate is not used for TLS 1.3
                    -- because PSK is always changed.
                    -- So, identity is not stored in Context.
                    msdata <-
                        if rtt0
                            then sessionResumeOnlyOnce mgr identity
                            else sessionResume mgr identity
                    case msdata of
                        Just sdata -> do
                            let tinfo = fromJust $ sessionTicketInfo sdata
                                psk = sessionSecret sdata
                            isFresh <- checkFreshness tinfo obfAge
                            (isPSKvalid, is0RTTvalid) <- checkSessionEquality sdata
                            if isPSKvalid && isFresh
                                then return (psk, Just (bnd, 0 :: Int, len), is0RTTvalid)
                                else -- fall back to full handshake
                                    return (zero, Nothing, False)
                        _ -> return (zero, Nothing, False)
                else return (zero, Nothing, False)
        _ -> return (zero, Nothing, False)

    checkSessionEquality sdata = do
        msni <- usingState_ ctx getClientSNI
        malpn <- usingState_ ctx getNegotiatedProtocol
        let isSameSNI = sessionClientSNI sdata == msni
            isSameCipher = sessionCipher sdata == cipherID usedCipher
            ciphers = supportedCiphers $ serverSupported sparams
            isSameKDF = case find (\c -> cipherID c == sessionCipher sdata) ciphers of
                Nothing -> False
                Just c -> cipherHash c == cipherHash usedCipher
            isSameVersion = TLS13 == sessionVersion sdata
            isSameALPN = sessionALPN sdata == malpn
            isPSKvalid = isSameKDF && isSameSNI -- fixme: SNI is not required
            is0RTTvalid = isSameVersion && isSameCipher && isSameALPN
        return (isPSKvalid, is0RTTvalid)

    rtt0max = safeNonNegative32 $ serverEarlyDataSize sparams
    rtt0accept = serverEarlyDataSize sparams > 0

    checkBinder _ Nothing = return []
    checkBinder earlySecret (Just (binder, n, tlen)) = do
        binder' <- makePSKBinder ctx earlySecret usedHash tlen Nothing
        unless (binder == binder') $
            decryptError "PSK binder validation failed"
        let selectedIdentity = extensionEncode $ PreSharedKeyServerHello $ fromIntegral n
        return [ExtensionRaw EID_PreSharedKey selectedIdentity]

    decideCredentialInfo allCreds = do
        cHashSigs <- case extensionLookup EID_SignatureAlgorithms chExtensions of
            Nothing ->
                throwCore $ Error_Protocol "no signature_algorithms extension" MissingExtension
            Just sa -> case extensionDecode MsgTClientHello sa of
                Nothing ->
                    throwCore $ Error_Protocol "broken signature_algorithms extension" DecodeError
                Just (SignatureAlgorithms sas) -> return sas
        -- When deciding signature algorithm and certificate, we try to keep
        -- certificates supported by the client, but fallback to all credentials
        -- if this produces no suitable result (see RFC 5246 section 7.4.2 and
        -- RFC 8446 section 4.4.2.2).
        let sHashSigs = filter isHashSignatureValid13 $ supportedHashSignatures $ ctxSupported ctx
            hashSigs = sHashSigs `intersect` cHashSigs
            cltCreds = filterCredentialsWithHashSignatures chExtensions allCreds
        case credentialsFindForSigning13 hashSigs cltCreds of
            Nothing ->
                case credentialsFindForSigning13 hashSigs allCreds of
                    Nothing -> throwCore $ Error_Protocol "credential not found" HandshakeFailure
                    mcs -> return mcs
            mcs -> return mcs

    sendServerHello keyShare srand extensions = do
        let serverKeyShare = extensionEncode $ KeyShareServerHello keyShare
            selectedVersion = extensionEncode $ SupportedVersionsServerHello TLS13
            extensions' =
                ExtensionRaw EID_KeyShare serverKeyShare
                    : ExtensionRaw EID_SupportedVersions selectedVersion
                    : extensions
            helo = ServerHello13 srand chSession (cipherID usedCipher) extensions'
        loadPacket13 ctx $ Handshake13 [helo]

    sendCertAndVerify cred@(certChain, _) hashSig = do
        storePrivInfoServer ctx cred
        when (serverWantClientCert sparams) $ do
            let certReqCtx = "" -- this must be zero length here.
                certReq = makeCertRequest sparams ctx certReqCtx
            loadPacket13 ctx $ Handshake13 [certReq]
            usingHState ctx $ setCertReqSent True

        let CertificateChain cs = certChain
        -- Build per-certificate extensions, including OCSP response if available
        -- Also handle must-staple certificate validation
        ess <- if hasStatusRequest chExtensions && not (null cs)
            then do
                clientSNI <- liftIO $ usingState_ ctx getClientSNI
                mOcspResponse <- liftIO $ onCertificateStatus (serverHooks sparams) certChain clientSNI
                case mOcspResponse of
                    Just ocspDer ->
                        -- Add OCSP extension to the leaf certificate only
                        -- For TLS 1.3, we need to wrap the OCSP DER in CertificateStatus format
                        let wrappedOcsp = encodeCertificateStatusForExtension ocspDer
                            ocspExt = ExtensionRaw EID_StatusRequest wrappedOcsp
                         in return $ [ocspExt] : replicate (length cs - 1) []
                    Nothing -> do
                        -- Check if certificate requires OCSP stapling (must-staple)
                        if certificateChainRequiresStapling certChain && serverEnforceMustStaple sparams
                            then liftIO $ throwCore $ Error_Protocol "certificate requires OCSP stapling but no OCSP response provided" CertificateRequired
                            else return $ replicate (length cs) []
            else do
                -- Client didn't request OCSP but check if certificate requires it (must-staple)
                if not (null cs) && certificateChainRequiresStapling certChain && serverEnforceMustStaple sparams
                    then liftIO $ throwCore $ Error_Protocol "certificate requires OCSP stapling but client did not request it" CertificateRequired
                    else return $ replicate (length cs) []
        loadPacket13 ctx $ Handshake13 [Certificate13 "" certChain ess]
        liftIO $ usingState_ ctx $ setServerCertificateChain certChain
        hChSc <- transcriptHash ctx
        pubkey <- getLocalPublicKey ctx
        vrfy <- makeCertVerify ctx pubkey hashSig hChSc
        loadPacket13 ctx $ Handshake13 [vrfy]

    sendExtensions rtt0OK protoExt = do
        msni <- liftIO $ usingState_ ctx getClientSNI
        let sniExtension = case msni of
                -- RFC6066: In this event, the server SHALL include
                -- an extension of type "server_name" in the
                -- (extended) server hello. The "extension_data"
                -- field of this extension SHALL be empty.
                Just _ -> Just $ ExtensionRaw EID_ServerName ""
                Nothing -> Nothing
        mgroup <- usingHState ctx getSupportedGroup
        let serverGroups = supportedGroups (ctxSupported ctx)
            groupExtension
                | null serverGroups = Nothing
                | maybe True (== head serverGroups) mgroup = Nothing
                | otherwise =
                    Just $
                        ExtensionRaw EID_SupportedGroups $
                            extensionEncode (SupportedGroups serverGroups)
        let earlyDataExtension
                | rtt0OK =
                    Just $
                        ExtensionRaw EID_EarlyData $
                            extensionEncode (EarlyDataIndication Nothing)
                | otherwise = Nothing
        let extensions =
                sharedHelloExtensions (serverShared sparams)
                    ++ catMaybes
                        [ earlyDataExtension
                        , groupExtension
                        , sniExtension
                        ]
                    ++ protoExt
        extensions' <-
            liftIO $ onEncryptedExtensionsCreating (serverHooks sparams) extensions
        loadPacket13 ctx $ Handshake13 [EncryptedExtensions13 extensions']

    dhModes = case extensionLookup EID_PskKeyExchangeModes chExtensions
        >>= extensionDecode MsgTClientHello of
        Just (PskKeyExchangeModes ms) -> ms
        Nothing -> []

    hashSize = hashDigestSize usedHash
    zero = B.replicate hashSize 0

credentialsFindForSigning13
    :: [HashAndSignatureAlgorithm]
    -> Credentials
    -> Maybe (Credential, HashAndSignatureAlgorithm)
credentialsFindForSigning13 hss0 creds = loop hss0
  where
    loop [] = Nothing
    loop (hs : hss) = case credentialsFindForSigning13' hs creds of
        Nothing -> loop hss
        Just cred -> Just (cred, hs)

-- See credentialsFindForSigning.
credentialsFindForSigning13'
    :: HashAndSignatureAlgorithm -> Credentials -> Maybe Credential
credentialsFindForSigning13' sigAlg (Credentials l) = find forSigning l
  where
    forSigning cred = case credentialDigitalSignatureKey cred of
        Nothing -> False
        Just pub -> pub `signatureCompatible13` sigAlg

contextSync :: Context -> ServerState -> IO ()
contextSync ctx ctl = case ctxHandshakeSync ctx of
    HandshakeSync _ sync -> sync ctx ctl
