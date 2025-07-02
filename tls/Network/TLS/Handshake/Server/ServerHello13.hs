{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.ServerHello13 (
    sendServerHello13,
) where

import Control.Monad.State.Strict
import qualified Data.ByteString as B

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
import Network.TLS.X509

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
    -- parse CompressCertificate to check if it is broken here
    let zlib =
            lookupAndDecode
                EID_CompressCertificate
                MsgTClientHello
                chExtensions
                False
                (\(CompressCertificate ccas) -> CCA_Zlib `elem` ccas)

    recodeSizeLimitExt <- processRecordSizeLimit ctx chExtensions True
    enableMyRecordLimit ctx

    newSession ctx >>= \ss -> usingState_ ctx $ do
        setSession ss
        setTLS13ClientSupportsPHA supportsPHA
    usingHState ctx $ setSupportedGroup $ keyShareEntryGroup clientKeyShare
    srand <- setServerParameter
    -- ALPN is used in choosePSK
    alpnExt <- applicationProtocol ctx chExtensions sparams
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
    let p = makeCredentialPredicate TLS13 chExtensions
        allCreds =
            filterCredentials (isCredentialAllowed TLS13 p) $
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
        liftIO $ enablePeerRecordLimit ctx
        sendExtensions rtt0OK alpnExt recodeSizeLimitExt
        case mCredInfo of
            Nothing -> return ()
            Just (cred, hashSig) -> sendCertAndVerify cred hashSig zlib
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
    when rtt0OK $ setEstablished ctx (EarlyDataAllowed rtt0max)
    return (appKey, clientHandshakeSecret, authenticated, rtt0OK)
  where
    choice = makeCipherChoice TLS13 usedCipher

    setServerParameter = do
        srand <-
            serverRandom ctx TLS13 $ supportedVersions $ serverSupported sparams
        usingState_ ctx $ setVersion TLS13
        failOnEitherError $ usingHState ctx $ setHelloParameters13 usedCipher
        return srand

    supportsPHA =
        lookupAndDecode
            EID_PostHandshakeAuth
            MsgTClientHello
            chExtensions
            False
            (\PostHandshakeAuth -> True)

    selectPSK (PreSharedKeyClientHello (PskIdentity identity obfAge : _) bnds@(bnd : _)) = do
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
    selectPSK _ = return (zero, Nothing, False)

    choosePSK =
        lookupAndDecodeAndDo
            EID_PreSharedKey
            MsgTClientHello
            chExtensions
            (return (zero, Nothing, False))
            selectPSK

    checkSessionEquality sdata = do
        msni <- usingState_ ctx getClientSNI
        malpn <- usingState_ ctx getNegotiatedProtocol
        let isSameSNI = sessionClientSNI sdata == msni
            isSameCipher = sessionCipher sdata == cipherID usedCipher
            ciphers = supportedCiphers $ serverSupported sparams
            scid = sessionCipher sdata
            isSameKDF = case findCipher scid ciphers of
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
        return [toExtensionRaw $ PreSharedKeyServerHello $ fromIntegral n]

    decideCredentialInfo allCreds = do
        let err =
                throwCore $ Error_Protocol "broken signature_algorithms extension" DecodeError
        cHashSigs <-
            lookupAndDecodeAndDo
                EID_SignatureAlgorithms
                MsgTClientHello
                chExtensions
                err
                (\(SignatureAlgorithms sas) -> return sas)
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
        let keyShareExt = toExtensionRaw $ KeyShareServerHello keyShare
            versionExt = toExtensionRaw $ SupportedVersionsServerHello TLS13
            extensions' = keyShareExt : versionExt : extensions
            helo = ServerHello13 srand chSession (CipherId (cipherID usedCipher)) extensions'
        loadPacket13 ctx $ Handshake13 [helo]

    sendCertAndVerify cred@(certChain, _) hashSig zlib = do
        storePrivInfoServer ctx cred
        when (serverWantClientCert sparams) $ do
            let certReqCtx = "" -- this must be zero length here.
                certReq = makeCertRequest sparams ctx certReqCtx True
            loadPacket13 ctx $ Handshake13 [certReq]
            usingHState ctx $ setCertReqSent True

        let CertificateChain cs = certChain
        -- Build per-certificate extensions, including OCSP response if available
        -- Also handle must-staple certificate validation
        ess <- if hasStatusRequest chExtensions && not (null cs)
            then do
                mOcspResponse <- liftIO $ onCertificateStatus (serverHooks sparams)
                case mOcspResponse of
                    Just ocspDer ->
                        -- Add OCSP extension to the leaf certificate only
                        let ocspExt = ExtensionRaw EID_StatusRequest ocspDer
                         in return $ [ocspExt] : replicate (length cs - 1) []
                    Nothing -> do
                        -- Check if certificate requires OCSP stapling (must-staple)
                        if certificateChainRequiresStapling certChain
                            then liftIO $ throwCore $ Error_Protocol "certificate requires OCSP stapling but no OCSP response provided" CertificateRequired
                            else return $ replicate (length cs) []
            else do
                -- Client didn't request OCSP but check if certificate requires it (must-staple)
                if not (null cs) && certificateChainRequiresStapling certChain
                    then liftIO $ throwCore $ Error_Protocol "certificate requires OCSP stapling but client did not request it" CertificateRequired
                    else return $ replicate (length cs) []
        let certtag = if zlib then CompressedCertificate13 else Certificate13
        loadPacket13 ctx $
            Handshake13 [certtag "" (TLSCertificateChain certChain) ess]
        liftIO $ usingState_ ctx $ setServerCertificateChain certChain
        hChSc <- transcriptHash ctx
        pubkey <- getLocalPublicKey ctx
        vrfy <- makeCertVerify ctx pubkey hashSig hChSc
        loadPacket13 ctx $ Handshake13 [vrfy]

    sendExtensions rtt0OK alpnExt recodeSizeLimitExt = do
        msni <- liftIO $ usingState_ ctx getClientSNI
        let sniExt = case msni of
                -- RFC6066: In this event, the server SHALL include
                -- an extension of type "server_name" in the
                -- (extended) server hello. The "extension_data"
                -- field of this extension SHALL be empty.
                Just _ -> Just $ toExtensionRaw $ ServerName []
                Nothing -> Nothing

        mgroup <- usingHState ctx getSupportedGroup
        let serverGroups = supportedGroups (ctxSupported ctx)
            groupExt = case serverGroups of
                [] -> Nothing
                rg : _ -> case mgroup of
                    Nothing -> Nothing
                    Just grp
                        | grp == rg -> Nothing
                        | otherwise -> Just $ toExtensionRaw $ SupportedGroups serverGroups
        let earlyDataExt
                | rtt0OK = Just $ toExtensionRaw $ EarlyDataIndication Nothing
                | otherwise = Nothing

        let extensions =
                sharedHelloExtensions (serverShared sparams)
                    ++ catMaybes
                        [ {- 0x00 -} sniExt
                        , {- 0x0a -} groupExt
                        , {- 0x10 -} alpnExt
                        , {- 0x1c -} recodeSizeLimitExt
                        , {- 0x2a -} earlyDataExt
                        ]
        extensions' <-
            liftIO $ onEncryptedExtensionsCreating (serverHooks sparams) extensions
        loadPacket13 ctx $ Handshake13 [EncryptedExtensions13 extensions']

    dhModes =
        lookupAndDecode
            EID_PskKeyExchangeModes
            MsgTClientHello
            chExtensions
            []
            (\(PskKeyExchangeModes ms) -> ms)

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

-- | Check if client requested OCSP stapling via status_request extension  
hasStatusRequest :: [ExtensionRaw] -> Bool
hasStatusRequest exts = lookupAndDecode EID_StatusRequest MsgTClientHello exts False (const True :: StatusRequest -> Bool)
