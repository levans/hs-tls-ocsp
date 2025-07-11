{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.TLS.Handshake.Server.ServerHello12 (
    sendServerHello12,
) where

import qualified Data.ByteString as B
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Credentials
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake.Certificate
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Random
import Network.TLS.Handshake.Server.Common
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Parameters
import Network.TLS.Session
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Types
import Network.TLS.X509 hiding (Certificate)

import System.Timeout (timeout)

-- | Check if client requested OCSP stapling via status_request extension
hasStatusRequest :: [ExtensionRaw] -> Bool
hasStatusRequest exts = lookupAndDecode EID_StatusRequest MsgTClientHello exts False (const True :: StatusRequest -> Bool)

-- | Helper function to convert Extension to ExtensionRaw
toExtensionRaw :: Extension e => e -> ExtensionRaw
toExtensionRaw ext = ExtensionRaw (extensionID ext) (extensionEncode ext)

sendServerHello12
    :: ServerParams
    -> Context
    -> (Cipher, Maybe Credential)
    -> CH
    -> IO (Maybe SessionData)
sendServerHello12 sparams ctx (usedCipher, mcred) ch@CH{..} = do
    resumeSessionData <- recoverSessionData ctx ch
    case resumeSessionData of
        Nothing -> do
            serverSession <- newSession ctx
            usingState_ ctx $ setSession serverSession
            serverhello <-
                makeServerHello sparams ctx usedCipher mcred chExtensions serverSession
            build <- sendServerFirstFlight sparams ctx usedCipher mcred chExtensions
            let ff = serverhello : build [ServerHelloDone]
            sendPacket12 ctx $ Handshake ff
            contextFlush ctx
        Just sessionData -> do
            usingState_ ctx $ do
                setSession chSession
                setTLS12SessionResuming True
            serverhello <-
                makeServerHello sparams ctx usedCipher mcred chExtensions chSession
            sendPacket12 ctx $ Handshake [serverhello]
            let mainSecret = sessionSecret sessionData
            usingHState ctx $ setMainSecret TLS12 ServerRole mainSecret
            logKey ctx $ MainSecret mainSecret
            sendCCSandFinished ctx ServerRole
    return resumeSessionData

recoverSessionData :: Context -> CH -> IO (Maybe SessionData)
recoverSessionData ctx CH{..} = do
    serverName <- usingState_ ctx getClientSNI
    ems <- processExtendedMainSecret ctx TLS12 MsgTClientHello chExtensions
    let mSessionTicket =
            extensionLookup EID_SessionTicket chExtensions
                >>= extensionDecode MsgTClientHello
        mticket = case mSessionTicket of
            Nothing -> Nothing
            Just (SessionTicket ticket) -> Just ticket
        midentity = ticketOrSessionID12 mticket chSession
    case midentity of
        Nothing -> return Nothing
        Just identity -> do
            sd <- sessionResume (sharedSessionManager $ ctxShared ctx) identity
            validateSession chCiphers serverName ems sd

validateSession
    :: [CipherID]
    -> Maybe HostName
    -> Bool
    -> Maybe SessionData
    -> IO (Maybe SessionData)
validateSession _ _ _ Nothing = return Nothing
validateSession ciphers sni ems m@(Just sd)
    -- SessionData parameters are assumed to match the local server configuration
    -- so we need to compare only to ClientHello inputs.  Abbreviated handshake
    -- uses the same server_name than full handshake so the same
    -- credentials (and thus ciphers) are available.
    | TLS12 < sessionVersion sd = return Nothing -- fixme
    | sessionCipher sd `notElem` ciphers = return Nothing
    | isJust sni && sessionClientSNI sd /= sni = return Nothing
    | ems && not emsSession = return Nothing
    | not ems && emsSession =
        let err = "client resumes an EMS session without EMS"
         in throwCore $ Error_Protocol err HandshakeFailure
    | otherwise = return m
  where
    emsSession = SessionEMS `elem` sessionFlags sd

sendServerFirstFlight
    :: ServerParams
    -> Context
    -> Cipher
    -> Maybe Credential
    -> [ExtensionRaw]
    -> IO ([Handshake] -> [Handshake])
sendServerFirstFlight sparams ctx usedCipher mcred chExts = do
    let b0 = id
    let cc = case mcred of
            Just (srvCerts, _) -> srvCerts
            _ -> CertificateChain []
    let b1 = b0 . (Certificate cc :)
    usingState_ ctx $ setServerCertificateChain cc

    -- Send OCSP CertificateStatus immediately after Certificate (RFC 6066)
    -- Also handle must-staple certificate validation
    b2 <- if hasStatusRequest chExts && not (isNullCertificateChain cc)
        then do
            clientSNI <- usingState_ ctx getClientSNI
            
            -- Check if HTTP/2 was negotiated via ALPN - if so, use non-blocking OCSP
            alpnProto <- usingState_ ctx getNegotiatedProtocol
            let isHTTP2 = alpnProto == Just "h2"
            
            mOcspResponse <- if isHTTP2
                then do
                    -- For HTTP/2, call OCSP hook with configurable timeout to prevent handshake hanging
                    result <- timeout (serverOCSPTimeoutMicros sparams) $ onCertificateStatus (serverHooks sparams) cc clientSNI
                    case result of
                        Just ocspResp -> return ocspResp
                        Nothing -> return Nothing  -- Timeout - don't provide OCSP response
                else 
                    -- For HTTP/1.1, use normal blocking call
                    onCertificateStatus (serverHooks sparams) cc clientSNI
            
            -- Validate OCSP response size to prevent allocation spikes
            mValidatedOcspResponse <- case mOcspResponse of
                Just ocspDer -> 
                    if B.length ocspDer > 16384  -- Max 16KB per RFC recommendation
                        then do
                            -- Log oversized response and reject it
                            return Nothing  -- TODO: Add proper logging here
                        else return $ Just ocspDer
                Nothing -> return Nothing
                    
            case mValidatedOcspResponse of
                Just ocspDer -> return $ b1 . (CertificateStatus ocspDer :)
                Nothing -> do
                    -- Check if certificate requires OCSP stapling (must-staple)
                    if certificateChainRequiresStapling cc && serverEnforceMustStaple sparams
                        then if isHTTP2
                            then throwCore $ Error_Protocol "certificate requires OCSP stapling but OCSP hook timed out (HTTP/2)" CertificateRequired
                            else throwCore $ Error_Protocol "certificate requires OCSP stapling but no OCSP response provided" CertificateRequired
                        else return b1
        else do
            -- Client didn't request OCSP but check if certificate requires it (must-staple)
            if not (isNullCertificateChain cc) && certificateChainRequiresStapling cc && serverEnforceMustStaple sparams
                then throwCore $ Error_Protocol "certificate requires OCSP stapling but client did not request it" CertificateRequired
                else return b1

    -- send server key exchange if needed (after Certificate and CertificateStatus)
    skx <- case cipherKeyExchange usedCipher of
        CipherKeyExchange_DH_Anon -> Just <$> generateSKX_DH_Anon
        CipherKeyExchange_DHE_RSA -> Just <$> generateSKX_DHE KX_RSA
        CipherKeyExchange_DHE_DSA -> Just <$> generateSKX_DHE KX_DSA
        CipherKeyExchange_ECDHE_RSA -> Just <$> generateSKX_ECDHE KX_RSA
        CipherKeyExchange_ECDHE_ECDSA -> Just <$> generateSKX_ECDHE KX_ECDSA
        _ -> return Nothing
    let b3 = case skx of
            Nothing -> b2
            Just kx -> b2 . (ServerKeyXchg kx :)
    -- FIXME we don't do this on a Anonymous server

    -- When configured, send a certificate request with the DNs of all
    -- configured CA certificates.
    --
    -- Client certificates MUST NOT be accepted if not requested.
    --
    if serverWantClientCert sparams
        then do
            let (certTypes, hashSigs) =
                    let as = supportedHashSignatures $ ctxSupported ctx
                     in (nub $ mapMaybe hashSigToCertType as, as)
                creq =
                    CertRequest
                        certTypes
                        hashSigs
                        (map extractCAname $ serverCACertificates sparams)
            usingHState ctx $ setCertReqSent True
            return $ b3 . (creq :)
        else return b3
  where
    setup_DHE = do
        let possibleFFGroups = negotiatedGroupsInCommon ctx chExts `intersect` availableFFGroups
        (dhparams, priv, pub) <-
            case possibleFFGroups of
                [] ->
                    let dhparams = fromJust $ serverDHEParams sparams
                     in case findFiniteFieldGroup dhparams of
                            Just g -> do
                                usingHState ctx $ setSupportedGroup g
                                generateFFDHE ctx g
                            Nothing -> do
                                (priv, pub) <- generateDHE ctx dhparams
                                return (dhparams, priv, pub)
                g : _ -> do
                    usingHState ctx $ setSupportedGroup g
                    generateFFDHE ctx g

        let serverParams = serverDHParamsFrom dhparams pub

        usingHState ctx $ setServerDHParams serverParams
        usingHState ctx $ setDHPrivate priv
        return serverParams

    -- Choosing a hash algorithm to sign (EC)DHE parameters
    -- in ServerKeyExchange. Hash algorithm is not suggested by
    -- the chosen cipher suite. So, it should be selected based on
    -- the "signature_algorithms" extension in a client hello.
    -- If RSA is also used for key exchange, this function is
    -- not called.
    decideHashSig pubKey = do
        let hashSigs = hashAndSignaturesInCommon ctx chExts
        case filter (pubKey `signatureCompatible`) hashSigs of
            [] -> error ("no hash signature for " ++ pubkeyType pubKey)
            x : _ -> return x

    generateSKX_DHE kxsAlg = do
        serverParams <- setup_DHE
        pubKey <- getLocalPublicKey ctx
        mhashSig <- decideHashSig pubKey
        signed <- digitallySignDHParams ctx serverParams pubKey mhashSig
        case kxsAlg of
            KX_RSA -> return $ SKX_DHE_RSA serverParams signed
            KX_DSA -> return $ SKX_DHE_DSA serverParams signed
            _ ->
                error ("generate skx_dhe unsupported key exchange signature: " ++ show kxsAlg)

    generateSKX_DH_Anon = SKX_DH_Anon <$> setup_DHE

    setup_ECDHE grp = do
        usingHState ctx $ setSupportedGroup grp
        (srvpri, srvpub) <- generateECDHE ctx grp
        let serverParams = ServerECDHParams grp srvpub
        usingHState ctx $ setServerECDHParams serverParams
        usingHState ctx $ setGroupPrivate srvpri
        return serverParams

    generateSKX_ECDHE kxsAlg = do
        let possibleECGroups = negotiatedGroupsInCommon ctx chExts `intersect` availableECGroups
        grp <- case possibleECGroups of
            [] -> throwCore $ Error_Protocol "no common group" HandshakeFailure
            g : _ -> return g
        serverParams <- setup_ECDHE grp
        pubKey <- getLocalPublicKey ctx
        mhashSig <- decideHashSig pubKey
        signed <- digitallySignECDHParams ctx serverParams pubKey mhashSig
        case kxsAlg of
            KX_RSA -> return $ SKX_ECDHE_RSA serverParams signed
            KX_ECDSA -> return $ SKX_ECDHE_ECDSA serverParams signed
            _ ->
                error ("generate skx_ecdhe unsupported key exchange signature: " ++ show kxsAlg)

---
-- When the client sends a certificate, check whether
-- it is acceptable for the application.
--
---
makeServerHello
    :: ServerParams
    -> Context
    -> Cipher
    -> Maybe Credential
    -> [ExtensionRaw]
    -> Session
    -> IO Handshake
makeServerHello sparams ctx usedCipher mcred chExts session = do
    resuming <- usingState_ ctx getTLS12SessionResuming
    srand <-
        serverRandom ctx TLS12 $ supportedVersions $ serverSupported sparams
    case mcred of
        Just cred -> storePrivInfoServer ctx cred
        _ -> return () -- return a sensible error

    -- in TLS12, we need to check as well the certificates we are sending if they have in the extension
    -- the necessary bits set.
    secReneg <- usingState_ ctx getSecureRenegotiation
    secRengExt <-
        if secReneg
            then do
                vd <- usingState_ ctx $ do
                    cvd <- getVerifyData ClientRole
                    svd <- getVerifyData ServerRole
                    return $ extensionEncode $ SecureRenegotiation cvd svd
                return [ExtensionRaw EID_SecureRenegotiation vd]
            else return []
    ems <- usingHState ctx getExtendedMainSecret
    let emsExt
            | ems =
                let raw = extensionEncode ExtendedMainSecret
                 in [ExtensionRaw EID_ExtendedMainSecret raw]
            | otherwise = []
    protoExt <- applicationProtocol ctx chExts sparams
    sniExt <- do
        if resuming
            then return []
            else do
                msni <- usingState_ ctx getClientSNI
                case msni of
                    -- RFC6066: In this event, the server SHALL include
                    -- an extension of type "server_name" in the
                    -- (extended) server hello. The "extension_data"
                    -- field of this extension SHALL be empty.
                    Just _ -> return [ExtensionRaw EID_ServerName ""]
                    Nothing -> return []
    let useTicket = sessionUseTicket $ sharedSessionManager $ serverShared sparams
        sessionTicketExt
            | not resuming && useTicket = Just $ toExtensionRaw $ SessionTicket ""
            | otherwise = Nothing

    -- in TLS12, we need to check as well the certificates we are sending if they have in the extension
    -- the necessary bits set.
    secReneg <- usingState_ ctx getSecureRenegotiation
    secureRenegExt <-
        if secReneg
            then do
                vd <- usingState_ ctx $ do
                    cvd <- getVerifyData ClientRole
                    svd <- getVerifyData ServerRole
                    return $ SecureRenegotiation cvd svd
                return $ Just $ toExtensionRaw vd
            else return Nothing

    let recodeSizeLimitExt = Nothing  -- TODO: Implement record size limit processing
        ecPointExt = Nothing  -- TODO: Implement EC point format if needed
        alpnExt = Nothing     -- TODO: Implement ALPN if needed

    let statusReqExt =
            if hasStatusRequest chExts
                then Just $ ExtensionRaw EID_StatusRequest ""   -- empty payload as per RFC 6066
                else Nothing

    let shExts =
            sharedHelloExtensions (serverShared sparams)
                ++ catMaybes
                    [ {- 0x00 -} listToMaybe sniExt
                    , {- 0x05 -} statusReqExt
                    , {- 0x0b -} ecPointExt
                    , {- 0x10 -} alpnExt
                    , {- 0x17 -} listToMaybe emsExt
                    , {- 0x1c -} recodeSizeLimitExt
                    , {- 0x23 -} sessionTicketExt
                    , {- 0xff01 -} secureRenegExt
                    ]
    usingState_ ctx $ setVersion TLS12
    usingHState ctx $
        setServerHelloParameters TLS12 srand usedCipher nullCompression
    return $
        ServerHello
            TLS12
            srand
            session
            (cipherID usedCipher)
            (compressionID nullCompression)
            shExts

hashAndSignaturesInCommon
    :: Context -> [ExtensionRaw] -> [HashAndSignatureAlgorithm]
hashAndSignaturesInCommon ctx chExts =
    let cHashSigs = case extensionLookup EID_SignatureAlgorithms chExts
            >>= extensionDecode MsgTClientHello of
            -- See Section 7.4.1.4.1 of RFC 5246.
            Nothing ->
                [ (HashSHA1, SignatureECDSA)
                , (HashSHA1, SignatureRSA)
                , (HashSHA1, SignatureDSA)
                ]
            Just (SignatureAlgorithms sas) -> sas
        sHashSigs = supportedHashSignatures $ ctxSupported ctx
     in -- The values in the "signature_algorithms" extension
        -- are in descending order of preference.
        -- However here the algorithms are selected according
        -- to server preference in 'supportedHashSignatures'.
        sHashSigs `intersect` cHashSigs

negotiatedGroupsInCommon :: Context -> [ExtensionRaw] -> [Group]
negotiatedGroupsInCommon ctx chExts = case extensionLookup EID_SupportedGroups chExts
    >>= extensionDecode MsgTClientHello of
    Just (SupportedGroups clientGroups) ->
        let serverGroups = supportedGroups (ctxSupported ctx)
         in serverGroups `intersect` clientGroups
    _ -> []
