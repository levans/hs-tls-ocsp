{-# LANGUAGE OverloadedStrings #-}

module OCSPHookSpec (spec) where

import Test.Hspec
import Network.TLS
import Network.TLS.X509
import Data.IORef
import Control.Exception (ErrorCall(..), catch)
import qualified Data.ByteString as B
import Data.X509 (CertificateChain(..))

-- Mock OCSP response (simplified DER-encoded structure)
mockOcspResponse :: B.ByteString
mockOcspResponse = B.pack [0x30, 0x82, 0x01, 0x00] -- Basic DER SEQUENCE header

-- Mock certificate chain for testing
mockCertChain :: CertificateChain
mockCertChain = CertificateChain []  -- Empty chain for testing

-- Mock SNI hostname
mockSNI :: Maybe HostName
mockSNI = Just "example.com"

spec :: Spec
spec = describe "OCSP Hook Execution" $ do
    describe "onCertificateStatus hook" $ do
        it "can return OCSP response" $ do
            let hook = \_ _ -> return $ Just mockOcspResponse
            result <- hook mockCertChain mockSNI
            result `shouldBe` Just mockOcspResponse

        it "can disable OCSP by returning Nothing" $ do
            let hook = \_ _ -> return Nothing
            result <- hook mockCertChain mockSNI
            result `shouldBe` (Nothing :: Maybe B.ByteString)

        it "hook is called during server parameter creation" $ do
            hookCallCounter <- newIORef (0 :: Int)
            let trackingHook _ _ = do
                    modifyIORef hookCallCounter (+1)
                    return $ Just mockOcspResponse
                
                serverParams = defaultServerHooks { onCertificateStatus = trackingHook }
            
            -- Simulate hook call
            _ <- onCertificateStatus serverParams mockCertChain mockSNI
            callCount <- readIORef hookCallCounter
            callCount `shouldBe` 1

        it "hook can be called multiple times" $ do
            responses <- newIORef ([] :: [Maybe B.ByteString])
            let loggingHook _ _ = do
                    let response = Just mockOcspResponse
                    modifyIORef responses (response:)
                    return response
                
                serverParams = defaultServerHooks { onCertificateStatus = loggingHook }
            
            -- Call hook multiple times
            _ <- onCertificateStatus serverParams mockCertChain mockSNI
            _ <- onCertificateStatus serverParams mockCertChain mockSNI
            _ <- onCertificateStatus serverParams mockCertChain mockSNI
            
            allResponses <- readIORef responses
            length allResponses `shouldBe` 3
            all (== Just mockOcspResponse) allResponses `shouldBe` True

    describe "Hook integration with ServerHooks" $ do
        it "default hook returns Nothing" $ do
            result <- onCertificateStatus defaultServerHooks mockCertChain mockSNI
            result `shouldBe` Nothing

        it "can override default hook" $ do
            let customHooks = defaultServerHooks { 
                    onCertificateStatus = \_ _ -> return $ Just mockOcspResponse 
                }
            result <- onCertificateStatus customHooks mockCertChain mockSNI
            result `shouldBe` Just mockOcspResponse

        it "hook maintains independence from other hooks" $ do
            clientCertHookCalled <- newIORef False
            let customHooks = defaultServerHooks { 
                    onCertificateStatus = \_ _ -> return $ Just mockOcspResponse,
                    onClientCertificate = \_ -> do
                        writeIORef clientCertHookCalled True
                        return $ CertificateUsageAccept
                }
            
            -- Call OCSP hook
            ocspResult <- onCertificateStatus customHooks mockCertChain mockSNI
            ocspResult `shouldBe` Just mockOcspResponse
            
            -- Verify other hook wasn't affected
            wasClientCertHookCalled <- readIORef clientCertHookCalled
            wasClientCertHookCalled `shouldBe` False

    describe "Hook error handling" $ do
        it "can handle hook that throws exception" $ do
            let errorHook _ _ = error "OCSP service unavailable"
                serverParams = defaultServerHooks { onCertificateStatus = errorHook }
            
            result <- (onCertificateStatus serverParams mockCertChain mockSNI >> return (Left "should not reach here")) 
                      `catch` (\e -> return $ Right $ show (e :: ErrorCall))
            
            case result of
                Right errMsg -> errMsg `shouldContain` "OCSP service unavailable"
                Left _ -> expectationFailure "Expected exception to be caught"

    describe "Hook response validation" $ do
        it "accepts valid DER-encoded response" $ do
            let hook = \_ _ -> return $ Just mockOcspResponse
            result <- hook mockCertChain mockSNI
            case result of
                Just response -> B.length response `shouldSatisfy` (> 0)
                Nothing -> expectationFailure "Expected OCSP response"

        it "accepts empty response as None" $ do
            let hook = \_ _ -> return Nothing
            result <- hook mockCertChain mockSNI
            result `shouldBe` (Nothing :: Maybe B.ByteString)

        it "can return different responses on subsequent calls" $ do
            callCount <- newIORef (0 :: Int)
            let dynamicHook _ _ = do
                    count <- readIORef callCount
                    modifyIORef callCount (+1)
                    if even count
                        then return $ Just mockOcspResponse
                        else return Nothing
            
            result1 <- dynamicHook mockCertChain mockSNI
            result2 <- dynamicHook mockCertChain mockSNI
            result3 <- dynamicHook mockCertChain mockSNI
            
            result1 `shouldBe` Just mockOcspResponse
            result2 `shouldBe` Nothing
            result3 `shouldBe` Just mockOcspResponse

        it "hook receives certificate chain and SNI parameters" $ do
            receivedChain <- newIORef Nothing
            receivedSNI <- newIORef Nothing
            let captureHook chain sni = do
                    writeIORef receivedChain (Just chain)
                    writeIORef receivedSNI (Just sni)
                    return $ Just mockOcspResponse
                
                serverParams = defaultServerHooks { onCertificateStatus = captureHook }
            
            _ <- onCertificateStatus serverParams mockCertChain mockSNI
            
            capturedChain <- readIORef receivedChain
            capturedSNI <- readIORef receivedSNI
            
            capturedChain `shouldBe` Just mockCertChain
            capturedSNI `shouldBe` Just mockSNI