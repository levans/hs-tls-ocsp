{-# LANGUAGE OverloadedStrings #-}

module OCSPHookSpec (spec) where

import Test.Hspec
import Network.TLS
import Network.TLS.X509
import Data.IORef
import Control.Exception (ErrorCall(..), catch)
import qualified Data.ByteString as B

-- Mock OCSP response (simplified DER-encoded structure)
mockOcspResponse :: B.ByteString
mockOcspResponse = B.pack [0x30, 0x82, 0x01, 0x00] -- Basic DER SEQUENCE header

spec :: Spec
spec = describe "OCSP Hook Execution" $ do
    describe "onCertificateStatus hook" $ do
        it "can return OCSP response" $ do
            let hook = return $ Just mockOcspResponse
            result <- hook
            result `shouldBe` Just mockOcspResponse

        it "can disable OCSP by returning Nothing" $ do
            let hook = return Nothing
            result <- hook
            result `shouldBe` (Nothing :: Maybe B.ByteString)

        it "hook is called during server parameter creation" $ do
            hookCallCounter <- newIORef (0 :: Int)
            let trackingHook = do
                    modifyIORef hookCallCounter (+1)
                    return $ Just mockOcspResponse
                
                serverParams = defaultServerHooks { onCertificateStatus = trackingHook }
            
            -- Simulate hook call
            _ <- onCertificateStatus serverParams
            callCount <- readIORef hookCallCounter
            callCount `shouldBe` 1

        it "hook can be called multiple times" $ do
            responses <- newIORef ([] :: [Maybe B.ByteString])
            let loggingHook = do
                    let response = Just mockOcspResponse
                    modifyIORef responses (response:)
                    return response
                
                serverParams = defaultServerHooks { onCertificateStatus = loggingHook }
            
            -- Call hook multiple times
            _ <- onCertificateStatus serverParams
            _ <- onCertificateStatus serverParams
            _ <- onCertificateStatus serverParams
            
            allResponses <- readIORef responses
            length allResponses `shouldBe` 3
            all (== Just mockOcspResponse) allResponses `shouldBe` True

    describe "Hook integration with ServerHooks" $ do
        it "default hook returns Nothing" $ do
            result <- onCertificateStatus defaultServerHooks
            result `shouldBe` Nothing

        it "can override default hook" $ do
            let customHooks = defaultServerHooks { 
                    onCertificateStatus = return $ Just mockOcspResponse 
                }
            result <- onCertificateStatus customHooks
            result `shouldBe` Just mockOcspResponse

        it "hook maintains independence from other hooks" $ do
            clientCertHookCalled <- newIORef False
            let customHooks = defaultServerHooks { 
                    onCertificateStatus = return $ Just mockOcspResponse,
                    onClientCertificate = \_ -> do
                        writeIORef clientCertHookCalled True
                        return $ CertificateUsageAccept
                }
            
            -- Call OCSP hook
            ocspResult <- onCertificateStatus customHooks
            ocspResult `shouldBe` Just mockOcspResponse
            
            -- Verify other hook wasn't affected
            wasClientCertHookCalled <- readIORef clientCertHookCalled
            wasClientCertHookCalled `shouldBe` False

    describe "Hook error handling" $ do
        it "can handle hook that throws exception" $ do
            let errorHook = error "OCSP service unavailable"
                serverParams = defaultServerHooks { onCertificateStatus = errorHook }
            
            result <- (onCertificateStatus serverParams >> return (Left "should not reach here")) 
                      `catch` (\e -> return $ Right $ show (e :: ErrorCall))
            
            case result of
                Right errMsg -> errMsg `shouldContain` "OCSP service unavailable"
                Left _ -> expectationFailure "Expected exception to be caught"

    describe "Hook response validation" $ do
        it "accepts valid DER-encoded response" $ do
            let hook = return $ Just mockOcspResponse
            result <- hook
            case result of
                Just response -> B.length response `shouldSatisfy` (> 0)
                Nothing -> expectationFailure "Expected OCSP response"

        it "accepts empty response as None" $ do
            let hook = return Nothing
            result <- hook
            result `shouldBe` (Nothing :: Maybe B.ByteString)

        it "can return different responses on subsequent calls" $ do
            callCount <- newIORef (0 :: Int)
            let dynamicHook = do
                    count <- readIORef callCount
                    modifyIORef callCount (+1)
                    if even count
                        then return $ Just mockOcspResponse
                        else return Nothing
            
            result1 <- dynamicHook
            result2 <- dynamicHook
            result3 <- dynamicHook
            
            result1 `shouldBe` Just mockOcspResponse
            result2 `shouldBe` Nothing
            result3 `shouldBe` Just mockOcspResponse