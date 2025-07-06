{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module OCSPExtensionSpec (spec) where

import Test.Hspec
import Test.QuickCheck
import Network.TLS.Extension
import Network.TLS.Wire
import qualified Data.ByteString as B

spec :: Spec
spec = describe "OCSP StatusRequest Extension" $ do
    describe "StatusRequest encoding/decoding" $ do
        it "can encode StatusRequest extension" $ do
            let statusReq = StatusRequest
                encoded = extensionEncode statusReq
            -- Should be: status_type=1 (1 byte) + responder_id_length=0 (2 bytes) + request_ext_length=0 (2 bytes)
            encoded `shouldBe` B.pack [0x01, 0x00, 0x00, 0x00, 0x00]

        it "can decode StatusRequest from ClientHello" $ do
            let validPayload = B.pack [0x01, 0x00, 0x00, 0x00, 0x00] -- OCSP with no additional data
                result = extensionDecode MsgTClientHello validPayload :: Maybe StatusRequest
            result `shouldBe` Just StatusRequest

        it "can decode StatusRequest from ServerHello" $ do
            let validPayload = B.pack [0x01, 0x00, 0x00, 0x00, 0x00]
                result = extensionDecode MsgTServerHello validPayload :: Maybe StatusRequest
            result `shouldBe` Just StatusRequest

        it "rejects invalid status type" $ do
            let invalidPayload = B.pack [0x02, 0x00, 0x00, 0x00, 0x00] -- Invalid status type
                result = extensionDecode MsgTClientHello invalidPayload :: Maybe StatusRequest
            result `shouldBe` Nothing

        it "rejects truncated payload" $ do
            let truncatedPayload = B.pack [0x01, 0x00] -- Too short
                result = extensionDecode MsgTClientHello truncatedPayload :: Maybe StatusRequest
            result `shouldBe` Nothing

        it "handles responder ID list correctly" $ do
            let payloadWithResponderIds = B.pack [0x01, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00]
                result = extensionDecode MsgTClientHello payloadWithResponderIds :: Maybe StatusRequest
            result `shouldBe` Just StatusRequest

        it "handles request extensions correctly" $ do
            let payloadWithReqExts = B.pack [0x01, 0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04]
                result = extensionDecode MsgTClientHello payloadWithReqExts :: Maybe StatusRequest
            result `shouldBe` Just StatusRequest

    describe "Extension ID and supportedExtensions" $ do
        it "has correct extension ID" $ do
            extensionID StatusRequest `shouldBe` EID_StatusRequest

        it "EID_StatusRequest is in supportedExtensions" $ do
            EID_StatusRequest `shouldSatisfy` (`elem` supportedExtensions)

        it "EID_StatusRequest has correct numeric value" $ do
            let (ExtensionID val) = EID_StatusRequest
            val `shouldBe` 0x05

    describe "Round-trip encoding/decoding" $ do
        it "can round-trip encode and decode StatusRequest" $ property $ \() ->
            let statusReq = StatusRequest
                encoded = extensionEncode statusReq
                decoded = extensionDecode MsgTClientHello encoded :: Maybe StatusRequest
            in decoded === Just statusReq