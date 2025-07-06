{-# LANGUAGE OverloadedStrings #-}

module MustStapleAdvancedSpec (spec) where

import Test.Hspec
import Network.TLS.X509
import Data.X509
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.Hourglass
import qualified Data.ByteString as B
import PubKey (getGlobalRSAPair)

-- TLS Feature extension OID: 1.3.6.1.5.5.7.1.24
tlsFeatureOID :: [Integer]
tlsFeatureOID = [1, 3, 6, 1, 5, 5, 7, 1, 24]

-- Create a TLS Feature extension with must-staple (value 5)
createMustStapleExtension :: B.ByteString
createMustStapleExtension = 
    let asn1 = [Start Sequence, IntVal 5, End Sequence] -- status_request = 5
    in encodeASN1' DER asn1

-- Create a TLS Feature extension without must-staple
createNonMustStapleExtension :: B.ByteString  
createNonMustStapleExtension =
    let asn1 = [Start Sequence, IntVal 6, End Sequence] -- some other feature
    in encodeASN1' DER asn1

-- Create a certificate with TLS Feature extension
createCertWithTLSFeature :: B.ByteString -> Certificate
createCertWithTLSFeature tlsFeatureBytes =
    let (pubKey, _) = getGlobalRSAPair
        tlsFeatureExt = ExtensionRaw tlsFeatureOID False tlsFeatureBytes
        exts = Extensions $ Just [tlsFeatureExt]
        cert = Certificate {
            certVersion = 3,
            certSerial = 1,
            certSignatureAlg = SignatureALG HashSHA256 PubKeyALG_RSA,
            certIssuerDN = DistinguishedName [],
            certValidity = (thisUpdate, nextUpdate),
            certSubjectDN = DistinguishedName [],
            certPubKey = PubKeyRSA pubKey,
            certExtensions = exts
        }
        thisUpdate = DateTime (Date 2023 January 1) (TimeOfDay 0 0 0 0)
        nextUpdate = DateTime (Date 2024 January 1) (TimeOfDay 0 0 0 0)
    in cert

spec :: Spec
spec = describe "Advanced Must-Staple Certificate Validation" $ do
    describe "TLS Feature extension parsing" $ do
        it "correctly identifies must-staple certificate" $ do
            let cert = createCertWithTLSFeature createMustStapleExtension
            hasMustStapleExtension cert `shouldBe` True

        it "correctly identifies non-must-staple certificate" $ do
            let cert = createCertWithTLSFeature createNonMustStapleExtension
            hasMustStapleExtension cert `shouldBe` False

        it "handles certificate without TLS Feature extension" $ do
            let (pubKey, _) = getGlobalRSAPair
                cert = Certificate {
                    certVersion = 3,
                    certSerial = 1,
                    certSignatureAlg = SignatureALG HashSHA256 PubKeyALG_RSA,
                    certIssuerDN = DistinguishedName [],
                    certValidity = (thisUpdate, nextUpdate),
                    certSubjectDN = DistinguishedName [],
                    certPubKey = PubKeyRSA pubKey,
                    certExtensions = Extensions Nothing
                }
                thisUpdate = DateTime (Date 2023 January 1) (TimeOfDay 0 0 0 0)
                nextUpdate = DateTime (Date 2024 January 1) (TimeOfDay 0 0 0 0)
            hasMustStapleExtension cert `shouldBe` False

        it "handles certificate with empty extensions" $ do
            let (pubKey, _) = getGlobalRSAPair
                cert = Certificate {
                    certVersion = 3,
                    certSerial = 1,
                    certSignatureAlg = SignatureALG HashSHA256 PubKeyALG_RSA,
                    certIssuerDN = DistinguishedName [],
                    certValidity = (thisUpdate, nextUpdate),
                    certSubjectDN = DistinguishedName [],
                    certPubKey = PubKeyRSA pubKey,
                    certExtensions = Extensions $ Just []
                }
                thisUpdate = DateTime (Date 2023 January 1) (TimeOfDay 0 0 0 0)
                nextUpdate = DateTime (Date 2024 January 1) (TimeOfDay 0 0 0 0)
            hasMustStapleExtension cert `shouldBe` False

    describe "TLS Feature extension with multiple values" $ do
        it "detects must-staple among multiple features" $ do
            let multiFeatureAsn1 = [Start Sequence, IntVal 6, IntVal 5, IntVal 7, End Sequence]
                multiFeatureBytes = encodeASN1' DER multiFeatureAsn1
                cert = createCertWithTLSFeature multiFeatureBytes
            hasMustStapleExtension cert `shouldBe` True

        it "handles TLS Feature extension with only non-must-staple values" $ do
            let nonMustStapleAsn1 = [Start Sequence, IntVal 6, IntVal 7, IntVal 8, End Sequence]
                nonMustStapleBytes = encodeASN1' DER nonMustStapleAsn1
                cert = createCertWithTLSFeature nonMustStapleBytes
            hasMustStapleExtension cert `shouldBe` False

    describe "Invalid TLS Feature extension handling" $ do
        it "handles malformed ASN.1 in TLS Feature extension" $ do
            let malformedBytes = B.pack [0xFF, 0xFE, 0xFD] -- Invalid ASN.1
                cert = createCertWithTLSFeature malformedBytes
            hasMustStapleExtension cert `shouldBe` False

        it "handles empty TLS Feature extension" $ do
            let emptyBytes = B.empty
                cert = createCertWithTLSFeature emptyBytes
            hasMustStapleExtension cert `shouldBe` False

    describe "Certificate chain validation" $ do
        it "identifies must-staple requirement in leaf certificate" $ do
            let leafCert = createCertWithTLSFeature createMustStapleExtension
                intermediateCert = createCertWithTLSFeature createNonMustStapleExtension
                leafSigned = createSignedCert leafCert
                intermediateSigned = createSignedCert intermediateCert
                chain = CertificateChain [leafSigned, intermediateSigned]
            certificateChainRequiresStapling chain `shouldBe` True

        it "ignores must-staple in intermediate certificates" $ do
            let leafCert = createCertWithTLSFeature createNonMustStapleExtension
                intermediateCert = createCertWithTLSFeature createMustStapleExtension
                leafSigned = createSignedCert leafCert
                intermediateSigned = createSignedCert intermediateCert
                chain = CertificateChain [leafSigned, intermediateSigned]
            certificateChainRequiresStapling chain `shouldBe` False

        it "handles single certificate chain" $ do
            let cert = createCertWithTLSFeature createMustStapleExtension
                signed = createSignedCert cert
                chain = CertificateChain [signed]
            certificateChainRequiresStapling chain `shouldBe` True

    describe "Edge cases and error conditions" $ do
        it "handles very large TLS Feature extension" $ do
            let largeAsn1 = Start Sequence : (replicate 1000 (IntVal 6)) ++ [IntVal 5] ++ [End Sequence]
                largeBytes = encodeASN1' DER largeAsn1
                cert = createCertWithTLSFeature largeBytes
            hasMustStapleExtension cert `shouldBe` True

        it "handles TLS Feature extension with negative values" $ do
            let negativeAsn1 = [Start Sequence, IntVal (-1), IntVal 5, End Sequence]
                negativeBytes = encodeASN1' DER negativeAsn1
                cert = createCertWithTLSFeature negativeBytes
            hasMustStapleExtension cert `shouldBe` True

-- Helper function to create a signed certificate from a certificate
createSignedCert :: Certificate -> SignedCertificate
createSignedCert cert =
    let sig = replicate 40 1
        sigalg = SignatureALG HashSHA256 PubKeyALG_RSA
        (signedExact, ()) = objectToSignedExact (\_ -> (B.pack sig, sigalg, ())) cert
     in signedExact