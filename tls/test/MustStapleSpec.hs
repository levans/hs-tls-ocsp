{-# LANGUAGE OverloadedStrings #-}

module MustStapleSpec (spec) where

import Test.Hspec
import Network.TLS (hasMustStapleExtension, certificateChainRequiresStapling, CertificateChain(..))
import Certificate (simpleCertificate)
import PubKey (getGlobalRSAPair)
import Data.X509
import qualified Data.ByteString as B

spec :: Spec
spec = describe "Must-Staple Certificate Validation" $ do
    describe "hasMustStapleExtension" $ do
        it "returns False for certificates without TLS Feature extension" $ do
            let (pubKey, _) = getGlobalRSAPair
                cert = simpleCertificate (PubKeyRSA pubKey)
            hasMustStapleExtension cert `shouldBe` False

    describe "certificateChainRequiresStapling" $ do
        it "returns False for empty certificate chain" $ do
            certificateChainRequiresStapling (CertificateChain []) `shouldBe` False

        it "returns False for chain with non-must-staple leaf certificate" $ do
            let (pubKey, _) = getGlobalRSAPair
                cert = simpleCertificate (PubKeyRSA pubKey)
                signedCert = createSignedCert cert
                chain = CertificateChain [signedCert]
            certificateChainRequiresStapling chain `shouldBe` False

-- | Create a signed certificate from a certificate (for testing purposes)
createSignedCert :: Certificate -> SignedCertificate
createSignedCert cert =
    let sig = replicate 40 1
        sigalg = SignatureALG HashSHA1 PubKeyALG_RSA
        (signedExact, ()) = objectToSignedExact (\_ -> (B.pack sig, sigalg, ())) cert
     in signedExact