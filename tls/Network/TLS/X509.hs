-- | X509 helpers
module Network.TLS.X509 (
    CertificateChain (..),
    Certificate (..),
    SignedCertificate,
    getCertificate,
    isNullCertificateChain,
    getCertificateChainLeaf,
    CertificateRejectReason (..),
    CertificateUsage (..),
    CertificateStore,
    ValidationCache,
    -- defaultValidationCache, -- Not available in this version
    exceptionValidationCache,
    validateDefault,
    FailedReason,
    ServiceID,
    wrapCertificateChecks,
    pubkeyType,
    validateClientCertificate,
    hasMustStapleExtension,
    certificateChainRequiresStapling,
) where

import Data.X509
import Data.X509.CertificateStore
import Data.X509.Validation
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.OID
import qualified Data.ByteString as B

isNullCertificateChain :: CertificateChain -> Bool
isNullCertificateChain (CertificateChain l) = null l

getCertificateChainLeaf :: CertificateChain -> Maybe (SignedExact Certificate)
getCertificateChainLeaf (CertificateChain []) = Nothing
getCertificateChainLeaf (CertificateChain (x : _)) = Just x

-- | Certificate and Chain rejection reason
data CertificateRejectReason
    = CertificateRejectExpired
    | CertificateRejectRevoked
    | CertificateRejectUnknownCA
    | CertificateRejectAbsent
    | CertificateRejectOther String
    deriving (Show, Eq)

-- | Certificate Usage callback possible returns values.
data CertificateUsage
    = -- | usage of certificate accepted
      CertificateUsageAccept
    | -- | usage of certificate rejected
      CertificateUsageReject CertificateRejectReason
    deriving (Show, Eq)

wrapCertificateChecks :: [FailedReason] -> CertificateUsage
wrapCertificateChecks [] = CertificateUsageAccept
wrapCertificateChecks l
    | Expired `elem` l = CertificateUsageReject CertificateRejectExpired
    | InFuture `elem` l = CertificateUsageReject CertificateRejectExpired
    | UnknownCA `elem` l = CertificateUsageReject CertificateRejectUnknownCA
    | SelfSigned `elem` l = CertificateUsageReject CertificateRejectUnknownCA
    | EmptyChain `elem` l = CertificateUsageReject CertificateRejectAbsent
    | otherwise = CertificateUsageReject $ CertificateRejectOther (show l)

pubkeyType :: PubKey -> String
pubkeyType = show . pubkeyToAlg

-- | A utility function for client authentication which can be used
-- `onClientCertificate`.
--
-- Since: 2.1.7
validateClientCertificate
    :: CertificateStore
    -> ValidationCache
    -> CertificateChain
    -> IO CertificateUsage
validateClientCertificate store cache cc =
    wrapCertificateChecks
        <$> validate
            HashSHA256
            defaultHooks
            defaultChecks{checkFQHN = False}
            store
            cache
            ("", mempty)
            cc

-- | Check if a certificate has the TLS Feature extension with must-staple (RFC 7633)
-- TLS Feature extension OID: 1.3.6.1.5.5.7.1.24
-- Must-staple feature value: 5 (status_request)
hasMustStapleExtension :: Certificate -> Bool
hasMustStapleExtension cert =
    case getTLSFeatureExtensionBytes (certExtensions cert) of
        Just bytes -> parseTLSFeatureExtension bytes
        Nothing -> False
  where
    -- TLS Feature extension OID: 1.3.6.1.5.5.7.1.24
    extensionOID = [1, 3, 6, 1, 5, 5, 7, 1, 24]
    
    getTLSFeatureExtensionBytes :: Extensions -> Maybe B.ByteString
    getTLSFeatureExtensionBytes (Extensions Nothing) = Nothing
    getTLSFeatureExtensionBytes (Extensions (Just extList)) = 
        findExtensionByOID extensionOID extList
    
    findExtensionByOID :: [Integer] -> [ExtensionRaw] -> Maybe B.ByteString
    findExtensionByOID targetOID [] = Nothing
    findExtensionByOID targetOID (ExtensionRaw oid _ bytes : rest)
        | oid == targetOID = Just bytes
        | otherwise = findExtensionByOID targetOID rest

-- | Parse TLS Feature extension content to check for must-staple (value 5)
parseTLSFeatureExtension :: B.ByteString -> Bool
parseTLSFeatureExtension bytes =
    case decodeASN1' DER bytes of
        Right asn1 -> hasStatusRequestFeature asn1
        Left _ -> False

-- | Check if ASN.1 sequence contains status_request feature (value 5)
hasStatusRequestFeature :: [ASN1] -> Bool
hasStatusRequestFeature asn1 = 5 `elem` extractIntegers 10 asn1  -- Max depth of 10
  where
    extractIntegers :: Int -> [ASN1] -> [Integer]
    extractIntegers 0 _ = []  -- Prevent deep recursion
    extractIntegers _ [] = []
    extractIntegers depth (Start Sequence : rest) = extractIntegers (depth - 1) rest
    extractIntegers depth (End Sequence : rest) = extractIntegers depth rest
    extractIntegers depth (IntVal n : rest) = n : extractIntegers depth rest
    extractIntegers depth (_ : rest) = extractIntegers depth rest

-- | Check if any certificate in the chain requires OCSP stapling
-- According to RFC 7633, only the leaf certificate's must-staple matters
certificateChainRequiresStapling :: CertificateChain -> Bool
certificateChainRequiresStapling (CertificateChain []) = False
certificateChainRequiresStapling (CertificateChain (leafCert : _)) =
    hasMustStapleExtension (getCertificate leafCert)
