{-# LANGUAGE OverloadedStrings #-}

-- OCSP Stapling Test Server
-- Proves that OCSP hooks work end-to-end in both TLS 1.2 and TLS 1.3

import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad
import Crypto.Random
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as LC
import Data.Default (def)
import Data.IORef
import Data.X509.CertificateStore
import Network.Socket (accept, bind, close, listen, socket)
import qualified Network.Socket as S
import Network.TLS.SessionTicket
import System.Console.GetOpt
import System.Environment
import System.Exit
import System.IO
import System.IO.Unsafe (unsafeDupablePerformIO)

import Network.TLS hiding (TLS12, TLS13)
import qualified Network.TLS as TLS
import Network.TLS.Extra.Cipher
import Network.TLS.X509 (CertificateChain(..))

import Common
import Imports

-- Test OCSP response (DER-encoded) - same as we were using before
testOcspResponse :: B.ByteString
testOcspResponse = B.pack [0x30, 0x82, 0x02, 0x0b, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x02, 0x04, 0x30, 0x82, 0x02, 0x00, 0x06, 
    0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x01, 0xf1, 0x30, 0x82, 
    0x01, 0xed, 0x30, 0x81, 0xd6, 0xa1, 0x38, 0x30, 0x36, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 
    0x04, 0x03, 0x0c, 0x07, 0x54, 0x65, 0x73, 0x74, 0x2d, 0x43, 0x41, 0x31, 0x15, 0x30, 0x13, 0x06, 
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x2d, 0x54, 0x65, 0x73, 0x74, 0x2d, 
    0x43, 0x41, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x18, 
    0x0f, 0x32, 0x30, 0x32, 0x35, 0x30, 0x37, 0x30, 0x35, 0x30, 0x36, 0x31, 0x37, 0x32, 0x33, 0x5a, 
    0x30, 0x64, 0x30, 0x62, 0x30, 0x4d, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 
    0x00, 0x04, 0x14, 0x4a, 0x71, 0x94, 0xc5, 0x18, 0x1b, 0x30, 0xd8, 0x0b, 0x03, 0x2d, 0xc4, 0x32, 
    0xd6, 0x36, 0x48, 0x0c, 0xe1, 0xfc, 0x31, 0x04, 0x14, 0xa8, 0x15, 0x5c, 0x12, 0xc6, 0xed, 0x21, 
    0x51, 0x1a, 0x8c, 0xe5, 0xf6, 0xb8, 0x3a, 0xac, 0x98, 0x6b, 0x30, 0xd3, 0xa3, 0x02, 0x14, 0x32, 
    0x13, 0xfd, 0x34, 0x41, 0xd2, 0xad, 0x0a, 0xcc, 0x9a, 0x9e, 0xc9, 0x25, 0x1a, 0x93, 0x64, 0xcb, 
    0x9b, 0x39, 0x97, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x35, 0x30, 0x37, 0x30, 0x35, 0x30, 
    0x36, 0x31, 0x37, 0x32, 0x33, 0x5a, 0xa1, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2b, 0x06, 
    0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10, 0xe0, 0x4c, 0x91, 0x4d, 0x76, 
    0x49, 0x53, 0x94, 0x56, 0xa4, 0xf2, 0x91, 0x71, 0xf1, 0x0a, 0x6e, 0x30, 0x0d, 0x06, 0x09, 0x2a, 
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x41, 
    0xd5, 0x69, 0xd1, 0xa7, 0xab, 0x08, 0x8d, 0x52, 0x84, 0x23, 0xa3, 0xa7, 0x53, 0xcd, 0x06, 0xcd, 
    0xb7, 0x7a, 0x21, 0x0e, 0xeb, 0xbe, 0x53, 0x40, 0x54, 0x47, 0x8a, 0x28, 0x2c, 0x3b, 0x4a, 0x69, 
    0x96, 0x42, 0xb2, 0x0e, 0xbb, 0xf0, 0x40, 0x57, 0xc5, 0xc1, 0xe4, 0x0b, 0x3a, 0xbb, 0xce, 0xa2, 
    0xfb, 0x5f, 0x8e, 0x2a, 0x09, 0x50, 0x35, 0xb2, 0xd8, 0x7c, 0x02, 0xf8, 0x0b, 0x13, 0x5d, 0xc1, 
    0xc7, 0x80, 0xbd, 0x2c, 0xb5, 0xea, 0x82, 0x60, 0x72, 0xcb, 0xcf, 0x98, 0xcf, 0xe3, 0x54, 0x2f, 
    0x05, 0x61, 0x44, 0x07, 0x59, 0x33, 0x5d, 0x46, 0x58, 0x17, 0x9e, 0x03, 0x76, 0xb6, 0xc2, 0x2f, 
    0xef, 0x80, 0x6c, 0xd6, 0x4f, 0x46, 0xe4, 0x87, 0xa1, 0x00, 0x34, 0x9c, 0x18, 0xf6, 0x48, 0x08, 
    0xb0, 0xd4, 0xfb, 0xe2, 0x97, 0xec, 0xb9, 0xa2, 0x6e, 0x88, 0x4a, 0x0a, 0x7f, 0x83, 0x7b, 0x3a, 
    0x94, 0x3d, 0x0c, 0x25, 0x42, 0xc2, 0x4a, 0x5d, 0x8a, 0xb0, 0x49, 0x32, 0x7f, 0x94, 0xee, 0xec, 
    0x19, 0xab, 0x36, 0xfe, 0x71, 0x69, 0x5d, 0x62, 0x2f, 0x8c, 0x38, 0xfd, 0x6b, 0x4d, 0x0a, 0xcd, 
    0xbd, 0x15, 0xaf, 0xbf, 0xce, 0xe8, 0x93, 0xcc, 0x1c, 0xac, 0x9a, 0xb6, 0x6f, 0xdd, 0xc3, 0x9a, 
    0xe1, 0x5a, 0x7f, 0x78, 0xec, 0x4a, 0x99, 0xa2, 0x0a, 0x6e, 0x93, 0x76, 0x15, 0xc4, 0x59, 0x20, 
    0x22, 0x61, 0x19, 0xef, 0xa0, 0xe3, 0x4a, 0x7b, 0x9d, 0xca, 0x4a, 0xd2, 0xed, 0xe9, 0xdd, 0x6f, 
    0x8d, 0x9b, 0xc6, 0xc8, 0xc2, 0x40, 0xc5, 0x7a, 0x63, 0xdf, 0xa0, 0x1e, 0x07, 0xf2, 0x7e, 0x61, 
    0x12, 0x11, 0x71, 0x39, 0xeb, 0x35, 0x43, 0xb6, 0xc9, 0xeb, 0x3b, 0x48, 0x5d, 0xd3, 0xdb, 0xbc, 
    0x9f, 0xd5, 0x7a, 0x84, 0x6d, 0x20, 0x65, 0x1c, 0x00, 0x93, 0x39, 0x95, 0x43, 0x82, 0xa4]

-- Hook call counter for testing verification  
hookCallCounter :: IORef Int
{-# NOINLINE hookCallCounter #-}
hookCallCounter = unsafeDupablePerformIO $ newIORef 0

-- OCSP hook implementation for testing
ocspHook :: CertificateChain -> Maybe String -> IO (Maybe B.ByteString)
ocspHook (CertificateChain certs) sni = do
    count <- atomicModifyIORef hookCallCounter (\n -> (n+1, n+1))
    
    putStrLn ""
    putStrLn $ "*** OCSP HOOK CALLED (Call #" ++ show count ++ ") ***"
    putStrLn $ "    SNI hostname: " ++ show sni
    putStrLn $ "    Certificate chain length: " ++ show (length certs)
    putStrLn $ "    Providing OCSP response: " ++ show (B.length testOcspResponse) ++ " bytes"
    putStrLn $ "    Response type: Raw DER (library handles TLS wrapping)"
    putStrLn ""
    
    return $ Just testOcspResponse

-- Simple HTTP response
httpResponse :: LC.ByteString
httpResponse = "HTTP/1.1 200 OK\r\n\
              \Content-Type: text/html\r\n\
              \Content-Length: 89\r\n\
              \\r\n\
              \<html><body>\
              \<h1>OCSP Test Server</h1>\
              \<p>TLS handshake with OCSP stapling worked!</p>\
              \</body></html>"

-- Server configuration
data ServerConfig = ServerConfig
    { configPort :: Int
    , configTlsVersion :: Maybe TLS.Version
    , configCertFile :: String
    , configKeyFile :: String
    , configVerbose :: Bool
    }

defaultServerConfig :: ServerConfig
defaultServerConfig = ServerConfig
    { configPort = 4443
    , configTlsVersion = Nothing
    , configCertFile = "../server.crt"
    , configKeyFile = "../server.key"
    , configVerbose = False
    }

-- Command line flags
data Flag 
    = Port String
    | TLS12
    | TLS13
    | Certificate String
    | Key String
    | Verbose
    | Help
    deriving (Show, Eq)

options :: [OptDescr Flag]
options = 
    [ Option ['p'] ["port"] (ReqArg Port "PORT") "Port to listen on (default: 4443)"
    , Option [] ["tls12"] (NoArg TLS12) "Force TLS 1.2 only"
    , Option [] ["tls13"] (NoArg TLS13) "Force TLS 1.3 only"
    , Option [] ["certificate"] (ReqArg Certificate "FILE") "Certificate file"
    , Option [] ["key"] (ReqArg Key "FILE") "Private key file"
    , Option ['v'] ["verbose"] (NoArg Verbose) "Enable verbose output"
    , Option ['h'] ["help"] (NoArg Help) "Show this help"
    ]

parseConfig :: [Flag] -> ServerConfig
parseConfig flags = foldl applyFlag defaultServerConfig flags
  where
    applyFlag config flag = case flag of
        Port p -> config { configPort = read p }
        TLS12 -> config { configTlsVersion = Just TLS.TLS12 }
        TLS13 -> config { configTlsVersion = Just TLS.TLS13 }
        Certificate f -> config { configCertFile = f }
        Key f -> config { configKeyFile = f }
        Verbose -> config { configVerbose = True }
        _ -> config

-- Create server parameters with OCSP hook
createServerParams :: ServerConfig -> Credential -> IO ServerParams
createServerParams config cred = do
    when (configVerbose config) $ putStrLn "Creating ServerParams with OCSP hook..."
    
    sessionMgr <- newSessionTicketManager Network.TLS.SessionTicket.defaultConfig
    let certStore = makeCertificateStore []
    
    let supportedVersions = case configTlsVersion config of
            Just v -> [v]
            Nothing -> [TLS.TLS13, TLS.TLS12]
            
        params = def 
            { serverWantClientCert = False
            , serverCACertificates = []
            , serverShared = def
                { sharedSessionManager = sessionMgr
                , sharedCAStore = certStore  
                , sharedCredentials = Credentials [cred]
                }
            , serverSupported = def
                { supportedVersions = supportedVersions
                , supportedCiphers = ciphersuite_default
                }
            , serverHooks = def
                { onCertificateStatus = ocspHook
                }
            }
    
    when (configVerbose config) $ do
        putStrLn "OCSP hook registered in ServerParams"
        putStrLn $ "Supported TLS versions: " ++ show supportedVersions
    return params

-- Handle a client connection
handleClient :: ServerConfig -> ServerParams -> S.Socket -> IO ()
handleClient config params sock = do
    (clientSock, clientAddr) <- accept sock
    when (configVerbose config) $ 
        putStrLn $ "Incoming connection from: " ++ show clientAddr
    
    void $ forkIO $ do
        ctx <- contextNew clientSock params
        
        E.handle (\e -> putStrLn $ "Client error: " ++ show (e :: E.SomeException)) $ do
            when (configVerbose config) $ putStrLn "Starting TLS handshake..."
            
            -- Reset hook counter before handshake
            writeIORef hookCallCounter 0
            
            -- Perform TLS handshake
            handshake ctx
            
            -- Check hook call results
            hookCalls <- readIORef hookCallCounter
            putStrLn $ "TLS Handshake completed! OCSP hook called " ++ show hookCalls ++ " times"
            
            -- Get handshake information
            info <- contextGetInformation ctx
            case info of
                Nothing -> putStrLn "No handshake information available"
                Just i -> do
                    putStrLn $ "TLS Version: " ++ show (infoVersion i)
                    putStrLn $ "Cipher Suite: " ++ show (infoCipher i)
            
            -- Handle HTTP request
            when (configVerbose config) $ putStrLn "Waiting for HTTP request..."
            request <- recvData ctx
            unless (B.null request) $ do
                when (configVerbose config) $ 
                    putStrLn $ "Request: " ++ show (B.take 50 request) ++ "..."
                    
                sendData ctx httpResponse
                when (configVerbose config) $ putStrLn "Sent HTTP response"
            
            -- Clean shutdown
            bye ctx
            when (configVerbose config) $ putStrLn "Connection closed cleanly"
            
        `E.finally` close clientSock

-- Load server credentials
loadCredentials :: ServerConfig -> IO Credential
loadCredentials config = do
    when (configVerbose config) $ do
        putStrLn $ "Loading certificate: " ++ configCertFile config
        putStrLn $ "Loading private key: " ++ configKeyFile config
    
    result <- credentialLoadX509 (configCertFile config) (configKeyFile config)
    case result of
        Left err -> error $ "Failed to load credentials: " ++ err
        Right cred -> do
            when (configVerbose config) $ putStrLn "Credentials loaded successfully"
            return cred

-- Main server loop
runServer :: ServerConfig -> IO ()
runServer config = do
    putStrLn "OCSP Stapling Test Server"
    putStrLn "========================="
    
    -- Load credentials
    cred <- loadCredentials config
    
    -- Create server parameters with OCSP hook
    params <- createServerParams config cred
    
    -- Create and bind socket
    sock <- socket S.AF_INET S.Stream S.defaultProtocol
    S.setSocketOption sock S.ReuseAddr 1
    bind sock (S.SockAddrInet (fromIntegral $ configPort config) 0)
    listen sock 5
    
    putStrLn $ "Server listening on port " ++ show (configPort config)
    case configTlsVersion config of
        Just v -> putStrLn $ "TLS Version: " ++ show v ++ " only"
        Nothing -> putStrLn "TLS Versions: TLS 1.3 and TLS 1.2"
    putStrLn ""
    putStrLn "Test commands:"
    putStrLn $ "  TLS 1.2: openssl s_client -connect localhost:" ++ show (configPort config) ++ " -tls1_2 -status"
    putStrLn $ "  TLS 1.3: openssl s_client -connect localhost:" ++ show (configPort config) ++ " -tls1_3 -status"
    putStrLn ""
    
    -- Accept connections forever
    (forever $ handleClient config params sock)
        `E.finally` close sock

printUsage :: IO ()
printUsage = putStrLn $ usageInfo "OCSP Stapling Test Server\n" options

main :: IO ()
main = do
    -- Set unbuffered output from the start
    hSetBuffering stdout NoBuffering
    hSetBuffering stderr NoBuffering
    
    args <- getArgs
    let (flags, _, errs) = getOpt Permute options args
    
    unless (null errs) $ do
        mapM_ putStrLn errs
        exitFailure
    
    when (Help `elem` flags) $ do
        printUsage
        exitSuccess
    
    let config = parseConfig flags
    runServer config