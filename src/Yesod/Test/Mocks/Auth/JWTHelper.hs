{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}

module Yesod.Test.Mocks.Auth.JWTHelper
       ( requestWithSubject
       , requestWithSubjectRSA
       ) where

import           Control.Lens
import           Control.Monad.Trans.Except (runExceptT)
import           Crypto.JOSE.Compact (encodeCompact)
import qualified Crypto.JOSE.Error as J
import           Crypto.JOSE.JWK (JWK)
import           Crypto.JOSE.JWS (Alg(HS256, RS256), newJWSHeader)
import qualified Crypto.JWT as J
import           Data.ByteString (ByteString)
import           Data.ByteString.Lazy (toStrict)
import           Data.Monoid ((<>))
import           Data.Text (Text)
import           Network.HTTP.Types.Header
import           Yesod.Core (Yesod)
import qualified Yesod.Test.Mocks as Y

requestWithSubject :: (Yesod site, J.MonadRandom (Y.SIO (Y.YesodExampleData site addl)))
                   => JWK
                   -> Text
                   -> Y.RequestBuilder site ()
                   -> Y.YesodExample site addl ()
requestWithSubject jwk subject builder = do
  result <- runExceptT $ do
    let header = newJWSHeader ((), HS256)
        claims = claimSubject subject
    encodeCompact <$> J.signClaims jwk header claims
  case result of
    Left e -> assertFailure $ show (e :: J.Error)
    Right compact -> Y.request $ do
      Y.addRequestHeader $ bearerTokenAuthHeader $ toStrict compact
      builder

requestWithSubjectRSA :: (Yesod site, J.MonadRandom (Y.SIO (Y.YesodExampleData site addl)))
                      => JWK
                      -> Text
                      -> Y.RequestBuilder site ()
                      -> Y.YesodExample site addl ()
requestWithSubjectRSA k subject builder = do
  result <- runExceptT $ do
    let header = newJWSHeader ((), RS256)
        claims = claimSubject subject
    encodeCompact <$> J.signClaims k header claims
  case result of
    Left e -> assertFailure $ show (e :: J.Error)
    Right compact -> Y.request $ do
      Y.addRequestHeader $ bearerTokenAuthHeader $ toStrict compact
      builder

bearerTokenAuthHeader :: ByteString -> Header
bearerTokenAuthHeader jwt = (hAuthorization, "Bearer " <> jwt)

claimSubject :: Text -> J.ClaimsSet
claimSubject t = J.emptyClaimsSet & J.claimSub .~ (t ^? J.stringOrUri)

assertFailure :: String -> Y.YesodExample site ctx b
assertFailure msg = Y.assertEq msg True False >> error "assertFailure skipped, somehow"
