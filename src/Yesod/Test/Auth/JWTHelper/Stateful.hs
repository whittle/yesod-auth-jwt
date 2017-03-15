{-# LANGUAGE OverloadedStrings #-}

module Yesod.Test.Auth.JWTHelper.Stateful
       ( requestWithSubject
       ) where

import           Control.Monad.Trans.Except (runExceptT)
import           Crypto.JOSE.Compact (encodeCompact)
import qualified Crypto.JOSE.Error as J
import           Crypto.JOSE.JWK (JWK)
import           Crypto.JOSE.JWS (Alg(HS256), newJWSHeader, Protection(..))
import qualified Crypto.JWT as J
import           Data.ByteString (ByteString)
import           Data.ByteString.Lazy (toStrict)
import           Data.Monoid ((<>))
import           Data.Text (Text)
import           Network.HTTP.Types.Header
import           Yesod.Core (Yesod)
import qualified Yesod.Test.Stateful as Y

requestWithSubject :: Yesod site => JWK -> Text -> Y.RequestBuilder site () -> Y.YesodExample site ctx ()
requestWithSubject jwk subject builder = do
  result <- runExceptT $ do
    let header = newJWSHeader (Protected, HS256)
    jwt <- J.createJWSJWT jwk header $ newClaimsSet subject
    encodeCompact jwt
  case result of
    Left e -> assertFailure $ show (e :: J.Error)
    Right compact -> Y.request $ do
      Y.addRequestHeader $ bearerTokenAuthHeader $ toStrict compact
      builder

bearerTokenAuthHeader :: ByteString -> Header
bearerTokenAuthHeader jwt = (hAuthorization, "Bearer " <> jwt)

newClaimsSet :: Text -> J.ClaimsSet
newClaimsSet subject = J.emptyClaimsSet { J._claimSub = Just $ J.fromString subject }

assertFailure :: String -> Y.YesodExample site ctx b
assertFailure msg = Y.assertEq msg True False >> error "assertFailure skipped, somehow"
