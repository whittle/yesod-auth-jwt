{-# LANGUAGE OverloadedStrings #-}

module Yesod.Test.Auth.JWTHelper
       ( requestWithSubject
       ) where

import           Control.Monad.IO.Class (MonadIO(..))
import           Crypto.JOSE.Compact (toCompact)
import           Crypto.JOSE.JWK (JWK)
import           Crypto.JOSE.JWS (Alg(HS256), JWSHeader, newJWSHeader)
import qualified Crypto.JWT as J
import           Data.ByteString (ByteString)
import           Data.ByteString.Lazy (toStrict, intercalate)
import           Data.Monoid ((<>))
import           Data.Text (Text)
import           Network.HTTP.Types.Header
import           Yesod.Core (Yesod)
import qualified Yesod.Test as Y

requestWithSubject :: Yesod site => JWK -> Text -> Y.RequestBuilder site () -> Y.YesodExample site ()
requestWithSubject jwk subject builder = do
  jwt <- liftIO . J.createJWSJWT jwk jwsHeader $ newClaimsSet subject
  jwt' <- fromRight "Can’t create JWT" jwt
  compacts <- fromRight "Can’t serialize JWT to compact" $ toCompact jwt'
  Y.request $ do
    builder
    Y.addRequestHeader . bearerTokenAuthHeader . toStrict $ intercalate "." compacts

jwsHeader :: JWSHeader
jwsHeader = newJWSHeader HS256

bearerTokenAuthHeader :: ByteString -> Header
bearerTokenAuthHeader jwt = (hAuthorization, "Bearer " <> jwt)

newClaimsSet :: Text -> J.ClaimsSet
newClaimsSet subject = J.emptyClaimsSet { J._claimSub = Just $ J.fromString subject }

fromRight :: String -> Either a b -> Y.YesodExample site b
fromRight msg = either (const $ assertFailure msg) pure

assertFailure :: String -> Y.YesodExample site b
assertFailure msg = Y.assertEqual msg True False >> error "assertFailure skipped, somehow"
