module Yesod.Auth.JOSE.TokenValidator
       ( defaultExtractSubject
       , defaultTokenValidator
       , defaultValidateToken
       ) where

import           Crypto.JOSE.Compact
import           Crypto.JOSE.JWK
import           Crypto.JOSE.JWS
import           Crypto.JWT
import           Data.ByteString (ByteString)
import           Data.ByteString.Lazy (fromStrict)
import           Data.Default (def)
import           Data.Text (Text)
import           Yesod.Auth.Http.BearerToken (TokenValidator(..))

defaultTokenValidator :: Applicative m => JWK -> TokenValidator m
defaultTokenValidator k = TokenValidator { validateToken = defaultValidateToken k
                                         , extractSubject = defaultExtractSubject
                                         }

defaultValidateToken :: Applicative m => JWK -> ByteString -> m Bool
defaultValidateToken jwk = pure . either (const False) vfy . decodeCompact . fromStrict
  where vfy = verifyJWS def def jwk

defaultExtractSubject :: ByteString -> Maybe Text
defaultExtractSubject = either (const Nothing) ext . decodeCompact . fromStrict
  where ext = (getString =<<) . _claimSub . jwtClaimsSet
