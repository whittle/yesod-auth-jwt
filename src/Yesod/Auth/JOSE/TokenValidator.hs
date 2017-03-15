module Yesod.Auth.JOSE.TokenValidator
       ( extractValidatedSubject
       ) where

import           Control.Lens
import           Control.Monad.Time (MonadTime)
import           Control.Monad.Trans.Except (runExceptT)
import           Crypto.JOSE.Compact
import           Crypto.JOSE.JWK
import           Crypto.JWT
import           Data.ByteString (ByteString)
import           Data.ByteString.Lazy (fromStrict)
import           Data.Text (Text)
import           Yesod.Core.Types (HandlerT)

extractValidatedSubject :: (Monad m, MonadTime m) => JWK -> ByteString -> HandlerT site m (Maybe Text)
extractValidatedSubject jwk compactToken = do
  result <- runExceptT $ do
    jwt <- decodeCompact $ fromStrict compactToken
    validateJWSJWT defaultJWTValidationSettings jwk jwt
    return $ jwtClaimsSet jwt
  case result of
    Left e -> return (e :: JWTError) >> return Nothing
    Right claims -> return $ claims^.claimSub >>= getString
