{-# LANGUAGE OverloadedStrings #-}

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
import           Data.Text (pack, Text)
import           Yesod.Core.Types (HandlerT)


extractValidatedSubject :: (Monad m, MonadTime m)
                        => JWK
                        -> JWTValidationSettings
                        -> ByteString
                        -> HandlerT site m (Either Text Text)
extractValidatedSubject jwk config compactToken = do
  result <- runExceptT $ do
    jwt <- decodeCompact $ fromStrict compactToken
    validateJWSJWT config jwk jwt
    return $ jwtClaimsSet jwt
  return $ case result of
    Left e -> Left $ pack $ show (e :: JWTError)
    Right claims -> case claims^.claimSub of
      Nothing -> Left "Claims set did not contain a subject claim"
      Just sub -> case getString sub of
        Nothing -> Left "Subject claim was a URI"
        Just t -> Right t
