{-# LANGUAGE OverloadedStrings #-}

module Yesod.Auth.JOSE.TokenValidator
       ( extractValidatedSubject
       , extractValidatedSubject'
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
import           Yesod.Core (MonadHandler)


extractValidatedSubject :: (MonadHandler m, MonadTime m)
                        => JWK
                        -> JWTValidationSettings
                        -> ByteString
                        -> m (Either Text Text)
extractValidatedSubject k config compactToken = do
  result <- runExceptT $ do
    jwt <- decodeCompact $ fromStrict compactToken
    verifyClaims config k jwt
  return $ case result of
    Left e -> Left $ pack $ show (e :: JWTError)
    Right claims -> case claims^.claimSub of
      Nothing -> Left "Claims set did not contain a subject claim"
      Just sub -> case sub ^? string of
        Nothing -> Left "Subject claim was a URI"
        Just s -> Right s

extractValidatedSubject' :: (MonadHandler m, MonadTime m)
                         => JWKSet
                         -> JWTValidationSettings
                         -> ByteString
                         -> m (Either Text Text)
extractValidatedSubject' k config compactToken = do
  result <- runExceptT $ do
    jwt <- decodeCompact $ fromStrict compactToken
    verifyClaims config k jwt
  return $ case result of
    Left e -> Left $ pack $ show (e :: JWTError)
    Right claims -> case claims^.claimSub of
      Nothing -> Left "Claims set did not contain a subject claim"
      Just sub -> case sub ^? string of
        Nothing -> Left "Subject claim was a URI"
        Just s -> Right s
