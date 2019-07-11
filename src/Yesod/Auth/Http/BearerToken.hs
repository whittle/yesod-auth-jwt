{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Yesod.Auth.Http.BearerToken
       ( defaultBearerTokenAuthId
       , bearerTokenAuthId
       ) where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Text (Text)
import           Data.Typeable
import           Data.Word8 (isSpace, toLower)
import           Network.Wai (Request, requestHeaders)
import           Yesod.Core.Handler (cached, waiRequest)
import           Yesod.Core (MonadHandler)


-- | Cachable basic authentication credentials
newtype CachedBearerTokenAuthId a
  = CachedBearerTokenAuthId
  { unCached :: Either Text a
  } deriving Typeable


-- | Retrieve the 'AuthId' using Authorization header.
--
-- If valid credentials are found and authorized the auth id is
-- cached.
defaultBearerTokenAuthId :: MonadHandler m
                         => (ByteString -> m (Either Text Text))
                         -> m (Either Text Text)
defaultBearerTokenAuthId auth =
  cachedAuth $ waiRequest >>= bearerTokenAuthId auth


-- | Cached Authentication credentials
cachedAuth :: MonadHandler m
           => m (Either Text Text)
           -> m (Either Text Text)
cachedAuth = fmap unCached . cached . fmap CachedBearerTokenAuthId


-- | Use the bearer token in the HTTP _Authorization_ header to
-- retrieve the AuthId of request
bearerTokenAuthId :: MonadHandler m
                  => (ByteString -> m (Either Text Text))
                  -> Request
                  -> m (Either Text Text)
bearerTokenAuthId f req =
  case lookup "Authorization" (requestHeaders req) of
    Nothing -> return $ Left "No Authorization header"
    Just authHead -> case BS.break isSpace authHead of
      (strategy, token)
        | BS.map toLower strategy == "bearer" ->
          f $ BS.dropWhile isSpace token
        | otherwise ->
          return $ Left "Could not recover bearer token from Authorization header"
