{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Yesod.Auth.Http.BearerToken
       ( defaultBearerTokenAuthId
       , bearerTokenAuthId
       ) where

import           Control.Monad.Catch (MonadThrow)
import           Control.Monad.IO.Class (MonadIO)
import           Control.Monad.Time (MonadTime)
import           Control.Monad.Trans.Control (MonadBaseControl)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Text (Text)
import           Data.Typeable
import           Data.Word8 (isSpace, toLower)
import           Network.Wai (Request, requestHeaders)
import           Yesod.Core.Handler (cached, waiRequest)
import           Yesod.Core.Types (HandlerT)


-- | Cachable basic authentication credentials
newtype CachedBearerTokenAuthId a
  = CachedBearerTokenAuthId
  { unCached :: Either Text a
  } deriving Typeable


-- | Retrieve the 'AuthId' using Authorization header.
--
-- If valid credentials are found and authorized the auth id is
-- cached.
defaultBearerTokenAuthId :: (Monad m, MonadBaseControl IO m, MonadIO m, MonadThrow m, MonadTime m)
                         => (ByteString -> HandlerT site m (Either Text Text))
                         -> HandlerT site m (Either Text Text)
defaultBearerTokenAuthId auth =
  cachedAuth $ waiRequest >>= bearerTokenAuthId auth


-- | Cached Authentication credentials
cachedAuth :: (MonadIO m, MonadThrow m, MonadBaseControl IO m)
           => HandlerT site m (Either Text Text) -> HandlerT site m (Either Text Text)
cachedAuth = fmap unCached . cached . fmap CachedBearerTokenAuthId


-- | Use the bearer token in the HTTP _Authorization_ header to
-- retrieve the AuthId of request
bearerTokenAuthId :: (Monad m, MonadTime m)
                  => (ByteString -> HandlerT site m (Either Text Text))
                  -> Request
                  -> HandlerT site m (Either Text Text)
bearerTokenAuthId f req =
  case lookup "Authorization" (requestHeaders req) of
    Nothing -> return $ Left "No Authorization header"
    Just authHead -> case BS.break isSpace authHead of
      (strategy, token)
        | BS.map toLower strategy == "bearer" ->
          f $ BS.dropWhile isSpace token
        | otherwise ->
          return $ Left "Could not recover bearer token from Authorization header"
