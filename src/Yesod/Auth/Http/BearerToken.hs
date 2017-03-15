{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Yesod.Auth.Http.BearerToken
       ( defaultMaybeBearerTokenAuthId
       , maybeBearerTokenAuthId
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
newtype CachedBearerTokenAuthId a = CachedBearerTokenAuthId { unCached :: Maybe a }
                                  deriving Typeable


-- | Retrieve the 'AuthId' using Authorization header.
--
-- If valid credentials are found and authorized the auth id is
-- cached.
defaultMaybeBearerTokenAuthId :: (Monad m, MonadBaseControl IO m, MonadIO m, MonadThrow m, MonadTime m)
                              => (ByteString -> HandlerT site m (Maybe Text))
                              -> HandlerT site m (Maybe Text)
defaultMaybeBearerTokenAuthId auth =
  cachedAuth $ waiRequest >>= maybeBearerTokenAuthId auth


-- | Cached Authentication credentials
cachedAuth :: (MonadIO m, MonadThrow m, MonadBaseControl IO m)
           => HandlerT site m (Maybe Text) -> HandlerT site m (Maybe Text)
cachedAuth = fmap unCached . cached . fmap CachedBearerTokenAuthId


-- | Use the bearer token in the HTTP _Authorization_ header to
-- retrieve the AuthId of request
maybeBearerTokenAuthId :: (Monad m, MonadTime m)
                       => (ByteString -> HandlerT site m (Maybe Text))
                       -> Request
                       -> HandlerT site m (Maybe Text)
maybeBearerTokenAuthId f req =
  case authorization of
   Just (strategy, token)
     | BS.map toLower strategy == "bearer" ->
         f $ BS.dropWhile isSpace token
     | otherwise -> return Nothing
   _ -> return Nothing
  where
    authorization = BS.break isSpace
                <$> lookup "Authorization" (requestHeaders req)
