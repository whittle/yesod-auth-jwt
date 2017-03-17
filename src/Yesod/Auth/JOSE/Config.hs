{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Yesod.Auth.JOSE.Config
  ( JWTValidationSettings
  ) where

import Control.Lens
import Crypto.JWT
import Data.Aeson


instance FromJSON JWTValidationSettings where
  parseJSON = withObject "JWTValidationSettings" $ \o -> do
    aud <- fromString <$> o .: "audience"
    iss <- fromString <$> o .: "issuer"
    return $ jwtValidationSettingsAudiencePredicate .~ (== aud)
           $ jwtValidationSettingsIssuerPredicate .~ (== iss)
           $ defaultJWTValidationSettings
