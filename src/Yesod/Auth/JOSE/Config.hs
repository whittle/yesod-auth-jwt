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
    aud <- o .: "audience"
    iss <- o .: "issuer"
    return $ defaultJWTValidationSettings (== aud)
           & jwtValidationSettingsIssuerPredicate .~ (== iss)
