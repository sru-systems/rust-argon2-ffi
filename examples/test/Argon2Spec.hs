{-# LANGUAGE OverloadedStrings #-}

module Argon2Spec
  ( main
  , spec
  ) where


import Argon2
import Data.ByteString (ByteString)
import Data.Text (Text)
import Test.Hspec

import qualified Data.ByteString as BS


main :: IO ()
main = hspec spec


spec :: Spec
spec = do
  describe "encodedLen" $
    it "returns correct length" $ do
      len <- encodedLen Argon2i 4096 3 1 8 32
      len `shouldBe` 85

  describe "encodedLenSimple" $
    it "returns correct length" $ do
      len <- encodedLenSimple 8
      len `shouldBe` 85

  describe "hashEncoded" $ do
    context "with correct parameters" $
      it "returns correct encoded string" $ do
        res <- hashEncoded Argon2i Version13 4096 3 1 1 "password" "somesalt" "" "" 32
        res `shouldBe` Right encoded
    context "with too short hash" $
      it "returns SaltTooShort" $ do
        res <- hashEncoded Argon2i Version13 4096 3 1 1 "password" "salt" "" "" 32
        res `shouldBe` Left SaltTooShort

  describe "hashEncodedSimple" $ do
    context "with correct parameters" $
      it "returns correct encoded string" $ do
        res <- hashEncodedSimple "password" "somesalt"
        res `shouldBe` Right encoded
    context "with too short hash" $
      it "returns SaltTooShort" $ do
        res <- hashEncodedSimple "password" "salt"
        res `shouldBe` Left SaltTooShort

  describe "hashRaw" $ do
    context "with correct parameters" $
      it "returns correct hash" $ do
        res <- hashRaw Argon2i Version13 4096 3 1 1 "password" "somesalt" "" "" 32
        res `shouldBe` Right hash
    context "with too short hash" $
      it "returns SaltTooShort" $ do
        res <- hashRaw Argon2i Version13 4096 3 1 1 "password" "salt" "" "" 32
        res `shouldBe` Left SaltTooShort

  describe "hashRawSimple" $ do
    context "with correct parameters" $
      it "returns correct hash" $ do
        res <- hashRawSimple "password" "somesalt" 32
        res `shouldBe` Right hash
    context "with too short hash" $
      it "returns SaltTooShort" $ do
        res <- hashRawSimple "password" "salt" 32
        res `shouldBe` Left SaltTooShort

  describe "verifyEncoded" $ do
    context "with correct password" $
      it "returns True" $ do
        res <- verifyEncoded encoded "password"
        res `shouldBe` Right True
    context "with incorrect password" $
      it "returns False" $ do
        res <- verifyEncoded encoded "wrong"
        res `shouldBe` Right False
    context "with too short hash" $
      it "returns SaltTooShort" $ do
        res <- verifyEncoded "$argon2i$v=19$m=4096,t=3,p=1$dGVz$3xtUlWp/" "password"
        res `shouldBe` Left SaltTooShort

  describe "verifyRaw" $ do
    context "with correct password" $
      it "returns True" $ do
        res <- verifyRaw Argon2i Version13 4096 3 1 1 "password" "somesalt" "" "" hash
        res `shouldBe` Right True
    context "with incorrect password" $
      it "returns False" $ do
        res <- verifyRaw Argon2i Version13 4096 3 1 1 "wrong" "somesalt" "" "" hash
        res `shouldBe` Right False
    context "with too short hash" $
      it "returns SaltTooShort" $ do
        res <- verifyRaw Argon2i Version13 4096 3 1 1 "password" "salt" "" "" hash
        res `shouldBe` Left SaltTooShort

  describe "verifyRawSimple" $ do
    context "with correct password" $
      it "returns True" $ do
        res <- verifyRawSimple "password" "somesalt" hash
        res `shouldBe` Right True
    context "with incorrect password" $
      it "returns False" $ do
        res <- verifyRawSimple "wrong" "somesalt" hash
        res `shouldBe` Right False
    context "with too short hash" $
      it "returns SaltTooShort" $ do
        res <- verifyRawSimple "password" "salt" hash
        res `shouldBe` Left SaltTooShort


encoded :: Text
encoded = "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$iWh06vD8Fy27wf9npn6FXWiCX4K6pW6Ue1Bnzz07Z8A"


hash :: ByteString
hash =
  BS.pack
    [ 137
    , 104
    , 116
    , 234
    , 240
    , 252
    , 23
    , 45
    , 187
    , 193
    , 255
    , 103
    , 166
    , 126
    , 133
    , 93
    , 104
    , 130
    , 95
    , 130
    , 186
    , 165
    , 110
    , 148
    , 123
    , 80
    , 103
    , 207
    , 61
    , 59
    , 103
    , 192
    ]

