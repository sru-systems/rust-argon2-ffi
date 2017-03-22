-- |
-- Module:      Argon2
-- Copyright:   (c) 2017 Martijn Rijkeboer
-- License:     MIT
-- Maintainer:  Martijn Rijkeboer <mrr@sru-systems.com>
--
-- FFI bindings to rust-argon2-ffi library.

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}

module Argon2
  ( Variant(..)
  , Version(..)
  , ErrorCode(..)
  , Encoded
  , MemCost
  , TimeCost
  , Lanes
  , Threads
  , Parallelism
  , HashLen
  , Password
  , Salt
  , SaltLen
  , Secret
  , Ad
  , Hash
  , encodedLen
  , encodedLenSimple
  , hashEncoded
  , hashEncodedSimple
  , hashRaw
  , hashRawSimple
  , verifyEncoded
  , verifyRaw
  , verifyRawSimple
  ) where

import Data.ByteString (ByteString)
import Data.Text (Text)
import Foreign
import Foreign.C

import qualified Data.ByteString as BS
import qualified Data.Text.Encoding as T


foreign import ccall unsafe "encoded_len" c_encoded_len
  :: Word32    -- variant
  -> Word32    -- mem_cost
  -> Word32    -- time_cost
  -> Word32    -- parallelism
  -> Word32    -- salt_len
  -> Word32    -- hash_len
  -> IO Word32 -- encoded length


foreign import ccall unsafe "encoded_len_simple" c_encoded_len_simple
  :: Word32    -- salt_len
  -> IO Word32 -- encoded length


foreign import ccall unsafe "hash_encoded" c_hash_encoded
  :: Word32   -- variant
  -> Word32   -- version
  -> Word32   -- mem_cost
  -> Word32   -- time_cost
  -> Word32   -- lanes
  -> Word32   -- threads
  -> Ptr a    -- pwd
  -> CSize    -- pwd_len
  -> Ptr b    -- salt
  -> CSize    -- salt_len
  -> Ptr c    -- secret
  -> CSize    -- secret_len
  -> Ptr d    -- ad
  -> CSize    -- ad_len
  -> CSize    -- hash_len
  -> CString  -- encoded (output)
  -> CSize    -- encoded_len
  -> IO Int32 -- return value


foreign import ccall unsafe "hash_encoded_simple" c_hash_encoded_simple
  :: Ptr a    -- pwd
  -> CSize    -- pwd_len
  -> Ptr b    -- salt
  -> CSize    -- salt_len
  -> CString  -- encoded (output)
  -> CSize    -- encoded_len
  -> IO Int32 -- return value


foreign import ccall unsafe "hash_raw" c_hash_raw
  :: Word32   -- variant
  -> Word32   -- version
  -> Word32   -- mem_cost
  -> Word32   -- time_cost
  -> Word32   -- lanes
  -> Word32   -- threads
  -> Ptr a    -- pwd
  -> CSize    -- pwd_len
  -> Ptr b    -- salt
  -> CSize    -- salt_len
  -> Ptr c    -- secret
  -> CSize    -- secret_len
  -> Ptr d    -- ad
  -> CSize    -- ad_len
  -> Ptr e    -- out (output)
  -> CSize    -- out_len
  -> IO Int32 -- return value


foreign import ccall unsafe "hash_raw_simple" c_hash_raw_simple
  :: Ptr a    -- pwd
  -> CSize    -- pwd_len
  -> Ptr b    -- salt
  -> CSize    -- salt_len
  -> Ptr e    -- out (output)
  -> CSize    -- out_len
  -> IO Int32 -- return value


foreign import ccall unsafe "verify_encoded" c_verify_encoded
  :: CString  -- encoded
  -> Ptr a    -- pwd
  -> CSize    -- pwd_len
  -> IO Int32 -- return value


foreign import ccall unsafe "verify_raw" c_verify_raw
  :: Word32   -- variant
  -> Word32   -- version
  -> Word32   -- mem_cost
  -> Word32   -- time_cost
  -> Word32   -- lanes
  -> Word32   -- threads
  -> Ptr a    -- pwd
  -> CSize    -- pwd_len
  -> Ptr b    -- salt
  -> CSize    -- salt_len
  -> Ptr c    -- secret
  -> CSize    -- secret_len
  -> Ptr d    -- ad
  -> CSize    -- ad_len
  -> Ptr e    -- hash
  -> CSize    -- hash_len
  -> IO Int32 -- return value


foreign import ccall unsafe "verify_raw_simple" c_verify_raw_simple
  :: Ptr a    -- pwd
  -> CSize    -- pwd_len
  -> Ptr b    -- salt
  -> CSize    -- salt_len
  -> Ptr e    -- hash
  -> CSize    -- hash_len
  -> IO Int32 -- return value


-- | Argon2 variant.
data Variant
  = Argon2d
  | Argon2i
  | Argon2id
  deriving (Eq, Ord, Show)


-- | Argon2 version.
data Version
  = Version10
  | Version13
  deriving (Eq, Ord, Show)


-- | Error code (return value).
data ErrorCode
  = OutputPtrNull
  | OutputTooShort
  | OutputTooLong
  | PwdTooShort
  | PwdTooLong
  | SaltTooShort
  | SaltTooLong
  | AdTooShort
  | AdTooLong
  | SecretTooShort
  | SecretTooLong
  | TimeTooSmall
  | TimeTooLarge
  | MemoryTooLittle
  | MemoryTooMuch
  | LanesTooFew
  | LanesTooMany
  | PwdPtrMismatch
  | SaltPtrMismatch
  | SecretPtrMismatch
  | AdPtrMismatch
  | IncorrectType
  | EncodingFail
  | DecodingFail
  | HashPtrMismatch
  | Unknown Int32
  deriving (Eq, Ord, Show)


-- | Type alias for the encoded string.
type Encoded = Text


-- | Type alias for the memory cost.
type MemCost = Word32


-- | Type alias for the time cost.
type TimeCost = Word32


-- | Type alias for the lanes count.
type Lanes = Word32


-- | Type alias for the threads count.
type Threads = Word32


-- | Type alias for the parallelism
type Parallelism = Word32


-- | Type alias for the hash length.
type HashLen = Int


-- | Type alias for the password.
type Password = ByteString


-- | Type alias for the salt.
type Salt = ByteString


-- | Type alias for the salt length.
type SaltLen = Int


-- | Type alias for the secret.
type Secret = ByteString


-- | Type alias for the associated data.
type Ad = ByteString


-- | Type alias for the hash.
type Hash = ByteString


-- | Get the length of the encoded string.
encodedLen
  :: Variant
  -> MemCost
  -> TimeCost
  -> Parallelism
  -> SaltLen
  -> HashLen
  -> IO Word32
encodedLen var mem time parallelism saltLen hashLen =
  c_encoded_len
    (variant var)
    mem
    time
    parallelism
    (fromIntegral saltLen)
    (fromIntegral hashLen)


-- | Get the length of the encoded string.
encodedLenSimple
  :: SaltLen
  -> IO Word32
encodedLenSimple saltLen = c_encoded_len_simple (fromIntegral saltLen)


-- | Hash the password and return the encoded string.
hashEncoded
  :: Variant
  -> Version
  -> MemCost
  -> TimeCost
  -> Lanes
  -> Threads
  -> Password
  -> Salt
  -> Secret
  -> Ad
  -> HashLen
  -> IO (Either ErrorCode Text)
hashEncoded var ver mem time lanes thrs pwd salt secret ad hashLen = do
  let pwdLen = fromIntegral (BS.length pwd)
  let saltLen = fromIntegral (BS.length salt)
  let secretLen = fromIntegral (BS.length secret)
  let adLen = fromIntegral (BS.length ad)
  encLen <- encodedLen var mem time lanes (fromIntegral saltLen) hashLen
  enc <- mallocBytes (fromIntegral encLen)
  result <-
    BS.useAsCString pwd $ \cpwd ->
      BS.useAsCString salt $ \csalt ->
        BS.useAsCString secret $ \csecret ->
          BS.useAsCString ad $ \cad ->
            c_hash_encoded
              (variant var)
              (version ver)
              mem
              time
              lanes
              thrs
              cpwd
              pwdLen
              csalt
              saltLen
              csecret
              secretLen
              cad
              adLen
              (fromIntegral hashLen)
              enc
              (fromIntegral encLen)
  case result of
    0 -> Right . T.decodeUtf8 <$> BS.packCString enc
    x -> return $ Left $ toErrorCode x


-- | Hash the password and return the encoded string.
hashEncodedSimple
  :: Password
  -> Salt
  -> IO (Either ErrorCode Text)
hashEncodedSimple pwd salt = do
  let pwdLen = fromIntegral (BS.length pwd)
  let saltLen = fromIntegral (BS.length salt)
  encLen <- encodedLenSimple (fromIntegral saltLen)
  enc <- mallocBytes (fromIntegral encLen)
  result <-
    BS.useAsCString pwd $ \cpwd ->
      BS.useAsCString salt $ \csalt ->
        c_hash_encoded_simple
          cpwd
          pwdLen
          csalt
          saltLen
          enc
          (fromIntegral encLen)
  case result of
    0 -> Right . T.decodeUtf8 <$> BS.packCString enc
    x -> return $ Left $ toErrorCode x


-- | Hash the password and return the hash's bytes.
hashRaw
  :: Variant
  -> Version
  -> MemCost
  -> TimeCost
  -> Lanes
  -> Threads
  -> Password
  -> Salt
  -> Secret
  -> Ad
  -> HashLen
  -> IO (Either ErrorCode Hash)
hashRaw var ver mem time lanes thrs pwd salt secret ad hashLen = do
  let pwdLen = fromIntegral (BS.length pwd)
  let saltLen = fromIntegral (BS.length salt)
  let secretLen = fromIntegral (BS.length secret)
  let adLen = fromIntegral (BS.length ad)
  hash <- mallocBytes hashLen
  result <-
    BS.useAsCString pwd $ \cpwd ->
      BS.useAsCString salt $ \csalt ->
        BS.useAsCString secret $ \csecret ->
          BS.useAsCString ad $ \cad ->
            c_hash_raw
              (variant var)
              (version ver)
              mem
              time
              lanes
              thrs
              cpwd
              pwdLen
              csalt
              saltLen
              csecret
              secretLen
              cad
              adLen
              hash
              (fromIntegral hashLen)
  case result of
    0 -> Right <$> BS.packCStringLen (hash, hashLen)
    x -> return $ Left $ toErrorCode x


-- | Hash the password and return the hash's bytes.
hashRawSimple
  :: Password
  -> Salt
  -> HashLen
  -> IO (Either ErrorCode Hash)
hashRawSimple pwd salt hashLen = do
  let pwdLen = fromIntegral (BS.length pwd)
  let saltLen = fromIntegral (BS.length salt)
  hash <- mallocBytes hashLen
  result <-
    BS.useAsCString pwd $ \cpwd ->
      BS.useAsCString salt $ \csalt ->
        c_hash_raw_simple
          cpwd
          pwdLen
          csalt
          saltLen
          hash
          (fromIntegral hashLen)
  case result of
    0 -> Right <$> BS.packCStringLen (hash, hashLen)
    x -> return $ Left $ toErrorCode x


-- | Verify the password with the encoded string.
verifyEncoded
  :: Encoded
  -> Password
  -> IO (Either ErrorCode Bool)
verifyEncoded enc pwd = do
  let pwdLen = fromIntegral (BS.length pwd)
  result <-
    BS.useAsCString (T.encodeUtf8 enc) $ \cenc ->
      BS.useAsCString pwd $ \cpwd ->
        c_verify_encoded cenc cpwd pwdLen
  return $ toBoolResult result


-- | Verify the password with the hash.
verifyRaw
  :: Variant
  -> Version
  -> MemCost
  -> TimeCost
  -> Lanes
  -> Threads
  -> Password
  -> Salt
  -> Secret
  -> Ad
  -> Hash
  -> IO (Either ErrorCode Bool)
verifyRaw var ver mem time lanes thrs pwd salt secret ad hash = do
  let pwdLen = fromIntegral (BS.length pwd)
  let saltLen = fromIntegral (BS.length salt)
  let secretLen = fromIntegral (BS.length secret)
  let adLen = fromIntegral (BS.length ad)
  let hashLen = fromIntegral (BS.length hash)
  result <-
    BS.useAsCString pwd $ \cpwd ->
      BS.useAsCString salt $ \csalt ->
        BS.useAsCString secret $ \csecret ->
          BS.useAsCString ad $ \cad ->
            BS.useAsCString hash $ \chash ->
              c_verify_raw
                (variant var)
                (version ver)
                mem
                time
                lanes
                thrs
                cpwd
                pwdLen
                csalt
                saltLen
                csecret
                secretLen
                cad
                adLen
                chash
                hashLen
  return $ toBoolResult result


-- | Verify the password with the hash.
verifyRawSimple
  :: Password
  -> Salt
  -> Hash
  -> IO (Either ErrorCode Bool)
verifyRawSimple pwd salt hash = do
  let pwdLen = fromIntegral (BS.length pwd)
  let saltLen = fromIntegral (BS.length salt)
  let hashLen = fromIntegral (BS.length hash)
  result <-
    BS.useAsCString pwd $ \cpwd ->
      BS.useAsCString salt $ \csalt ->
        BS.useAsCString hash $ \chash ->
          c_verify_raw_simple
            cpwd
            pwdLen
            csalt
            saltLen
            chash
            hashLen
  return $ toBoolResult result


variant :: Variant -> Word32
variant Argon2d  = 0
variant Argon2i  = 1
variant Argon2id = 2


version :: Version -> Word32
version Version10 = 0x10
version Version13 = 0x13


toErrorCode :: Int32 -> ErrorCode
toErrorCode (-1) = OutputPtrNull
toErrorCode (-2) = OutputTooShort
toErrorCode (-3) = OutputTooLong
toErrorCode (-4) = PwdTooShort
toErrorCode (-5) = PwdTooLong
toErrorCode (-6) = SaltTooShort
toErrorCode (-7) = SaltTooLong
toErrorCode (-8) = AdTooShort
toErrorCode (-9) = AdTooLong
toErrorCode (-10) = SecretTooShort
toErrorCode (-11) = SecretTooLong
toErrorCode (-12) = TimeTooSmall
toErrorCode (-13) = TimeTooLarge
toErrorCode (-14) = MemoryTooLittle
toErrorCode (-15) = MemoryTooMuch
toErrorCode (-16) = LanesTooFew
toErrorCode (-17) = LanesTooMany
toErrorCode (-18) = PwdPtrMismatch
toErrorCode (-19) = SaltPtrMismatch
toErrorCode (-20) = SecretPtrMismatch
toErrorCode (-21) = AdPtrMismatch
toErrorCode (-26) = IncorrectType
toErrorCode (-31) = EncodingFail
toErrorCode (-32) = DecodingFail
toErrorCode (-36) = HashPtrMismatch
toErrorCode x = Unknown x


toBoolResult :: Int32 -> Either ErrorCode Bool
toBoolResult 0     = Right True
toBoolResult (-35) = Right False
toBoolResult x     = Left $ toErrorCode x

