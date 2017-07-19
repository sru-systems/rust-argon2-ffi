// Copyright (c) 2017 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Foreign Function Interface (FFI) bindings for the rust-argon2 crate.
//!
//! # Return Values
//!
//! Most functions return an `int32_t`. On successful completion, the value `0`
//! is returned; otherwise a negative value is returned. The table below shows
//! the meaning of the return values.
//!
//! | Value | Description |
//! |:------|:------------|
//! | 0     | OK          |
//! | -1    | Output pointer is NULL |
//! | -2    | Output is too short |
//! | -3    | Output is too long  |
//! | -4    | Password is too short |
//! | -5    | Password is too long  |
//! | -6    | Salt is too short |
//! | -7    | Salt is too long  |
//! | -8    | Associated data is too short |
//! | -9    | Associated data is too long  |
//! | -10   | Secret is too short |
//! | -11   | Secret is too long  |
//! | -12   | Time cost is too small |
//! | -13   | Time cost is too large |
//! | -14   | Memory cost is too small |
//! | -15   | Memory cost is too large |
//! | -16   | Too few lanes  |
//! | -17   | Too many lanes |
//! | -18   | Password pointer is NULL, but password length is not 0 |
//! | -19   | Salt pointer is NULL, but salt length is not 0 |
//! | -20   | Secret pointer is NULL, but secret length is not 0 |
//! | -21   | Associated data pointer is NULL, bit ad length is not 0 |
//! | -26   | There is no such version of Argon2 |
//! | -31   | Encoding failed |
//! | -32   | Decoding failed |
//! | -35   | The password does not match the supplied hash |
//! | -36   | Hash pointer is NULL, but hash length is not 0 |

extern crate argon2;
extern crate libc;

use argon2::{Config, Error, ThreadMode, Variant, Version};
use libc::{c_char, size_t, uint8_t, int32_t, uint32_t};
use std::{ptr, slice};
use std::ffi::CStr;
use std::io::{Cursor, Write};


/// Argon2d variant.
#[no_mangle]
pub static ARGON2D: uint32_t = Variant::Argon2d as uint32_t;

/// Argon2i variant.
#[no_mangle]
pub static ARGON2I: uint32_t = Variant::Argon2i as uint32_t;

/// Argon2id variant.
#[no_mangle]
pub static ARGON2ID: uint32_t = Variant::Argon2id as uint32_t;

/// Argon version 10.
#[no_mangle]
pub static VERSION10: uint32_t = Version::Version10 as uint32_t;

/// Argon version 13.
#[no_mangle]
pub static VERSION13: uint32_t = Version::Version13 as uint32_t;


const DEF_HASH_LEN: usize = 32;
const DEF_LANES: u32 = 1;
const DEF_MEMORY: u32 = 4096;
const DEF_PARALLELISM: u32 = 1;
const DEF_THREADS: u32 = 1;
const DEF_TIME: u32 = 3;
const DEF_VARIANT: u32 = Variant::Argon2i as u32;
const DEF_VERSION: u32 = Version::Version13 as u32;


#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
enum ReturnValue {
    Ok = 0,
    OutputPtrNull = -1,
    OutputTooShort = -2,
    OutputTooLong = -3,
    PwdTooShort = -4,
    PwdTooLong = -5,
    SaltTooShort = -6,
    SaltTooLong = -7,
    AdTooShort = -8,
    AdTooLong = -9,
    SecretTooShort = -10,
    SecretTooLong = -11,
    TimeTooSmall = -12,
    TimeTooLarge = -13,
    MemoryTooLittle = -14,
    MemoryTooMuch = -15,
    LanesTooFew = -16,
    LanesTooMany = -17,
    PwdPtrMismatch = -18,
    SaltPtrMismatch = -19,
    SecretPtrMismatch = -20,
    AdPtrMismatch = -21,
    IncorrectType = -26,
    EncodingFail = -31,
    DecodingFail = -32,
    VerifyMismatch = -35,
    HashPtrMismatch = -36,
}

impl ReturnValue {
    pub fn from_error(error: Error) -> ReturnValue {
        match error {
            Error::OutputTooShort => ReturnValue::OutputTooShort,
            Error::OutputTooLong => ReturnValue::OutputTooLong,
            Error::PwdTooShort => ReturnValue::PwdTooShort,
            Error::PwdTooLong => ReturnValue::PwdTooLong,
            Error::SaltTooShort => ReturnValue::SaltTooShort,
            Error::SaltTooLong => ReturnValue::SaltTooLong,
            Error::AdTooShort => ReturnValue::AdTooShort,
            Error::AdTooLong => ReturnValue::AdTooLong,
            Error::SecretTooShort => ReturnValue::SecretTooShort,
            Error::SecretTooLong => ReturnValue::SecretTooLong,
            Error::TimeTooSmall => ReturnValue::TimeTooSmall,
            Error::TimeTooLarge => ReturnValue::TimeTooLarge,
            Error::MemoryTooLittle => ReturnValue::MemoryTooLittle,
            Error::MemoryTooMuch => ReturnValue::MemoryTooMuch,
            Error::LanesTooFew => ReturnValue::LanesTooFew,
            Error::LanesTooMany => ReturnValue::LanesTooMany,
            Error::IncorrectType => ReturnValue::IncorrectType,
            Error::IncorrectVersion => ReturnValue::IncorrectType,
            Error::DecodingFail => ReturnValue::DecodingFail,
        }
    }
}

/// Returns the length of a null terminated encoded string.
#[no_mangle]
pub extern "C" fn encoded_len(
    variant: uint32_t,
    mem_cost: uint32_t,
    time_cost: uint32_t,
    parallelism: uint32_t,
    salt_len: uint32_t,
    hash_len: uint32_t,
) -> uint32_t {
    let variant = match Variant::from_u32(variant) {
        Ok(val) => val,
        Err(_) => Variant::Argon2id,
    };
    argon2::encoded_len(variant, mem_cost, time_cost, parallelism, salt_len, hash_len) + 1
}

/// Returns the length of a null terminated encoded string using default settings.
#[no_mangle]
pub extern "C" fn encoded_len_simple(salt_len: uint32_t) -> uint32_t {
    encoded_len(DEF_VARIANT, DEF_MEMORY, DEF_TIME, DEF_PARALLELISM, salt_len, DEF_HASH_LEN as u32)
}

/// Hashes the password and writes the encoded string to `encoded`.
#[no_mangle]
pub extern "C" fn hash_encoded(
    variant: uint32_t,
    version: uint32_t,
    mem_cost: uint32_t,
    time_cost: uint32_t,
    lanes: uint32_t,
    threads: uint32_t,
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    secret: *const uint8_t,
    secret_len: size_t,
    ad: *const uint8_t,
    ad_len: size_t,
    hash_len: size_t,
    encoded: *mut c_char,
    encoded_len: size_t,
) -> int32_t {
    let pwd = match mk_slice(pwd, pwd_len, ReturnValue::PwdPtrMismatch) {
        Ok(val) => val,
        Err(err) => return err as i32,
    };

    let salt = match mk_slice(salt, salt_len, ReturnValue::SaltPtrMismatch) {
        Ok(val) => val,
        Err(err) => return err as i32,
    };

    if encoded.is_null() {
        return ReturnValue::EncodingFail as i32;
    }

    let config = match mk_config(
        variant,
        version,
        mem_cost,
        time_cost,
        lanes,
        threads,
        secret,
        secret_len,
        ad,
        ad_len,
        hash_len,
    ) {
        Ok(val) => val,
        Err(err) => return err as i32,
    };

    match argon2::hash_encoded(pwd, salt, &config) {
        Ok(string) => {
            let bytes = string.into_bytes();
            let null = [0u8];
            if bytes.len() + null.len() != encoded_len {
                return ReturnValue::EncodingFail as i32;
            }

            let out = unsafe { slice::from_raw_parts_mut(encoded as *mut u8, encoded_len) };

            let mut cursor = Cursor::new(out);
            if cursor.write(&bytes).is_err() {
                return ReturnValue::EncodingFail as i32;
            }
            if cursor.write(&null).is_err() {
                return ReturnValue::EncodingFail as i32;
            }
            ReturnValue::Ok as i32
        }
        Err(err) => ReturnValue::from_error(err) as i32,
    }
}

/// Hashes the password using Argon2d and writes the encoded string to `encoded`.
#[no_mangle]
pub extern "C" fn hash_encoded_argon2d(
    mem_cost: uint32_t,
    time_cost: uint32_t,
    parallelism: uint32_t,
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    hash_len: size_t,
    encoded: *mut c_char,
    encoded_len: size_t,
) -> int32_t {
    hash_encoded(
        Variant::Argon2d as u32,
        DEF_VERSION,
        mem_cost,
        time_cost,
        parallelism,
        parallelism,
        pwd,
        pwd_len,
        salt,
        salt_len,
        ptr::null(),
        0,
        ptr::null(),
        0,
        hash_len,
        encoded,
        encoded_len,
    )
}

/// Hashes the password using Argon2i and writes the encoded string to `encoded`.
#[no_mangle]
pub extern "C" fn hash_encoded_argon2i(
    mem_cost: uint32_t,
    time_cost: uint32_t,
    parallelism: uint32_t,
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    hash_len: size_t,
    encoded: *mut c_char,
    encoded_len: size_t,
) -> int32_t {
    hash_encoded(
        Variant::Argon2i as u32,
        DEF_VERSION,
        mem_cost,
        time_cost,
        parallelism,
        parallelism,
        pwd,
        pwd_len,
        salt,
        salt_len,
        ptr::null(),
        0,
        ptr::null(),
        0,
        hash_len,
        encoded,
        encoded_len,
    )
}

/// Hashes the password using Argon2id and writes the encoded string to `encoded`.
#[no_mangle]
pub extern "C" fn hash_encoded_argon2id(
    mem_cost: uint32_t,
    time_cost: uint32_t,
    parallelism: uint32_t,
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    hash_len: size_t,
    encoded: *mut c_char,
    encoded_len: size_t,
) -> int32_t {
    hash_encoded(
        Variant::Argon2id as u32,
        DEF_VERSION,
        mem_cost,
        time_cost,
        parallelism,
        parallelism,
        pwd,
        pwd_len,
        salt,
        salt_len,
        ptr::null(),
        0,
        ptr::null(),
        0,
        hash_len,
        encoded,
        encoded_len,
    )
}

/// Hashes the password using default settings and writes the encoded string to `encoded`.
#[no_mangle]
pub extern "C" fn hash_encoded_simple(
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    encoded: *mut c_char,
    encoded_len: size_t,
) -> int32_t {
    hash_encoded(
        DEF_VARIANT,
        DEF_VERSION,
        DEF_MEMORY,
        DEF_TIME,
        DEF_LANES,
        DEF_THREADS,
        pwd,
        pwd_len,
        salt,
        salt_len,
        ptr::null(),
        0,
        ptr::null(),
        0,
        DEF_HASH_LEN,
        encoded,
        encoded_len,
    )
}

/// Hashes the password and writes the hash bytes to `out`.
#[no_mangle]
pub extern "C" fn hash_raw(
    variant: uint32_t,
    version: uint32_t,
    mem_cost: uint32_t,
    time_cost: uint32_t,
    lanes: uint32_t,
    threads: uint32_t,
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    secret: *const uint8_t,
    secret_len: size_t,
    ad: *const uint8_t,
    ad_len: size_t,
    out: *mut uint8_t,
    out_len: size_t,
) -> int32_t {
    let pwd = match mk_slice(pwd, pwd_len, ReturnValue::PwdPtrMismatch) {
        Ok(val) => val,
        Err(err) => return err as i32,
    };

    let salt = match mk_slice(salt, salt_len, ReturnValue::SaltPtrMismatch) {
        Ok(val) => val,
        Err(err) => return err as i32,
    };

    if out.is_null() {
        return ReturnValue::OutputPtrNull as i32;
    }

    let config = match mk_config(
        variant,
        version,
        mem_cost,
        time_cost,
        lanes,
        threads,
        secret,
        secret_len,
        ad,
        ad_len,
        out_len,
    ) {
        Ok(val) => val,
        Err(err) => return err as i32,
    };

    match argon2::hash_raw(pwd, salt, &config) {
        Ok(vec) => {
            if vec.len() != out_len {
                return ReturnValue::EncodingFail as i32;
            }
            unsafe {
                ptr::copy_nonoverlapping(vec.as_ptr(), out, vec.len());
            }
            ReturnValue::Ok as i32
        }
        Err(err) => ReturnValue::from_error(err) as i32,
    }
}

/// Hashes the password using Argon2d and writes the hash bytes to `out`.
#[no_mangle]
pub extern "C" fn hash_raw_argon2d(
    mem_cost: uint32_t,
    time_cost: uint32_t,
    parallelism: uint32_t,
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    out: *mut uint8_t,
    out_len: size_t,
) -> int32_t {
    hash_raw(
        Variant::Argon2d as u32,
        DEF_VERSION,
        mem_cost,
        time_cost,
        parallelism,
        parallelism,
        pwd,
        pwd_len,
        salt,
        salt_len,
        ptr::null(),
        0,
        ptr::null(),
        0,
        out,
        out_len,
    )
}

/// Hashes the password using Argon2i and writes the hash bytes to `out`.
#[no_mangle]
pub extern "C" fn hash_raw_argon2i(
    mem_cost: uint32_t,
    time_cost: uint32_t,
    parallelism: uint32_t,
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    out: *mut uint8_t,
    out_len: size_t,
) -> int32_t {
    hash_raw(
        Variant::Argon2i as u32,
        DEF_VERSION,
        mem_cost,
        time_cost,
        parallelism,
        parallelism,
        pwd,
        pwd_len,
        salt,
        salt_len,
        ptr::null(),
        0,
        ptr::null(),
        0,
        out,
        out_len,
    )
}

/// Hashes the password using Argon2id and writes the hash bytes to `out`.
#[no_mangle]
pub extern "C" fn hash_raw_argon2id(
    mem_cost: uint32_t,
    time_cost: uint32_t,
    parallelism: uint32_t,
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    out: *mut uint8_t,
    out_len: size_t,
) -> int32_t {
    hash_raw(
        Variant::Argon2id as u32,
        DEF_VERSION,
        mem_cost,
        time_cost,
        parallelism,
        parallelism,
        pwd,
        pwd_len,
        salt,
        salt_len,
        ptr::null(),
        0,
        ptr::null(),
        0,
        out,
        out_len,
    )
}

/// Hashes the password using default settings and writes the hash bytes to `out`.
#[no_mangle]
pub extern "C" fn hash_raw_simple(
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    out: *mut uint8_t,
    out_len: size_t,
) -> int32_t {
    hash_raw(
        DEF_VARIANT,
        DEF_VERSION,
        DEF_MEMORY,
        DEF_TIME,
        DEF_LANES,
        DEF_THREADS,
        pwd,
        pwd_len,
        salt,
        salt_len,
        ptr::null(),
        0,
        ptr::null(),
        0,
        out,
        out_len,
    )
}

/// Verifies the password with the encoded string and returns `0` when correct.
#[no_mangle]
pub extern "C" fn verify_encoded(
    encoded: *const c_char,
    pwd: *const uint8_t,
    pwd_len: size_t,
) -> int32_t {
    let encoded = match mk_str(encoded, ReturnValue::DecodingFail) {
        Ok(val) => val,
        Err(err) => return err as i32,
    };

    let pwd = match mk_slice(pwd, pwd_len, ReturnValue::PwdPtrMismatch) {
        Ok(val) => val,
        Err(err) => return err as i32,
    };

    match argon2::verify_encoded(encoded, pwd) {
        Ok(true) => ReturnValue::Ok as i32,
        Ok(false) => ReturnValue::VerifyMismatch as i32,
        Err(err) => ReturnValue::from_error(err) as i32,
    }
}

/// Verifies the password and returns `0` when correct.
#[no_mangle]
pub extern "C" fn verify_raw(
    variant: uint32_t,
    version: uint32_t,
    mem_cost: uint32_t,
    time_cost: uint32_t,
    lanes: uint32_t,
    threads: uint32_t,
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    secret: *const uint8_t,
    secret_len: size_t,
    ad: *const uint8_t,
    ad_len: size_t,
    hash: *const uint8_t,
    hash_len: size_t,
) -> int32_t {
    let pwd = match mk_slice(pwd, pwd_len, ReturnValue::PwdPtrMismatch) {
        Ok(val) => val,
        Err(err) => return err as i32,
    };

    let salt = match mk_slice(salt, salt_len, ReturnValue::SaltPtrMismatch) {
        Ok(val) => val,
        Err(err) => return err as i32,
    };

    let hash = match mk_slice(hash, hash_len, ReturnValue::HashPtrMismatch) {
        Ok(val) => val,
        Err(err) => return err as i32,
    };

    let config = match mk_config(
        variant,
        version,
        mem_cost,
        time_cost,
        lanes,
        threads,
        secret,
        secret_len,
        ad,
        ad_len,
        hash_len,
    ) {
        Ok(val) => val,
        Err(err) => return err as i32,
    };
    match argon2::verify_raw(pwd, salt, hash, &config) {
        Ok(true) => ReturnValue::Ok as i32,
        Ok(false) => ReturnValue::VerifyMismatch as i32,
        Err(err) => ReturnValue::from_error(err) as i32,
    }
}

/// Verifies the password using Argon2d and returns `0` when correct.
#[no_mangle]
pub extern "C" fn verify_raw_argon2d(
    mem_cost: uint32_t,
    time_cost: uint32_t,
    parallelism: uint32_t,
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    hash: *const uint8_t,
    hash_len: size_t,
) -> int32_t {
    verify_raw(
        Variant::Argon2d as u32,
        DEF_VERSION,
        mem_cost,
        time_cost,
        parallelism,
        parallelism,
        pwd,
        pwd_len,
        salt,
        salt_len,
        ptr::null(),
        0,
        ptr::null(),
        0,
        hash,
        hash_len,
    )
}

/// Verifies the password using Argon2i and returns `0` when correct.
#[no_mangle]
pub extern "C" fn verify_raw_argon2i(
    mem_cost: uint32_t,
    time_cost: uint32_t,
    parallelism: uint32_t,
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    hash: *const uint8_t,
    hash_len: size_t,
) -> int32_t {
    verify_raw(
        Variant::Argon2i as u32,
        DEF_VERSION,
        mem_cost,
        time_cost,
        parallelism,
        parallelism,
        pwd,
        pwd_len,
        salt,
        salt_len,
        ptr::null(),
        0,
        ptr::null(),
        0,
        hash,
        hash_len,
    )
}

/// Verifies the password using Argon2id and returns `0` when correct.
#[no_mangle]
pub extern "C" fn verify_raw_argon2id(
    mem_cost: uint32_t,
    time_cost: uint32_t,
    parallelism: uint32_t,
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    hash: *const uint8_t,
    hash_len: size_t,
) -> int32_t {
    verify_raw(
        Variant::Argon2id as u32,
        DEF_VERSION,
        mem_cost,
        time_cost,
        parallelism,
        parallelism,
        pwd,
        pwd_len,
        salt,
        salt_len,
        ptr::null(),
        0,
        ptr::null(),
        0,
        hash,
        hash_len,
    )
}

/// Verifies the password using default settings and returns `0` when correct.
#[no_mangle]
pub extern "C" fn verify_raw_simple(
    pwd: *const uint8_t,
    pwd_len: size_t,
    salt: *const uint8_t,
    salt_len: size_t,
    hash: *const uint8_t,
    hash_len: size_t,
) -> int32_t {
    verify_raw(
        DEF_VARIANT,
        DEF_VERSION,
        DEF_MEMORY,
        DEF_TIME,
        DEF_LANES,
        DEF_THREADS,
        pwd,
        pwd_len,
        salt,
        salt_len,
        ptr::null(),
        0,
        ptr::null(),
        0,
        hash,
        hash_len,
    )
}

fn mk_config<'a>(
    variant: u32,
    version: u32,
    mem_cost: u32,
    time_cost: u32,
    lanes: u32,
    threads: u32,
    secret: *const uint8_t,
    secret_len: size_t,
    ad: *const uint8_t,
    ad_len: size_t,
    hash_len: size_t,
) -> Result<Config<'a>, ReturnValue> {
    let variant = match Variant::from_u32(variant) {
        Ok(val) => val,
        Err(err) => return Err(ReturnValue::from_error(err)),
    };

    let version = match Version::from_u32(version) {
        Ok(val) => val,
        Err(err) => return Err(ReturnValue::from_error(err)),
    };

    let secret = match mk_slice(secret, secret_len, ReturnValue::SecretPtrMismatch) {
        Ok(val) => val,
        Err(err) => return Err(err),
    };

    let ad = match mk_slice(ad, ad_len, ReturnValue::AdPtrMismatch) {
        Ok(val) => val,
        Err(err) => return Err(err),
    };

    Ok(Config {
        variant: variant,
        version: version,
        secret: secret,
        ad: ad,
        mem_cost: mem_cost,
        time_cost: time_cost,
        lanes: lanes,
        thread_mode: ThreadMode::from_threads(threads),
        hash_length: hash_len as u32,
    })
}

fn mk_slice<'a>(p: *const uint8_t, len: size_t, err: ReturnValue) -> Result<&'a [u8], ReturnValue> {
    if p.is_null() && len != 0 {
        return Err(err);
    } else {
        Ok(unsafe { slice::from_raw_parts(p, len) })
    }
}

fn mk_str<'a>(p: *const c_char, err: ReturnValue) -> Result<&'a str, ReturnValue> {
    if p.is_null() {
        return Err(err);
    } else {
        let c_str = unsafe { CStr::from_ptr(p) };
        match c_str.to_str() {
            Ok(str) => Ok(str),
            Err(_) => Err(err),
        }
    }
}


#[cfg(test)]
mod tests {

    use argon2::{Error, ThreadMode, Variant, Version};
    use std::ptr;
    use std::ffi::CString;
    use super::*;

    const ARGON2D_ENC: &'static [u8] =
        b"$argon2d$v=19$m=4096,t=3,p=1$c29tZXNhbHQ\
                                         $2+JCoQtY/2x5F0VB9pEVP3xBNguWP1T25Ui0PtZuk8o";

    const ARGON2I_ENC: &'static [u8] =
        b"$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ\
                                         $iWh06vD8Fy27wf9npn6FXWiCX4K6pW6Ue1Bnzz07Z8A";

    const ARGON2ID_ENC: &'static [u8] =
        b"$argon2id$v=19$m=4096,t=3,p=1$c29tZXNhbHQ\
                                          $qLml5cbqFAO6YxVHhrSBHP0UWdxrIxkNcM8aMX3blzU";

    const ARGON2D_HASH: [u8; 32] = [
        219,
        226,
        66,
        161,
        11,
        88,
        255,
        108,
        121,
        23,
        69,
        65,
        246,
        145,
        21,
        63,
        124,
        65,
        54,
        11,
        150,
        63,
        84,
        246,
        229,
        72,
        180,
        62,
        214,
        110,
        147,
        202,
    ];

    const ARGON2I_HASH: [u8; 32] = [
        137,
        104,
        116,
        234,
        240,
        252,
        23,
        45,
        187,
        193,
        255,
        103,
        166,
        126,
        133,
        93,
        104,
        130,
        95,
        130,
        186,
        165,
        110,
        148,
        123,
        80,
        103,
        207,
        61,
        59,
        103,
        192,
    ];

    const ARGON2ID_HASH: [u8; 32] = [
        168,
        185,
        165,
        229,
        198,
        234,
        20,
        3,
        186,
        99,
        21,
        71,
        134,
        180,
        129,
        28,
        253,
        20,
        89,
        220,
        107,
        35,
        25,
        13,
        112,
        207,
        26,
        49,
        125,
        219,
        151,
        53,
    ];

    const PWD: &'static [u8] = b"password";

    const PWD_INCORRECT: &'static [u8] = b"wrong";

    const SALT: &'static [u8] = b"somesalt";

    const SALT_SHORT: &'static [u8] = b"salt";

    #[test]
    fn return_value_from_error_returns_correct_value() {
        let tuples = vec![
            (Error::OutputTooShort, ReturnValue::OutputTooShort),
            (Error::OutputTooLong, ReturnValue::OutputTooLong),
            (Error::PwdTooShort, ReturnValue::PwdTooShort),
            (Error::PwdTooLong, ReturnValue::PwdTooLong),
            (Error::SaltTooShort, ReturnValue::SaltTooShort),
            (Error::SaltTooLong, ReturnValue::SaltTooLong),
            (Error::AdTooShort, ReturnValue::AdTooShort),
            (Error::AdTooLong, ReturnValue::AdTooLong),
            (Error::SecretTooShort, ReturnValue::SecretTooShort),
            (Error::SecretTooLong, ReturnValue::SecretTooLong),
            (Error::TimeTooSmall, ReturnValue::TimeTooSmall),
            (Error::TimeTooLarge, ReturnValue::TimeTooLarge),
            (Error::MemoryTooLittle, ReturnValue::MemoryTooLittle),
            (Error::MemoryTooMuch, ReturnValue::MemoryTooMuch),
            (Error::LanesTooFew, ReturnValue::LanesTooFew),
            (Error::LanesTooMany, ReturnValue::LanesTooMany),
            (Error::IncorrectType, ReturnValue::IncorrectType),
            (Error::IncorrectVersion, ReturnValue::IncorrectType),
            (Error::DecodingFail, ReturnValue::DecodingFail),
        ];
        for tuple in tuples {
            assert_eq!(ReturnValue::from_error(tuple.0), tuple.1);
        }
    }

    #[test]
    fn encoded_len_returns_correct_length() {
        let expected = 85;
        let actual = encoded_len(1, 4096, 3, 1, 8, 32);
        assert_eq!(actual, expected);
    }

    #[test]
    fn encoded_len_simple_returns_correct_length() {
        let expected = 85;
        let actual = encoded_len_simple(8);
        assert_eq!(actual, expected);
    }

    #[test]
    fn hash_encoded_with_correct_params_returns_ok() {
        let encoded = CString::new(vec![1u8; 84]).unwrap().into_raw();
        let result = hash_encoded(
            1,
            0x13,
            4096,
            3,
            1,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            32,
            encoded,
            85,
        );
        assert_eq!(result, 0);

        let expected = CString::new(ARGON2I_ENC).unwrap();
        let actual = unsafe { CString::from_raw(encoded) };
        assert_eq!(actual, expected);
    }

    #[test]
    fn hash_encoded_with_too_short_salt_returns_error() {
        let encoded = CString::new(vec![1u8; 84]).unwrap().into_raw();
        let result = hash_encoded(
            1,
            0x13,
            4096,
            3,
            1,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT_SHORT.as_ptr(),
            SALT_SHORT.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            32,
            encoded,
            85,
        );
        assert_eq!(result, -6);
    }

    #[test]
    fn hash_encoded_argon2d_with_correct_params_returns_ok() {
        let encoded = CString::new(vec![1u8; 84]).unwrap().into_raw();
        let result = hash_encoded_argon2d(
            4096,
            3,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            32,
            encoded,
            85,
        );
        assert_eq!(result, 0);

        let expected = CString::new(ARGON2D_ENC).unwrap();
        let actual = unsafe { CString::from_raw(encoded) };
        assert_eq!(actual, expected);
    }

    #[test]
    fn hash_encoded_argon2i_with_correct_params_returns_ok() {
        let encoded = CString::new(vec![1u8; 84]).unwrap().into_raw();
        let result = hash_encoded_argon2i(
            4096,
            3,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            32,
            encoded,
            85,
        );
        assert_eq!(result, 0);

        let expected = CString::new(ARGON2I_ENC).unwrap();
        let actual = unsafe { CString::from_raw(encoded) };
        assert_eq!(actual, expected);
    }

    #[test]
    fn hash_encoded_argon2id_with_correct_params_returns_ok() {
        let encoded = CString::new(vec![1u8; 85]).unwrap().into_raw();
        let result = hash_encoded_argon2id(
            4096,
            3,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            32,
            encoded,
            86,
        );
        assert_eq!(result, 0);

        let expected = CString::new(ARGON2ID_ENC).unwrap();
        let actual = unsafe { CString::from_raw(encoded) };
        assert_eq!(actual, expected);
    }

    #[test]
    fn hash_encoded_simple_with_correct_params_returns_ok() {
        let encoded = CString::new(vec![1u8; 84]).unwrap().into_raw();
        let result =
            hash_encoded_simple(PWD.as_ptr(), PWD.len(), SALT.as_ptr(), SALT.len(), encoded, 85);
        assert_eq!(result, 0);

        let expected = CString::new(ARGON2I_ENC).unwrap();
        let actual = unsafe { CString::from_raw(encoded) };
        assert_eq!(actual, expected);
    }

    #[test]
    fn hash_raw_with_correct_params_returns_ok() {
        let mut out = [0u8; 32];
        let result = hash_raw(
            1,
            0x13,
            4096,
            3,
            1,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len(),
        );
        assert_eq!(result, 0);
        assert_eq!(out, ARGON2I_HASH);
    }

    #[test]
    fn hash_raw_with_too_short_salt_returns_error() {
        let mut out = [0u8; 32];
        let result = hash_raw(
            1,
            0x13,
            4096,
            3,
            1,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT_SHORT.as_ptr(),
            SALT_SHORT.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len(),
        );
        assert_eq!(result, -6);
    }

    #[test]
    fn hash_raw_argon2d_with_correct_params_returns_ok() {
        let mut out = [0u8; 32];
        let result = hash_raw_argon2d(
            4096,
            3,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            out.as_mut_ptr(),
            out.len(),
        );
        assert_eq!(result, 0);
        assert_eq!(out, ARGON2D_HASH);
    }

    #[test]
    fn hash_raw_argon2i_with_correct_params_returns_ok() {
        let mut out = [0u8; 32];
        let result = hash_raw_argon2i(
            4096,
            3,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            out.as_mut_ptr(),
            out.len(),
        );
        assert_eq!(result, 0);
        assert_eq!(out, ARGON2I_HASH);
    }

    #[test]
    fn hash_raw_argon2id_with_correct_params_returns_ok() {
        let mut out = [0u8; 32];
        let result = hash_raw_argon2id(
            4096,
            3,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            out.as_mut_ptr(),
            out.len(),
        );
        assert_eq!(result, 0);
        assert_eq!(out, ARGON2ID_HASH);
    }

    #[test]
    fn hash_raw_simple_with_correct_params_returns_ok() {
        let mut out = [0u8; 32];
        let result = hash_raw_simple(
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            out.as_mut_ptr(),
            out.len(),
        );
        assert_eq!(result, 0);
        assert_eq!(out, ARGON2I_HASH);
    }

    #[test]
    fn verify_encoded_with_correct_password_returns_ok() {
        let encoded = CString::new(ARGON2I_ENC).unwrap();
        let result = verify_encoded(encoded.as_ptr(), PWD.as_ptr(), PWD.len());
        assert_eq!(result, 0);
    }

    #[test]
    fn verify_encoded_with_incorrect_password_returns_error() {
        let encoded = CString::new(ARGON2I_ENC).unwrap();
        let result = verify_encoded(encoded.as_ptr(), PWD_INCORRECT.as_ptr(), PWD_INCORRECT.len());
        assert_eq!(result, -35);
    }

    #[test]
    fn verify_raw_with_correct_password_returns_ok() {
        let result = verify_raw(
            1,
            0x13,
            4096,
            3,
            1,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            ARGON2I_HASH.as_ptr(),
            ARGON2I_HASH.len(),
        );
        assert_eq!(result, 0);
    }

    #[test]
    fn verify_raw_with_incorrect_password_returns_error() {
        let result = verify_raw(
            1,
            0x13,
            4096,
            3,
            1,
            1,
            PWD_INCORRECT.as_ptr(),
            PWD_INCORRECT.len(),
            SALT.as_ptr(),
            SALT.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            ARGON2I_HASH.as_ptr(),
            ARGON2I_HASH.len(),
        );
        assert_eq!(result, -35);
    }

    #[test]
    fn verify_raw_with_too_sort_salt_returns_error() {
        let result = verify_raw(
            1,
            0x13,
            4096,
            3,
            1,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT_SHORT.as_ptr(),
            SALT_SHORT.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            ARGON2I_HASH.as_ptr(),
            ARGON2I_HASH.len(),
        );
        assert_eq!(result, -6);
    }

    #[test]
    fn verify_raw_argon2d_with_correct_password_returns_ok() {
        let result = verify_raw_argon2d(
            4096,
            3,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            ARGON2D_HASH.as_ptr(),
            ARGON2D_HASH.len(),
        );
        assert_eq!(result, 0);
    }

    #[test]
    fn verify_raw_argon2i_with_correct_password_returns_ok() {
        let result = verify_raw_argon2i(
            4096,
            3,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            ARGON2I_HASH.as_ptr(),
            ARGON2I_HASH.len(),
        );
        assert_eq!(result, 0);
    }

    #[test]
    fn verify_raw_argon2id_with_correct_password_returns_ok() {
        let result = verify_raw_argon2id(
            4096,
            3,
            1,
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            ARGON2ID_HASH.as_ptr(),
            ARGON2ID_HASH.len(),
        );
        assert_eq!(result, 0);
    }

    #[test]
    fn verify_raw_simple_with_correct_password_returns_ok() {
        let result = verify_raw_simple(
            PWD.as_ptr(),
            PWD.len(),
            SALT.as_ptr(),
            SALT.len(),
            ARGON2I_HASH.as_ptr(),
            ARGON2I_HASH.len(),
        );
        assert_eq!(result, 0);
    }

    #[test]
    fn mk_config_with_correct_data_returns_correct_config() {
        let variant = 1;
        let version = 0x13;
        let mem_cost = 1024;
        let time_cost = 2;
        let lanes = 4;
        let threads = 4;
        let secret = b"secret";
        let ad = b"ad";
        let hash_len = 32;
        let result = mk_config(
            variant,
            version,
            mem_cost,
            time_cost,
            lanes,
            threads,
            secret.as_ptr(),
            secret.len(),
            ad.as_ptr(),
            ad.len(),
            hash_len,
        );
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.variant, Variant::Argon2i);
        assert_eq!(config.version, Version::Version13);
        assert_eq!(config.mem_cost, mem_cost);
        assert_eq!(config.time_cost, time_cost);
        assert_eq!(config.lanes, lanes);
        assert_eq!(config.thread_mode, ThreadMode::Parallel);
        assert_eq!(config.secret, secret);
        assert_eq!(config.ad, ad);
        assert_eq!(config.hash_length, hash_len as u32);
    }

    #[test]
    fn mk_config_with_incorrect_variant_returns_error() {
        let variant = 3;
        let secret = b"secret";
        let ad = b"ad";
        let result = mk_config(
            variant,
            0x13,
            1024,
            2,
            4,
            4,
            secret.as_ptr(),
            secret.len(),
            ad.as_ptr(),
            ad.len(),
            32,
        );
        assert_eq!(result, Err(ReturnValue::IncorrectType));
    }

    #[test]
    fn mk_config_with_incorrect_version_returns_error() {
        let version = 0;
        let secret = b"secret";
        let ad = b"ad";
        let result = mk_config(
            1,
            version,
            1024,
            2,
            4,
            4,
            secret.as_ptr(),
            secret.len(),
            ad.as_ptr(),
            ad.len(),
            32,
        );
        assert_eq!(result, Err(ReturnValue::IncorrectType));
    }

    #[test]
    fn mk_config_with_incorrect_secret_returns_error() {
        let ad = b"ad";
        let result = mk_config(1, 0x13, 1024, 2, 4, 4, ptr::null(), 1, ad.as_ptr(), ad.len(), 32);
        assert_eq!(result, Err(ReturnValue::SecretPtrMismatch));
    }

    #[test]
    fn mk_config_with_incorrect_ad_returns_error() {
        let secret = b"secret";
        let result =
            mk_config(1, 0x13, 1024, 2, 4, 4, secret.as_ptr(), secret.len(), ptr::null(), 1, 32);
        assert_eq!(result, Err(ReturnValue::AdPtrMismatch));
    }

    #[test]
    fn mk_slice_with_null_pointer_returns_empty_slice() {
        let expected: Result<&[u8], ReturnValue> = Ok(&[]);
        let actual = mk_slice(ptr::null(), 0, ReturnValue::Ok);
        assert_eq!(actual, expected);
    }

    #[test]
    fn mk_slice_with_correct_pointer_returns_slice() {
        let slice = b"test";
        let expected: Result<&[u8], ReturnValue> = Ok(slice);
        let actual = mk_slice(slice.as_ptr(), slice.len(), ReturnValue::Ok);
        assert_eq!(actual, expected);
    }

    #[test]
    fn mk_slice_with_incorrect_pointer_returns_error() {
        let expected = Err(ReturnValue::PwdPtrMismatch);
        let actual = mk_slice(ptr::null(), 1, ReturnValue::PwdPtrMismatch);
        assert_eq!(actual, expected);
    }

    #[test]
    fn mk_str_with_null_pointer_returns_error() {
        let expected = Err(ReturnValue::DecodingFail);
        let actual = mk_str(ptr::null(), ReturnValue::DecodingFail);
        assert_eq!(actual, expected);
    }

    #[test]
    fn mk_str_with_correct_pointer_returns_str() {
        let str = "String";
        let c_str = CString::new(str).unwrap();
        let expected = Ok(str);
        let actual = mk_str(c_str.as_ptr(), ReturnValue::Ok);
        assert_eq!(actual, expected);
    }
}
