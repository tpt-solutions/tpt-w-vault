// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! DPAPI protection for the platform key. The blob can only be decrypted by the same Windows
//! user on the same machine, and the vault id is passed as entropy, so a blob copied from one
//! vault does not open another.

use std::ffi::c_void;

use tpt_vault_core::{Protector, Result, VaultError};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows::core::PCWSTR;

/// DPAPI via `CryptProtectData` / `CryptUnprotectData`, with no UI.
pub struct Dpapi;

fn blob_of(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    }
}

/// Copies a DPAPI-allocated output blob into a Vec and frees the original.
///
/// # Safety
/// `out` must be a blob that DPAPI filled in successfully and that has not been freed.
unsafe fn take_output(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    let bytes = if out.pbData.is_null() || out.cbData == 0 {
        Vec::new()
    } else {
        // SAFETY: DPAPI guarantees `pbData` points to `cbData` valid bytes.
        unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec()
    };
    if !out.pbData.is_null() {
        // SAFETY: DPAPI allocates the output with LocalAlloc, so LocalFree releases it.
        unsafe { LocalFree(Some(HLOCAL(out.pbData as *mut c_void))) };
    }
    bytes
}

impl Protector for Dpapi {
    fn protect(&self, plain: &[u8], context: &[u8]) -> Result<Vec<u8>> {
        let input = blob_of(plain);
        let entropy = blob_of(context);
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: `input`, `entropy` and `output` are valid for the duration of the call, and
        // the buffers they point to outlive it.
        unsafe {
            CryptProtectData(
                &input,
                PCWSTR::null(),
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
        .map_err(|e| VaultError::Platform(format!("DPAPI protect failed: {e}")))?;
        // SAFETY: the call succeeded, so `output` holds a DPAPI allocation.
        Ok(unsafe { take_output(output) })
    }

    fn unprotect(&self, blob: &[u8], context: &[u8]) -> Result<Vec<u8>> {
        let input = blob_of(blob);
        let entropy = blob_of(context);
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: as in `protect`.
        unsafe {
            CryptUnprotectData(
                &input,
                None,
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
        .map_err(|e| VaultError::Platform(format!("DPAPI unprotect failed: {e}")))?;
        // SAFETY: the call succeeded, so `output` holds a DPAPI allocation.
        Ok(unsafe { take_output(output) })
    }
}
