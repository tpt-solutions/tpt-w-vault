// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Windows Credential Manager as a [`SecretStore`]: each entry is a generic credential whose
//! blob holds the DPAPI-protected platform key.

use std::ffi::c_void;

use tpt_vault_core::{Result, SecretStore, VaultError};
use windows::Win32::Foundation::ERROR_NOT_FOUND;
use windows::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW,
    CredWriteW,
};
use windows::core::{HRESULT, PCWSTR, PWSTR};

/// Credential Manager, scoped to the current user's generic credentials.
pub struct CredentialManager;

/// Windows caps a credential blob at 2560 bytes. The protected key is far smaller.
const MAX_BLOB: usize = 2560;

fn wide(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

fn is_not_found(e: &windows::core::Error) -> bool {
    e.code() == HRESULT::from_win32(ERROR_NOT_FOUND.0)
}

fn platform_err(context: &str, e: windows::core::Error) -> VaultError {
    VaultError::Platform(format!("{context}: {e}"))
}

impl SecretStore for CredentialManager {
    fn put(&self, name: &str, blob: &[u8]) -> Result<()> {
        if blob.len() > MAX_BLOB {
            return Err(VaultError::Platform("credential blob is too large".into()));
        }
        let mut target = wide(name);
        let cred = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target.as_mut_ptr()),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..Default::default()
        };
        // SAFETY: `cred` and the buffers it references (`target`, `blob`) are valid for the call.
        unsafe { CredWriteW(&cred, 0) }.map_err(|e| platform_err("writing credential", e))
    }

    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let target = wide(name);
        let mut out: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `target` is a valid, NUL-terminated wide string; `out` receives an allocation
        // that must be released with CredFree.
        match unsafe {
            CredReadW(
                PCWSTR(target.as_ptr()),
                CRED_TYPE_GENERIC,
                Some(0),
                &mut out,
            )
        } {
            Ok(()) => {}
            Err(e) if is_not_found(&e) => return Ok(None),
            Err(e) => return Err(platform_err("reading credential", e)),
        }
        // SAFETY: CredReadW succeeded, so `out` points to a valid credential structure.
        let blob = unsafe {
            let cred = &*out;
            let bytes = if cred.CredentialBlob.is_null() || cred.CredentialBlobSize == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize)
                    .to_vec()
            };
            CredFree(out as *const c_void);
            bytes
        };
        Ok(Some(blob))
    }

    fn delete(&self, name: &str) -> Result<()> {
        let target = wide(name);
        // SAFETY: `target` is a valid, NUL-terminated wide string.
        match unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, Some(0)) } {
            Ok(()) => Ok(()),
            Err(e) if is_not_found(&e) => Ok(()),
            Err(e) => Err(platform_err("deleting credential", e)),
        }
    }
}
