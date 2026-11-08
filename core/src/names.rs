// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Filename encryption with AES-256-SIV.
//!
//! SIV is deterministic: the same name always encrypts to the same string, so directory
//! listings stay stable without storing a per-directory IV. The cost is that equal names in
//! different directories produce equal ciphertext segments. This is the trade-off recorded in
//! the roadmap (no per-directory IV file).

use aes_siv::{KeyInit, siv::Aes256Siv};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::error::{Result, VaultError};

/// Longest encrypted filename a filesystem will reliably accept.
pub const MAX_ENCRYPTED_NAME_LEN: usize = 255;

/// Encrypts one path segment into a base64url string safe for any filesystem.
pub(crate) fn encrypt_segment(key: &[u8; 64], segment: &str) -> Result<String> {
    let mut siv = Aes256Siv::new_from_slice(key).expect("SIV key is 64 bytes");
    let ct = siv
        .encrypt(std::iter::empty::<&[u8]>(), segment.as_bytes())
        .expect("SIV encryption cannot fail for in-range input");
    let encoded = URL_SAFE_NO_PAD.encode(ct);
    if encoded.len() > MAX_ENCRYPTED_NAME_LEN {
        return Err(VaultError::NameTooLong(segment.to_owned()));
    }
    Ok(encoded)
}

/// Reverses [`encrypt_segment`]. Fails if the name is malformed or was not produced under this key.
pub(crate) fn decrypt_segment(key: &[u8; 64], encoded: &str) -> Result<String> {
    let corrupt = |detail: &str| VaultError::Corrupt {
        path: encoded.to_owned(),
        detail: detail.to_owned(),
    };
    let ct = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| corrupt("encrypted name is not valid base64url"))?;
    let mut siv = Aes256Siv::new_from_slice(key).expect("SIV key is 64 bytes");
    let plain = siv
        .decrypt(std::iter::empty::<&[u8]>(), &ct)
        .map_err(|_| corrupt("encrypted name failed authentication"))?;
    String::from_utf8(plain).map_err(|_| corrupt("decrypted name is not UTF-8"))
}
