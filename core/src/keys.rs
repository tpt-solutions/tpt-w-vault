// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Master key handling and subkey derivation.
//!
//! The master key is the only long-lived secret. Two purpose-separated subkeys are derived
//! from it with HKDF-SHA256: one for file-content AEAD and one for filename AES-SIV.
//! Key bytes are zeroized when their owners are dropped.

use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use zeroize::Zeroize;

/// Length of the master key in bytes (AES-256).
pub const MASTER_KEY_LEN: usize = 32;

const INFO_CONTENT: &[u8] = b"tpt-vault v1 content AES-256-GCM";
const INFO_NAME: &[u8] = b"tpt-vault v1 names AES-256-SIV";

/// Fills a fresh array with bytes from the operating system CSPRNG.
pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

/// The vault master key. Zeroized on drop; deliberately not `Clone` or `Debug`.
pub(crate) struct MasterKey([u8; MASTER_KEY_LEN]);

impl MasterKey {
    pub(crate) fn generate() -> Self {
        Self(random_bytes())
    }

    pub(crate) fn from_bytes(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.0
    }

    /// Derives the content and name subkeys.
    pub(crate) fn derive(&self) -> DerivedKeys {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut content = [0u8; 32];
        let mut name = [0u8; 64];
        // Expansion only fails for outputs longer than 255 * 32 bytes; these are fixed sizes.
        hk.expand(INFO_CONTENT, &mut content)
            .expect("HKDF expand: 32 bytes is within limits");
        hk.expand(INFO_NAME, &mut name)
            .expect("HKDF expand: 64 bytes is within limits");
        DerivedKeys { content, name }
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Subkeys used for file contents and names. Zeroized on drop.
pub(crate) struct DerivedKeys {
    /// AES-256-GCM key for content blocks.
    pub(crate) content: [u8; 32],
    /// AES-256-SIV key (two 256-bit halves) for filename segments.
    pub(crate) name: [u8; 64],
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.content.zeroize();
        self.name.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_wipe_clears_stored_bytes() {
        // Drop calls the same `zeroize` on the same field, so this checks the wipe itself.
        let mut key = MasterKey::from_bytes([0x5A; MASTER_KEY_LEN]);
        key.0.zeroize();
        assert!(key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn derived_keys_are_distinct_and_deterministic() {
        let key = MasterKey::from_bytes([1; MASTER_KEY_LEN]);
        let a = key.derive();
        let b = key.derive();
        assert_eq!(a.content, b.content);
        assert_eq!(a.name, b.name);
        assert_ne!(a.content[..], a.name[..32]);
    }
}
