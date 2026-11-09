// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Master key handling and subkey derivation.
//!
//! The master key is the only long-lived secret. Two purpose-separated subkeys are derived
//! from it with HKDF-SHA256: one for file-content AEAD and one for filename AES-SIV.
//!
//! Key bytes are zeroized when their owners are dropped. Each key sits in its own page of memory,
//! which the platform layer can pin in RAM with a [`PageLocker`], so it stays out of swap where
//! the OS allows it. Core itself has no unsafe code, so the OS calls live in the platform crates.

use std::{ops::Deref, sync::OnceLock};

use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use zeroize::Zeroize;

/// Length of the master key in bytes (AES-256).
pub const MASTER_KEY_LEN: usize = 32;

const PAGE_LEN: usize = 4096;
const INFO_CONTENT: &[u8] = b"tpt-vault v1 content AES-256-GCM";
const INFO_NAME: &[u8] = b"tpt-vault v1 names AES-256-SIV";

/// Fills a fresh array with bytes from the operating system CSPRNG.
pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

/// Pins and unpins memory. The platform layer supplies these, since they need OS calls.
#[derive(Debug, Clone, Copy)]
pub struct PageLocker {
    /// Pins `region` in RAM. Returns true if it is now pinned.
    pub lock: fn(&[u8]) -> bool,
    /// Releases a region pinned by `lock`.
    pub unlock: fn(&[u8]),
}

static PAGE_LOCKER: OnceLock<PageLocker> = OnceLock::new();

/// Installs the page locker for this process. Only the first call has an effect. Without one,
/// key memory is not pinned, and [`crate::FsVault::keys_locked`] reports false.
pub fn install_page_locker(locker: PageLocker) {
    let _ = PAGE_LOCKER.set(locker);
}

/// One whole, page-aligned page, so pinning it never touches memory that holds other data.
#[repr(C, align(4096))]
struct Page([u8; PAGE_LEN]);

/// Secret bytes in a page of their own. Zeroized on drop, and pinned when a locker is installed.
pub(crate) struct LockedBytes<const N: usize> {
    page: Box<Page>,
    locked: bool,
}

impl<const N: usize> LockedBytes<N> {
    pub(crate) fn new(bytes: [u8; N]) -> Self {
        const { assert!(N <= PAGE_LEN) };
        let mut page = Box::new(Page([0; PAGE_LEN]));
        page.0[..N].copy_from_slice(&bytes);
        let locked = PAGE_LOCKER.get().is_some_and(|l| (l.lock)(&page.0));
        LockedBytes { page, locked }
    }

    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }

    /// Zeroizes the bytes now, without waiting for drop.
    pub(crate) fn wipe(&mut self) {
        self.page.0.zeroize();
    }
}

impl<const N: usize> Deref for LockedBytes<N> {
    type Target = [u8; N];

    fn deref(&self) -> &[u8; N] {
        self.page.0[..N].try_into().expect("slice has length N")
    }
}

impl<const N: usize> Drop for LockedBytes<N> {
    fn drop(&mut self) {
        self.wipe();
        if self.locked {
            if let Some(locker) = PAGE_LOCKER.get() {
                (locker.unlock)(&self.page.0);
            }
        }
    }
}

/// The vault master key. Zeroized on drop; deliberately not `Clone` or `Debug`.
pub(crate) struct MasterKey(LockedBytes<MASTER_KEY_LEN>);

impl MasterKey {
    pub(crate) fn generate() -> Self {
        Self::from_bytes(random_bytes())
    }

    pub(crate) fn from_bytes(mut bytes: [u8; MASTER_KEY_LEN]) -> Self {
        let key = MasterKey(LockedBytes::new(bytes));
        bytes.zeroize();
        key
    }

    pub(crate) fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.0
    }

    pub(crate) fn is_locked(&self) -> bool {
        self.0.is_locked()
    }

    /// Derives the content and name subkeys.
    pub(crate) fn derive(&self) -> DerivedKeys {
        let hk = Hkdf::<Sha256>::new(None, &self.0[..]);
        let mut content = [0u8; 32];
        let mut name = [0u8; 64];
        // Expansion only fails for outputs longer than 255 * 32 bytes; these are fixed sizes.
        hk.expand(INFO_CONTENT, &mut content)
            .expect("HKDF expand: 32 bytes is within limits");
        hk.expand(INFO_NAME, &mut name)
            .expect("HKDF expand: 64 bytes is within limits");
        let keys = DerivedKeys {
            content: LockedBytes::new(content),
            name: LockedBytes::new(name),
        };
        content.zeroize();
        name.zeroize();
        keys
    }
}

/// Subkeys used for file contents and names. Each is zeroized on drop.
pub(crate) struct DerivedKeys {
    /// AES-256-GCM key for content blocks.
    pub(crate) content: LockedBytes<32>,
    /// AES-256-SIV key (two 256-bit halves) for filename segments.
    pub(crate) name: LockedBytes<64>,
}

impl DerivedKeys {
    pub(crate) fn is_locked(&self) -> bool {
        self.content.is_locked() && self.name.is_locked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_wipe_clears_stored_bytes() {
        // Drop calls the same `wipe` on the same page, so this checks the wipe itself.
        let mut key = MasterKey::from_bytes([0x5A; MASTER_KEY_LEN]);
        key.0.wipe();
        assert!(key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn derived_keys_are_distinct_and_deterministic() {
        let key = MasterKey::from_bytes([1; MASTER_KEY_LEN]);
        let a = key.derive();
        let b = key.derive();
        assert_eq!(a.content[..], b.content[..]);
        assert_eq!(a.name[..], b.name[..]);
        assert_ne!(a.content[..], a.name[..32]);
    }

    #[test]
    fn keys_are_unpinned_without_a_locker() {
        // Tests do not install a locker, so nothing is pinned.
        let key = MasterKey::from_bytes([2; MASTER_KEY_LEN]);
        assert!(!key.is_locked());
        assert!(!key.derive().is_locked());
    }
}
