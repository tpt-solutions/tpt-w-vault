// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Platform unlock: the OS-specific parts sit behind three traits, and this module supplies the
//! orchestration that is the same on every platform.
//!
//! The core never sees Windows Hello or the keyring directly. It issues a random 32-byte
//! [`PlatformKey`]. The platform crate stores that key protected by the OS, and releases it
//! only after a consent check. The key is one of the three ways to unwrap the master key, so
//! losing platform state does not lose the vault: the passphrase and recovery code still work.
//!
//! - [`ConsentGate`]: asks the user (for example, Windows Hello) and reports availability.
//! - [`SecretStore`]: persists the protected blob (Credential Manager, Secret Service).
//! - [`Protector`]: wraps the key for storage. It binds the blob to the vault id, so a blob
//!   copied from one vault does not open another.

use zeroize::Zeroize;

use crate::error::{Result, VaultError};

/// Length of the random key held by the platform layer.
pub const PLATFORM_KEY_LEN: usize = 32;

/// The platform-held unlock secret. Zeroized on drop; not `Clone` or `Debug`.
pub struct PlatformKey([u8; PLATFORM_KEY_LEN]);

impl PlatformKey {
    /// Wraps raw bytes, e.g. after the platform layer has unprotected a stored blob.
    pub fn from_bytes(bytes: [u8; PLATFORM_KEY_LEN]) -> Self {
        PlatformKey(bytes)
    }

    /// Builds a key from a slice, rejecting any length other than 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; PLATFORM_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| VaultError::Platform("stored platform key has the wrong length".into()))?;
        Ok(PlatformKey(arr))
    }

    /// The raw key bytes. The platform layer uses these to protect the key for storage.
    pub fn as_bytes(&self) -> &[u8; PLATFORM_KEY_LEN] {
        &self.0
    }
}

impl Drop for PlatformKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Decides whether the user is present and consents to an unlock.
pub trait ConsentGate {
    /// Whether this device can perform a consent check at all (for example, Windows Hello is
    /// set up). Passphrase-only unlock is the fallback when this is `false`.
    fn is_available(&self) -> bool;

    /// Shows the consent prompt. `Ok(true)` means the user approved.
    fn verify(&self, prompt: &str) -> Result<bool>;
}

/// Stores opaque blobs under a name, persisted by the OS.
pub trait SecretStore {
    fn put(&self, name: &str, blob: &[u8]) -> Result<()>;
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>>;
    fn delete(&self, name: &str) -> Result<()>;
}

/// Protects a secret for storage, bound to a context (here, the vault id).
pub trait Protector {
    fn protect(&self, plain: &[u8], context: &[u8]) -> Result<Vec<u8>>;
    fn unprotect(&self, blob: &[u8], context: &[u8]) -> Result<Vec<u8>>;
}

/// Prompt shown by the consent gate for a vault unlock.
pub const UNLOCK_PROMPT: &str = "Unlock your tpt-vault";

/// Orchestrates platform unlock from the three platform pieces.
pub struct PlatformUnlock<G, S, P> {
    gate: G,
    store: S,
    protector: P,
}

impl<G: ConsentGate, S: SecretStore, P: Protector> PlatformUnlock<G, S, P> {
    pub fn new(gate: G, store: S, protector: P) -> Self {
        PlatformUnlock {
            gate,
            store,
            protector,
        }
    }

    /// Whether the device can run a consent check. The UI uses this to offer the feature.
    pub fn is_available(&self) -> bool {
        self.gate.is_available()
    }

    fn entry_name(vault_id: &str) -> String {
        format!("tpt-vault/{vault_id}")
    }

    /// Stores `key` protected for `vault_id`, replacing any previous entry.
    pub fn enroll(&self, vault_id: &str, key: &PlatformKey) -> Result<()> {
        let blob = self
            .protector
            .protect(key.as_bytes(), vault_id.as_bytes())?;
        self.store.put(&Self::entry_name(vault_id), &blob)
    }

    /// Runs the consent check and releases the stored key for `vault_id`.
    pub fn unlock(&self, vault_id: &str) -> Result<PlatformKey> {
        if !self.gate.is_available() {
            return Err(VaultError::PlatformUnavailable);
        }
        if !self.gate.verify(UNLOCK_PROMPT)? {
            return Err(VaultError::ConsentDenied);
        }
        let blob = self
            .store
            .get(&Self::entry_name(vault_id))?
            .ok_or(VaultError::PlatformNotEnrolled)?;
        let mut plain = self.protector.unprotect(&blob, vault_id.as_bytes())?;
        let key = PlatformKey::from_slice(&plain);
        plain.zeroize();
        key
    }

    /// Removes the stored key for `vault_id`. Missing entries are not an error.
    pub fn remove(&self, vault_id: &str) -> Result<()> {
        self.store.delete(&Self::entry_name(vault_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    struct FakeGate {
        available: bool,
        approve: Cell<bool>,
    }

    impl ConsentGate for FakeGate {
        fn is_available(&self) -> bool {
            self.available
        }
        fn verify(&self, _prompt: &str) -> Result<bool> {
            Ok(self.approve.get())
        }
    }

    #[derive(Default)]
    struct MemStore(RefCell<HashMap<String, Vec<u8>>>);

    impl SecretStore for MemStore {
        fn put(&self, name: &str, blob: &[u8]) -> Result<()> {
            self.0.borrow_mut().insert(name.into(), blob.to_vec());
            Ok(())
        }
        fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.borrow().get(name).cloned())
        }
        fn delete(&self, name: &str) -> Result<()> {
            self.0.borrow_mut().remove(name);
            Ok(())
        }
    }

    /// Test-only protector: XORs with a context-derived pad. Not secure; it only checks that
    /// the context is passed through and must match on unprotect.
    struct XorProtector;

    fn pad(context: &[u8], len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| context[i % context.len()].wrapping_add(i as u8))
            .collect()
    }

    impl Protector for XorProtector {
        fn protect(&self, plain: &[u8], context: &[u8]) -> Result<Vec<u8>> {
            Ok(plain
                .iter()
                .zip(pad(context, plain.len()))
                .map(|(a, b)| a ^ b)
                .collect())
        }
        fn unprotect(&self, blob: &[u8], context: &[u8]) -> Result<Vec<u8>> {
            self.protect(blob, context)
        }
    }

    fn unit(gate: FakeGate) -> PlatformUnlock<FakeGate, MemStore, XorProtector> {
        PlatformUnlock::new(gate, MemStore::default(), XorProtector)
    }

    #[test]
    fn enroll_then_unlock_returns_the_same_key() {
        let p = unit(FakeGate {
            available: true,
            approve: Cell::new(true),
        });
        let key = PlatformKey::from_bytes([9; PLATFORM_KEY_LEN]);
        p.enroll("vault-a", &key).unwrap();
        assert_eq!(p.unlock("vault-a").unwrap().as_bytes(), key.as_bytes());
    }

    #[test]
    fn denied_consent_releases_nothing() {
        let p = unit(FakeGate {
            available: true,
            approve: Cell::new(false),
        });
        p.enroll("v", &PlatformKey::from_bytes([1; 32])).unwrap();
        assert!(matches!(p.unlock("v"), Err(VaultError::ConsentDenied)));
    }

    #[test]
    fn unavailable_device_reports_unavailable() {
        let p = unit(FakeGate {
            available: false,
            approve: Cell::new(true),
        });
        assert!(!p.is_available());
        assert!(matches!(
            p.unlock("v"),
            Err(VaultError::PlatformUnavailable)
        ));
    }

    #[test]
    fn unenrolled_vault_is_reported_as_such() {
        let p = unit(FakeGate {
            available: true,
            approve: Cell::new(true),
        });
        assert!(matches!(
            p.unlock("nothing-here"),
            Err(VaultError::PlatformNotEnrolled)
        ));
    }

    #[test]
    fn blob_is_bound_to_its_vault_id() {
        let p = unit(FakeGate {
            available: true,
            approve: Cell::new(true),
        });
        p.enroll("vault-a", &PlatformKey::from_bytes([3; 32]))
            .unwrap();
        // Move the stored blob to another vault's entry name.
        let blob = p.store.get("tpt-vault/vault-a").unwrap().unwrap();
        p.store.put("tpt-vault/vault-b", &blob).unwrap();
        let recovered = p.unlock("vault-b").unwrap();
        assert_ne!(
            recovered.as_bytes(),
            &[3u8; 32],
            "context must change the result"
        );
    }

    #[test]
    fn remove_clears_the_entry() {
        let p = unit(FakeGate {
            available: true,
            approve: Cell::new(true),
        });
        p.enroll("v", &PlatformKey::from_bytes([4; 32])).unwrap();
        p.remove("v").unwrap();
        assert!(matches!(
            p.unlock("v"),
            Err(VaultError::PlatformNotEnrolled)
        ));
    }
}
