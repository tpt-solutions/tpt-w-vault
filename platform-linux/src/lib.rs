// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! tpt-vault Linux platform layer: fingerprint consent via fprintd, and key storage in the
//! desktop keyring via the Secret Service API.
//!
//! The orchestration lives in `tpt_vault_core::PlatformUnlock`. This crate supplies the Linux
//! implementations and the fallback decision. When no provider or reader is available, the UI
//! should offer passphrase-only unlock, which is always available.
//!
//! Status: written against the fprintd and Secret Service specifications. The D-Bus code has
//! not yet been run against a live keyring or fingerprint reader. See the Phase 4 checklist.

mod fprintd;
mod secret_service;

pub use fprintd::FprintGate;
pub use secret_service::SecretService;

use tpt_vault_core::{ConsentGate, PlatformUnlock, Protector, Result};

/// Stores platform keys as-is in the keyring. The keyring encrypts items at rest with the
/// login secret, and the vault id is the item's lookup attribute, so no extra wrapping is
/// added here.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyringProtector;

impl Protector for KeyringProtector {
    fn protect(&self, plain: &[u8], _context: &[u8]) -> Result<Vec<u8>> {
        Ok(plain.to_vec())
    }

    fn unprotect(&self, blob: &[u8], _context: &[u8]) -> Result<Vec<u8>> {
        Ok(blob.to_vec())
    }
}

/// Platform unlock wired to Linux: fprintd consent, Secret Service storage.
pub type LinuxUnlock = PlatformUnlock<FprintGate, SecretService, KeyringProtector>;

/// Whether the device can offer platform unlock at all: a Secret Service provider is running
/// and fprintd has a reader. Passphrase unlock is the fallback when this is `false`.
pub fn platform_unlock_supported() -> bool {
    SecretService::provider_present() && ConsentGate::is_available(&FprintGate)
}

/// Builds the Linux platform unlock. Fails if the session bus is unavailable.
pub fn linux_unlock() -> Result<LinuxUnlock> {
    Ok(PlatformUnlock::new(
        FprintGate,
        SecretService::connect()?,
        KeyringProtector,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without a session bus (headless CI, or Windows), platform unlock must report itself
    /// unsupported rather than fail.
    #[test]
    fn missing_bus_means_unsupported_not_error() {
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            assert!(!platform_unlock_supported());
            assert!(linux_unlock().is_err());
        }
    }

    #[test]
    fn keyring_protector_is_a_passthrough() {
        let p = KeyringProtector;
        let blob = p.protect(b"key", b"ctx").unwrap();
        assert_eq!(p.unprotect(&blob, b"ctx").unwrap(), b"key");
    }
}
