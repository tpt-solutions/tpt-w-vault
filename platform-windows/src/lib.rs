// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! tpt-vault Windows platform layer: Windows Hello consent, DPAPI protection, and Credential
//! Manager storage for the platform unlock key.
//!
//! The orchestration lives in `tpt_vault_core::PlatformUnlock`. This crate only supplies the
//! three Windows implementations. Everything here is compiled only on Windows.

#![cfg(windows)]

mod credman;
mod dpapi;
mod hello;
mod memory;

pub use credman::CredentialManager;
pub use dpapi::Dpapi;
pub use hello::WindowsHello;
pub use memory::{lock_pages, unlock_pages};

use tpt_vault_core::PlatformUnlock;

/// Platform unlock wired to Windows: Hello consent, DPAPI protection, Credential Manager.
pub type WindowsUnlock = PlatformUnlock<WindowsHello, CredentialManager, Dpapi>;

/// Builds the Windows platform unlock. Pass the app window handle to anchor the Hello prompt,
/// or `None` for an unanchored prompt.
pub fn windows_unlock(window: Option<isize>) -> WindowsUnlock {
    let gate = match window {
        Some(hwnd) => WindowsHello::for_window(hwnd),
        None => WindowsHello::default(),
    };
    PlatformUnlock::new(gate, CredentialManager, Dpapi)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_vault_core::{ConsentGate, PlatformKey, SecretStore};

    /// DPAPI round trip, bound to a context. Runs on any Windows machine, with no UI.
    #[test]
    fn dpapi_round_trips_and_binds_context() {
        use tpt_vault_core::Protector;
        let blob = Dpapi.protect(b"secret-bytes", b"vault-a").unwrap();
        assert_ne!(blob, b"secret-bytes");
        assert_eq!(Dpapi.unprotect(&blob, b"vault-a").unwrap(), b"secret-bytes");
        assert!(Dpapi.unprotect(&blob, b"vault-b").is_err());
    }

    /// Credential Manager round trip under a unique name, removed afterwards.
    #[test]
    fn credential_manager_round_trip() {
        let name = format!("tpt-vault-test/{}", std::process::id());
        let store = CredentialManager;
        store.put(&name, b"blob-1").unwrap();
        assert_eq!(store.get(&name).unwrap().as_deref(), Some(&b"blob-1"[..]));
        store.put(&name, b"blob-2").unwrap();
        assert_eq!(store.get(&name).unwrap().as_deref(), Some(&b"blob-2"[..]));
        store.delete(&name).unwrap();
        assert_eq!(store.get(&name).unwrap(), None);
        // Deleting again is not an error.
        store.delete(&name).unwrap();
    }

    /// Full platform key path using the real Windows pieces, without a consent prompt:
    /// protect a key, store it, read it back and unprotect it.
    #[test]
    fn platform_key_survives_dpapi_and_credential_manager() {
        use tpt_vault_core::Protector;
        let name = format!("tpt-vault-test-key/{}", std::process::id());
        let key = PlatformKey::from_bytes([0x42; 32]);
        let blob = Dpapi.protect(key.as_bytes(), b"ctx").unwrap();
        CredentialManager.put(&name, &blob).unwrap();
        let stored = CredentialManager.get(&name).unwrap().unwrap();
        let back = PlatformKey::from_slice(&Dpapi.unprotect(&stored, b"ctx").unwrap()).unwrap();
        assert_eq!(back.as_bytes(), key.as_bytes());
        CredentialManager.delete(&name).unwrap();
    }

    /// Only checks that the availability query runs. Whether Hello is set up depends on the
    /// machine, so this does not assert a value.
    #[test]
    fn hello_availability_query_runs() {
        let available = WindowsHello::default().is_available();
        eprintln!("Windows Hello available on this machine: {available}");
    }
}
