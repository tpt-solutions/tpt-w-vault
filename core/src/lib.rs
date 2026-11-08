// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! tpt-vault core: vault format, crypto engine, key management.
//!
//! Layout of a vault on disk, and the rules behind it, are documented in [`file`] (content)
//! and [`names`] (filenames). Keys live in `keys`. The storage interface that every backend
//! implements is [`backend::VaultBackend`]; the local-directory implementation is [`FsVault`].
//!
//! # Example
//!
//! ```no_run
//! use tpt_vault_core::{FsVault, KdfParams, VaultBackend, VaultFile};
//!
//! let (vault, recovery_code) =
//!     FsVault::create("my-vault", b"correct horse", KdfParams::RECOMMENDED)?;
//! // Show `recovery_code` to the user once, and keep it somewhere safe.
//! println!("Recovery code: {recovery_code}");
//! vault.create_dir("notes")?;
//! let mut f = vault.create_file("notes/todo.md")?;
//! f.write_at(0, b"# Todo\n")?;
//! # Ok::<(), tpt_vault_core::VaultError>(())
//! ```

pub mod backend;
mod block;
pub mod config;
pub mod error;
mod file;
mod fsvault;
mod keys;
pub mod mount;
mod names;
mod platform;
mod recovery;

pub use backend::{EntryInfo, EntryKind, VaultBackend, VaultFile, copy_from_file, copy_into_file};
pub use config::{CONFIG_FILE_NAME, FORMAT_VERSION, KdfParams};
pub use error::{Result, VaultError};
pub use file::FileHandle;
pub use fsvault::FsVault;
pub use mount::{ROOT_INO, VaultTree};
pub use platform::{
    ConsentGate, PLATFORM_KEY_LEN, PlatformKey, PlatformUnlock, Protector, SecretStore,
};
pub use recovery::RecoveryCode;

/// Crate version, exposed so frontends and platform crates can report it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
