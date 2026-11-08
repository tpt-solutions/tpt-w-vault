// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Error types for the vault core.
//!
//! Wrong-passphrase and data-corruption failures are distinct variants so the UI can tell
//! the user "try again" apart from "this vault file is damaged".

use thiserror::Error;

/// Result alias used throughout the core crate.
pub type Result<T, E = VaultError> = std::result::Result<T, E>;

/// Everything that can go wrong while creating, opening or using a vault.
#[derive(Debug, Error)]
pub enum VaultError {
    /// The passphrase or recovery code did not unwrap the master key, or the config was
    /// altered. These are deliberately indistinguishable.
    #[error("wrong passphrase or recovery code, or the vault configuration has been damaged")]
    WrongPassphrase,

    /// A typed recovery code failed format or checksum validation (a typo, most likely).
    #[error("the recovery code is not valid; check it for typos")]
    InvalidRecoveryCode,

    /// `vault.conf` or an on-disk file declares a format version this build cannot read.
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u32),

    /// Ciphertext failed authentication after the key was already accepted. Surfaced
    /// separately from [`VaultError::WrongPassphrase`] on purpose.
    #[error("data in '{path}' is corrupt: {detail}")]
    Corrupt { path: String, detail: String },

    /// A plaintext path was rejected before touching the disk.
    #[error("invalid vault path '{path}': {reason}")]
    InvalidPath { path: String, reason: &'static str },

    /// The encrypted form of a name would not fit in a 255-byte filesystem name.
    #[error("name is too long to store in a vault: '{0}'")]
    NameTooLong(String),

    #[error("not found: '{0}'")]
    NotFound(String),

    #[error("already exists: '{0}'")]
    AlreadyExists(String),

    #[error("not a file: '{0}'")]
    NotAFile(String),

    #[error("not a directory: '{0}'")]
    NotADirectory(String),

    #[error("directory is not empty: '{0}'")]
    DirectoryNotEmpty(String),

    /// `vault.conf` is missing fields, has unknown algorithms, or is not valid JSON.
    #[error("vault configuration error: {0}")]
    Config(String),

    /// The key-derivation function rejected its parameters or failed.
    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<serde_json::Error> for VaultError {
    fn from(e: serde_json::Error) -> Self {
        VaultError::Config(e.to_string())
    }
}
