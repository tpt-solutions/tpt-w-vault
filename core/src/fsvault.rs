// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! [`FsVault`]: a vault stored as an ordinary directory tree on the local filesystem.
//!
//! The root directory holds `vault.conf` plus one encrypted directory or file per plaintext
//! entry. Each path segment is encrypted separately, so the tree shape is visible but the
//! names are not. Because names are encrypted per segment (not per path), renaming or moving
//! a directory never requires re-encrypting anything below it.
//!
//! An open `FsVault` is an unlocked session. It holds the master key and derived subkeys, both
//! zeroized on drop. [`FsVault::lock`] ends the session by dropping it.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use zeroize::Zeroize;

use crate::backend::{EntryInfo, EntryKind, VaultBackend, map_io, split_path};
use crate::config::{CONFIG_FILE_NAME, KdfParams, VaultConfig};
use crate::error::{Result, VaultError};
use crate::file::{FileHandle, plaintext_len_for_disk};
use crate::keys::{DerivedKeys, MasterKey};
use crate::names::{decrypt_segment, encrypt_segment};
use crate::recovery::{self, RecoveryCode};

/// An unlocked vault backed by a directory on disk.
pub struct FsVault {
    root: PathBuf,
    master: MasterKey,
    keys: Arc<DerivedKeys>,
}

impl FsVault {
    /// Creates a new vault in `root` (created if missing), protected by `passphrase`.
    ///
    /// Returns the unlocked vault and a recovery code. The code is shown once and never stored
    /// in plaintext. Fails with `AlreadyExists` if a vault is already present there.
    pub fn create(
        root: impl AsRef<Path>,
        passphrase: &[u8],
        params: KdfParams,
    ) -> Result<(Self, RecoveryCode)> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let conf = root.join(CONFIG_FILE_NAME);
        if conf.exists() {
            return Err(VaultError::AlreadyExists(CONFIG_FILE_NAME.into()));
        }
        let (mut config, master) = VaultConfig::create(passphrase, params)?;
        let (mut secret, code) = recovery::generate();
        config.set_recovery(&master, &secret);
        secret.zeroize();
        config.save_atomic(&conf)?;
        Ok((Self::unlocked(root, master), code))
    }

    /// Unlocks an existing vault in `root` with its passphrase.
    ///
    /// Returns [`VaultError::WrongPassphrase`] if the passphrase is incorrect.
    pub fn open(root: impl AsRef<Path>, passphrase: &[u8]) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let config = VaultConfig::load(&root.join(CONFIG_FILE_NAME))?;
        let master = config.unlock(passphrase)?;
        Ok(Self::unlocked(root, master))
    }

    /// Unlocks an existing vault in `root` with a recovery code.
    ///
    /// Typos are caught before any decryption: a malformed code gives
    /// [`VaultError::InvalidRecoveryCode`]. A well-formed code that does not match gives
    /// [`VaultError::WrongPassphrase`].
    pub fn open_with_recovery(root: impl AsRef<Path>, code: &str) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let mut secret = recovery::parse(code)?;
        let config = VaultConfig::load(&root.join(CONFIG_FILE_NAME))?;
        let master = config.unlock_with_recovery(&secret);
        secret.zeroize();
        Ok(Self::unlocked(root, master?))
    }

    /// Changes the passphrase. The master key and all file contents are unchanged; only the
    /// passphrase wrap in `vault.conf` is rewritten. The old passphrase is required.
    pub fn change_passphrase(
        &self,
        old_passphrase: &[u8],
        new_passphrase: &[u8],
        params: KdfParams,
    ) -> Result<()> {
        let path = self.config_path();
        let config = VaultConfig::load(&path)?;
        // Unlocking proves the caller knows the old passphrase. The rewrap uses this session's
        // master key, so the vault stays consistent with the open session.
        config.unlock(old_passphrase)?;
        let updated = config.with_new_passphrase(&self.master, new_passphrase, params)?;
        updated.save_atomic(&path)
    }

    /// Replaces the recovery code. The previous code stops working immediately. The passphrase
    /// is required, so only someone who can unlock the vault can issue a new code.
    pub fn rotate_recovery_code(&self, passphrase: &[u8]) -> Result<RecoveryCode> {
        let path = self.config_path();
        let mut config = VaultConfig::load(&path)?;
        let master = config.unlock(passphrase)?;
        let (mut secret, code) = recovery::generate();
        config.set_recovery(&master, &secret);
        secret.zeroize();
        config.save_atomic(&path)?;
        Ok(code)
    }

    /// Locks the vault. Dropping the session zeroizes the master key and derived keys.
    pub fn lock(self) {}

    /// Directory on disk that holds this vault.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn unlocked(root: PathBuf, master: MasterKey) -> Self {
        let keys = Arc::new(master.derive());
        FsVault { root, master, keys }
    }

    fn config_path(&self) -> PathBuf {
        self.root.join(CONFIG_FILE_NAME)
    }

    /// Maps a plaintext path to its encrypted location on disk.
    fn disk_path(&self, plain: &str) -> Result<PathBuf> {
        let segments = split_path(plain)?;
        if segments.len() == 1 && segments[0] == CONFIG_FILE_NAME {
            return Err(VaultError::InvalidPath {
                path: plain.to_owned(),
                reason: "reserved name",
            });
        }
        let mut path = self.root.clone();
        for seg in segments {
            path.push(encrypt_segment(&self.keys.name, seg)?);
        }
        Ok(path)
    }

    /// Like `disk_path`, but refuses the root (for operations that need a real entry).
    fn disk_entry_path(&self, plain: &str) -> Result<PathBuf> {
        if split_path(plain)?.is_empty() {
            return Err(VaultError::InvalidPath {
                path: plain.to_owned(),
                reason: "the root directory cannot be used here",
            });
        }
        self.disk_path(plain)
    }

    fn info_for(&self, plain_name: String, disk: &Path, plain_path: &str) -> Result<EntryInfo> {
        let meta = fs::metadata(disk).map_err(|e| map_io(plain_path, e))?;
        if meta.is_dir() {
            Ok(EntryInfo {
                name: plain_name,
                kind: EntryKind::Directory,
                size: 0,
            })
        } else {
            // Plaintext size comes from the on-disk length alone; no need to open the file.
            let size = plaintext_len_for_disk(meta.len()).ok_or_else(|| VaultError::Corrupt {
                path: plain_path.to_owned(),
                detail: "file length is not a valid layout".into(),
            })?;
            Ok(EntryInfo {
                name: plain_name,
                kind: EntryKind::File,
                size,
            })
        }
    }
}

impl VaultBackend for FsVault {
    type File = FileHandle;

    fn create_dir(&self, path: &str) -> Result<()> {
        let disk = self.disk_entry_path(path)?;
        fs::create_dir(&disk).map_err(|e| map_io(path, e))
    }

    fn list_dir(&self, path: &str) -> Result<Vec<EntryInfo>> {
        let at_root = split_path(path)?.is_empty();
        let disk = self.disk_path(path)?;
        if !fs::metadata(&disk).map_err(|e| map_io(path, e))?.is_dir() {
            return Err(VaultError::NotADirectory(path.to_owned()));
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(&disk)? {
            let entry = entry?;
            let disk_name = entry.file_name();
            let disk_name = disk_name.to_str().ok_or_else(|| VaultError::Corrupt {
                path: path.to_owned(),
                detail: "encrypted name is not valid UTF-8".into(),
            })?;
            if at_root && disk_name == CONFIG_FILE_NAME {
                continue;
            }
            let plain_name = decrypt_segment(&self.keys.name, disk_name)?;
            let child_path = if path.is_empty() {
                plain_name.clone()
            } else {
                format!("{path}/{plain_name}")
            };
            out.push(self.info_for(plain_name, &entry.path(), &child_path)?);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn create_file(&self, path: &str) -> Result<FileHandle> {
        let disk = self.disk_entry_path(path)?;
        FileHandle::create(&disk, path, Arc::clone(&self.keys))
    }

    fn open_file(&self, path: &str) -> Result<FileHandle> {
        let disk = self.disk_entry_path(path)?;
        if fs::metadata(&disk).map_err(|e| map_io(path, e))?.is_dir() {
            return Err(VaultError::NotAFile(path.to_owned()));
        }
        FileHandle::open(&disk, path, Arc::clone(&self.keys))
    }

    fn remove(&self, path: &str) -> Result<()> {
        let disk = self.disk_entry_path(path)?;
        let meta = fs::metadata(&disk).map_err(|e| map_io(path, e))?;
        if meta.is_dir() {
            fs::remove_dir(&disk).map_err(|e| map_io(path, e))
        } else {
            fs::remove_file(&disk).map_err(|e| map_io(path, e))
        }
    }

    fn rename(&self, from: &str, to: &str) -> Result<()> {
        let from_disk = self.disk_entry_path(from)?;
        let to_disk = self.disk_entry_path(to)?;
        fs::metadata(&from_disk).map_err(|e| map_io(from, e))?;
        // std::fs::rename silently replaces files on some platforms. Refuse instead.
        if to_disk.exists() {
            return Err(VaultError::AlreadyExists(to.to_owned()));
        }
        fs::rename(&from_disk, &to_disk).map_err(|e| map_io(to, e))
    }

    fn stat(&self, path: &str) -> Result<EntryInfo> {
        let segments = split_path(path)?;
        let name = segments.last().map(|s| (*s).to_owned()).unwrap_or_default();
        if segments.is_empty() {
            return Ok(EntryInfo {
                name,
                kind: EntryKind::Directory,
                size: 0,
            });
        }
        let disk = self.disk_entry_path(path)?;
        self.info_for(name, &disk, path)
    }
}
