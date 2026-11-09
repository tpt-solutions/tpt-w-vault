// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! [`FsVault`]: a vault stored as an ordinary directory tree on the local filesystem.
//!
//! The root directory holds `vault.conf` plus one encrypted directory or file per plaintext
//! entry. Each path segment is encrypted separately, so the tree shape is visible but the
//! names are not. Because names are encrypted per segment (not per path), renaming or moving
//! a directory never requires re-encrypting anything below it.
//!
//! **Long names.** An encrypted segment longer than 255 bytes cannot be a filename. Such
//! entries are stored as `longname.<sha256 of the encrypted name>`, and a sidecar file with the
//! same name plus `.name` holds the full encrypted name. Listing checks the sidecar against the
//! hash, so a swapped sidecar is reported as corruption.
//!
//! An open `FsVault` is an unlocked session. It holds the master key and derived subkeys, both
//! zeroized on drop. [`FsVault::lock`] ends the session by dropping it.

use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::backend::{
    EntryInfo, EntryKind, STREAM_CHUNK, VaultBackend, VaultFile, map_io, split_path,
};
use crate::config::Slot;
use crate::config::{CONFIG_FILE_NAME, KdfParams, VaultConfig};
use crate::error::{Result, VaultError};
use crate::file::{FileHandle, plaintext_len_for_disk};
use crate::journal;
use crate::keys::{DerivedKeys, MasterKey, random_bytes};
use crate::names::{decrypt_segment, encrypt_segment};
use crate::platform::PlatformKey;
use crate::recovery::{self, RecoveryCode};

/// Largest encrypted name that is stored directly as a filename.
const MAX_DISK_NAME_LEN: usize = 255;
const LONG_PREFIX: &str = "longname.";
const SIDECAR_SUFFIX: &str = ".name";

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
        config.set_slot(Slot::Recovery, &master, &secret);
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
        let master = config.unlock_slot(Slot::Recovery, &secret);
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
        config.set_slot(Slot::Recovery, &master, &secret);
        secret.zeroize();
        config.save_atomic(&path)?;
        Ok(code)
    }

    /// Re-keys the vault: every file is re-encrypted under a brand-new master key and name key.
    ///
    /// The vault is copied into a sibling directory (`<name>.rekey-tmp`), then swapped into
    /// place, and the old directory is deleted. The original stays untouched until the copy is
    /// complete, so a crash before the swap loses nothing. Peak disk use is roughly double the
    /// vault size.
    ///
    /// Consumes the session, since its keys no longer match the vault. The new session and a
    /// new recovery code are returned. Old recovery codes stop working.
    pub fn rekey(self, passphrase: &[u8], params: KdfParams) -> Result<(FsVault, RecoveryCode)> {
        let root = self.root.clone();
        let tmp = sibling(&root, "rekey-tmp")?;
        let old = sibling(&root, "rekey-old")?;
        if old.exists() {
            return Err(VaultError::AlreadyExists(
                old.to_string_lossy().into_owned(),
            ));
        }
        if tmp.exists() {
            // Left behind by an interrupted attempt. The original vault is still authoritative.
            fs::remove_dir_all(&tmp)?;
        }

        let (fresh, code) = FsVault::create(&tmp, passphrase, params)?;
        copy_tree(&self, &fresh, "")?;

        fs::rename(&root, &old)?;
        if let Err(e) = fs::rename(&tmp, &root) {
            // Put the original back so the user is not left without a vault.
            let _ = fs::rename(&old, &root);
            return Err(e.into());
        }
        fs::remove_dir_all(&old)?;

        let FsVault { master, keys, .. } = fresh;
        Ok((FsVault { root, master, keys }, code))
    }

    /// Reads a vault's id from `vault.conf` without unlocking it. The platform layer needs the
    /// id to find the key it stores for this vault.
    pub fn read_vault_id(root: impl AsRef<Path>) -> Result<String> {
        Ok(VaultConfig::load(&root.as_ref().join(CONFIG_FILE_NAME))?.vault_id)
    }

    /// Enables platform unlock. Returns the random key that the platform layer must store
    /// protected, behind a consent gate. The passphrase is required.
    ///
    /// Calling this again issues a new key and invalidates the previous one.
    pub fn enable_platform_unlock(&self, passphrase: &[u8]) -> Result<PlatformKey> {
        let path = self.config_path();
        let mut config = VaultConfig::load(&path)?;
        let master = config.unlock(passphrase)?;
        let mut secret = random_bytes::<32>();
        config.set_slot(Slot::Platform, &master, &secret);
        let key = PlatformKey::from_bytes(secret);
        secret.zeroize();
        config.save_atomic(&path)?;
        Ok(key)
    }

    /// Disables platform unlock for this vault. The passphrase is required. The caller should
    /// also remove the stored key with [`PlatformUnlock::remove`], since the stored key no
    /// longer unlocks anything.
    pub fn disable_platform_unlock(&self, passphrase: &[u8]) -> Result<()> {
        let path = self.config_path();
        let mut config = VaultConfig::load(&path)?;
        config.unlock(passphrase)?;
        if config.clear_slot(Slot::Platform) {
            config.save_atomic(&path)?;
        }
        Ok(())
    }

    /// Unlocks a vault with the platform key released by the platform layer.
    pub fn open_with_platform_key(root: impl AsRef<Path>, key: &PlatformKey) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let config = VaultConfig::load(&root.join(CONFIG_FILE_NAME))?;
        let master = config.unlock_slot(Slot::Platform, key.as_bytes())?;
        Ok(Self::unlocked(root, master))
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

    /// Encrypted on-disk name for one plaintext segment, shortened if it is too long.
    fn disk_name(&self, segment: &str) -> Result<String> {
        let enc = encrypt_segment(&self.keys.name, segment)?;
        Ok(if enc.len() <= MAX_DISK_NAME_LEN {
            enc
        } else {
            long_name_for(&enc)
        })
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
            path.push(self.disk_name(seg)?);
        }
        Ok(path)
    }

    /// Like `disk_path`, but refuses the root (for operations that need a real entry).
    /// On-disk path of a vault entry. Used by tests that inspect or damage the raw bytes.
    #[cfg(test)]
    pub(crate) fn disk_file(&self, plain: &str) -> Result<PathBuf> {
        self.disk_entry_path(plain)
    }

    fn disk_entry_path(&self, plain: &str) -> Result<PathBuf> {
        if split_path(plain)?.is_empty() {
            return Err(VaultError::InvalidPath {
                path: plain.to_owned(),
                reason: "the root directory cannot be used here",
            });
        }
        self.disk_path(plain)
    }

    /// Sidecar file for an entry stored under a long name, if it has one.
    fn sidecar_path(&self, plain: &str) -> Result<Option<PathBuf>> {
        let disk = self.disk_entry_path(plain)?;
        let name = disk
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !name.starts_with(LONG_PREFIX) {
            return Ok(None);
        }
        Ok(Some(disk.with_file_name(format!("{name}{SIDECAR_SUFFIX}"))))
    }

    /// Writes the sidecar for `plain`, if it needs one. Must run before the entry is created
    /// so a listing never sees an entry it cannot name.
    fn write_sidecar(&self, plain: &str) -> Result<()> {
        if let Some(sidecar) = self.sidecar_path(plain)? {
            let last = split_path(plain)?.last().copied().unwrap_or_default();
            let enc = encrypt_segment(&self.keys.name, last)?;
            fs::write(sidecar, enc)?;
        }
        Ok(())
    }

    /// Removes the sidecar for `plain`, ignoring a missing one.
    fn remove_sidecar(&self, plain: &str) -> Result<()> {
        if let Some(sidecar) = self.sidecar_path(plain)? {
            match fs::remove_file(sidecar) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Reads and verifies the full encrypted name stored in a long-name entry's sidecar.
    fn read_long_name(&self, dir: &Path, disk_name: &str) -> Result<String> {
        let corrupt = |detail: &str| VaultError::Corrupt {
            path: disk_name.to_owned(),
            detail: detail.to_owned(),
        };
        let sidecar = dir.join(format!("{disk_name}{SIDECAR_SUFFIX}"));
        let enc = fs::read_to_string(&sidecar).map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                corrupt("long-name sidecar is missing")
            } else {
                VaultError::Io(e)
            }
        })?;
        if long_name_for(&enc) != disk_name {
            return Err(corrupt("long-name sidecar does not match its entry"));
        }
        Ok(enc)
    }

    fn info_for(&self, plain_name: String, disk: &Path, plain_path: &str) -> Result<EntryInfo> {
        // An interrupted write changes the length, so undo it before reading the length.
        journal::recover(disk)?;
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

/// Stored name for an encrypted segment too long to be a filename.
fn long_name_for(enc: &str) -> String {
    let digest = Sha256::digest(enc.as_bytes());
    format!("{LONG_PREFIX}{}", URL_SAFE_NO_PAD.encode(digest))
}

/// `<root>.<suffix>` in the same parent directory.
fn sibling(root: &Path, suffix: &str) -> Result<PathBuf> {
    let name = root
        .file_name()
        .ok_or_else(|| VaultError::InvalidPath {
            path: root.to_string_lossy().into_owned(),
            reason: "vault root has no directory name",
        })?
        .to_string_lossy();
    Ok(root.with_file_name(format!("{name}.{suffix}")))
}

/// Copies every directory and file under `path` from `src` into `dst`, decrypting with
/// `src`'s keys and encrypting with `dst`'s.
fn copy_tree(src: &FsVault, dst: &FsVault, path: &str) -> Result<()> {
    for entry in src.list_dir(path)? {
        let child = if path.is_empty() {
            entry.name.clone()
        } else {
            format!("{path}/{}", entry.name)
        };
        match entry.kind {
            EntryKind::Directory => {
                dst.create_dir(&child)?;
                copy_tree(src, dst, &child)?;
            }
            EntryKind::File => copy_file(src, dst, &child, entry.size)?,
        }
    }
    Ok(())
}

fn copy_file(src: &FsVault, dst: &FsVault, path: &str, size: u64) -> Result<()> {
    let mut from = src.open_file(path)?;
    let mut to = dst.create_file(path)?;
    let mut buf = Zeroizing::new(vec![0u8; STREAM_CHUNK]);
    let mut offset = 0u64;
    loop {
        let n = from.read_at(offset, &mut buf)?;
        if n == 0 {
            break;
        }
        to.write_at(offset, &buf[..n])?;
        offset += n as u64;
    }
    if offset != size {
        return Err(VaultError::Corrupt {
            path: path.to_owned(),
            detail: format!("copied {offset} bytes but listing reported {size}"),
        });
    }
    Ok(())
}

impl VaultBackend for FsVault {
    type File = FileHandle;

    fn create_dir(&self, path: &str) -> Result<()> {
        let disk = self.disk_entry_path(path)?;
        self.write_sidecar(path)?;
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
            if disk_name.starts_with(LONG_PREFIX) && disk_name.ends_with(SIDECAR_SUFFIX) {
                continue;
            }
            if journal::is_journal_name(disk_name) {
                continue;
            }
            let enc = if disk_name.starts_with(LONG_PREFIX) {
                self.read_long_name(&disk, disk_name)?
            } else {
                disk_name.to_owned()
            };
            let plain_name = decrypt_segment(&self.keys.name, &enc)?;
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
        self.write_sidecar(path)?;
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
            fs::remove_dir(&disk).map_err(|e| map_io(path, e))?;
        } else {
            fs::remove_file(&disk).map_err(|e| map_io(path, e))?;
        }
        // The file is gone, so its journal has nothing left to apply to.
        journal::discard(&disk)?;
        self.remove_sidecar(path)
    }

    fn rename(&self, from: &str, to: &str) -> Result<()> {
        let from_disk = self.disk_entry_path(from)?;
        let to_disk = self.disk_entry_path(to)?;
        fs::metadata(&from_disk).map_err(|e| map_io(from, e))?;
        // Undo any interrupted write first. Otherwise its journal would stay behind under the
        // old name and never be applied.
        journal::recover(&from_disk)?;
        // std::fs::rename silently replaces files on some platforms. Refuse instead.
        if to_disk.exists() {
            return Err(VaultError::AlreadyExists(to.to_owned()));
        }
        journal::discard(&to_disk)?;
        self.write_sidecar(to)?;
        fs::rename(&from_disk, &to_disk).map_err(|e| map_io(to, e))?;
        self.remove_sidecar(from)
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
