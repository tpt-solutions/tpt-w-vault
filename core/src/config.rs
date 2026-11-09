// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! `vault.conf`: scrypt parameters and the wrapped master key.
//!
//! The file is JSON so it stays inspectable. The master key is wrapped with AES-256-GCM under
//! one of three keys ("slots"):
//!
//! - **passphrase** (always present): a scrypt-derived key from the passphrase.
//! - **recovery** (once a code is issued): a key derived from the 256-bit recovery secret.
//! - **platform** (once platform unlock is enabled): a key derived from a random 32-byte
//!   platform key. The platform layer stores that key OS-protected, behind a consent gate.
//!
//! Changing the passphrase re-wraps the master key only; file contents are never touched.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{fs, io::Write, path::Path};
use zeroize::Zeroize;

use crate::error::{Result, VaultError};
use crate::keys::{MASTER_KEY_LEN, MasterKey, random_bytes};

/// Current `vault.conf` format version.
pub const FORMAT_VERSION: u32 = 1;
/// Name of the config file at the root of a vault.
pub const CONFIG_FILE_NAME: &str = "vault.conf";

const KDF_ALGORITHM: &str = "scrypt";
const CONTENT_CIPHER: &str = "AES-256-GCM";
const NAME_CIPHER: &str = "AES-256-SIV";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const VAULT_ID_LEN: usize = 16;

/// The three ways the master key can be unwrapped, each with its own key-derivation label
/// and associated data, so one wrap cannot be substituted for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    Recovery,
    Platform,
}

impl Slot {
    fn aad(self) -> &'static [u8] {
        match self {
            Slot::Recovery => b"tpt-vault:vault.conf:v1:recovery",
            Slot::Platform => b"tpt-vault:vault.conf:v1:platform",
        }
    }

    fn info(self) -> &'static [u8] {
        match self {
            Slot::Recovery => b"tpt-vault v1 recovery-code wrap",
            Slot::Platform => b"tpt-vault v1 platform-key wrap",
        }
    }
}

const PASSPHRASE_AAD: &[u8] = b"tpt-vault:vault.conf:v1:passphrase";

/// scrypt cost parameters. `log_n` is log2 of the CPU/memory cost N.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
}

impl KdfParams {
    /// Default cost for new vaults: N = 2^17, r = 8, p = 1 (about 128 MiB, well under a second).
    pub const RECOMMENDED: KdfParams = KdfParams {
        log_n: 17,
        r: 8,
        p: 1,
    };
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct KdfConfig {
    pub algorithm: String,
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    /// base64url (no padding) salt.
    pub salt: String,
}

/// A master-key wrap stored in one of the optional slots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SlotWrap {
    /// base64url (no padding) of `nonce || ciphertext || tag`.
    pub wrapped_master_key: String,
}

/// Parsed contents of `vault.conf`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct VaultConfig {
    pub format_version: u32,
    /// Random identifier used to name this vault's platform-protected entries.
    pub vault_id: String,
    pub kdf: KdfConfig,
    pub content_cipher: String,
    pub name_cipher: String,
    /// base64url (no padding) of `nonce || ciphertext || tag`.
    pub wrapped_master_key: String,
    /// Absent until a recovery code has been issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<SlotWrap>,
    /// Absent until platform unlock is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<SlotWrap>,
    /// Block writes made under the current content key are never more than this. Raised in
    /// chunks before writes pass it. Defaults to 0 for vaults written before the counter existed.
    /// No release has shipped with such vaults.
    #[serde(default)]
    pub write_ceiling: u64,
}

fn derive_passphrase_key(passphrase: &[u8], kdf: &KdfConfig) -> Result<[u8; MASTER_KEY_LEN]> {
    let salt = URL_SAFE_NO_PAD
        .decode(&kdf.salt)
        .map_err(|_| VaultError::Config("salt is not valid base64url".into()))?;
    let params = scrypt::Params::new(kdf.log_n, kdf.r, kdf.p, MASTER_KEY_LEN)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    let mut out = [0u8; MASTER_KEY_LEN];
    scrypt::scrypt(passphrase, &salt, &params, &mut out)
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    Ok(out)
}

/// Derives a slot's wrap key from a high-entropy secret (no scrypt needed).
fn derive_slot_key(secret: &[u8; 32], slot: Slot) -> [u8; MASTER_KEY_LEN] {
    let mut out = [0u8; MASTER_KEY_LEN];
    Hkdf::<Sha256>::new(None, secret)
        .expand(slot.info(), &mut out)
        .expect("HKDF expand: 32 bytes is within limits");
    out
}

/// Wraps `master` under `wrap_key`. Consumes and zeroizes the wrap key.
fn wrap_master(mut wrap_key: [u8; MASTER_KEY_LEN], aad: &[u8], master: &MasterKey) -> String {
    let cipher = Aes256Gcm::new_from_slice(&wrap_key).expect("wrap key is 32 bytes");
    wrap_key.zeroize();
    let nonce: [u8; NONCE_LEN] = random_bytes();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: master.as_bytes(),
                aad,
            },
        )
        .expect("AES-GCM encryption cannot fail for in-range input");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    URL_SAFE_NO_PAD.encode(out)
}

/// Unwraps a master key. Returns `None` if the key is wrong or the data was altered.
fn unwrap_master(
    mut wrap_key: [u8; MASTER_KEY_LEN],
    aad: &[u8],
    encoded: &str,
) -> Result<Option<MasterKey>> {
    let wrapped = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| VaultError::Config("wrapped key is not valid base64url".into()))?;
    if wrapped.len() < NONCE_LEN {
        return Err(VaultError::Config("wrapped key is truncated".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(&wrap_key).expect("wrap key is 32 bytes");
    wrap_key.zeroize();
    let (nonce, ct) = wrapped.split_at(NONCE_LEN);
    let Ok(mut plain) = cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad }) else {
        return Ok(None);
    };
    if plain.len() != MASTER_KEY_LEN {
        plain.zeroize();
        return Err(VaultError::Config(
            "wrapped key has the wrong length".into(),
        ));
    }
    let mut bytes = [0u8; MASTER_KEY_LEN];
    bytes.copy_from_slice(&plain);
    plain.zeroize();
    let master = MasterKey::from_bytes(bytes);
    bytes.zeroize();
    Ok(Some(master))
}

fn new_kdf(params: KdfParams) -> KdfConfig {
    let salt: [u8; SALT_LEN] = random_bytes();
    KdfConfig {
        algorithm: KDF_ALGORITHM.into(),
        log_n: params.log_n,
        r: params.r,
        p: params.p,
        salt: URL_SAFE_NO_PAD.encode(salt),
    }
}

impl VaultConfig {
    /// Creates a new config wrapping a freshly generated master key. Only the passphrase slot
    /// is filled.
    pub(crate) fn create(passphrase: &[u8], params: KdfParams) -> Result<(Self, MasterKey)> {
        let master = MasterKey::generate();
        let kdf = new_kdf(params);
        let wrap_key = derive_passphrase_key(passphrase, &kdf)?;
        let vault_id: [u8; VAULT_ID_LEN] = random_bytes();
        let config = VaultConfig {
            format_version: FORMAT_VERSION,
            vault_id: URL_SAFE_NO_PAD.encode(vault_id),
            kdf,
            content_cipher: CONTENT_CIPHER.into(),
            name_cipher: NAME_CIPHER.into(),
            wrapped_master_key: wrap_master(wrap_key, PASSPHRASE_AAD, &master),
            recovery: None,
            platform: None,
            write_ceiling: 0,
        };
        Ok((config, master))
    }

    /// Returns a copy protected by a new passphrase (new salt and cost), wrapping the same
    /// master key. Other slots are kept unchanged.
    pub(crate) fn with_new_passphrase(
        &self,
        master: &MasterKey,
        passphrase: &[u8],
        params: KdfParams,
    ) -> Result<Self> {
        let kdf = new_kdf(params);
        let wrap_key = derive_passphrase_key(passphrase, &kdf)?;
        Ok(VaultConfig {
            kdf,
            wrapped_master_key: wrap_master(wrap_key, PASSPHRASE_AAD, master),
            ..self.clone()
        })
    }

    /// Wraps the master key under a slot secret, replacing any previous wrap in that slot.
    pub(crate) fn set_slot(&mut self, slot: Slot, master: &MasterKey, secret: &[u8; 32]) {
        let wrap = SlotWrap {
            wrapped_master_key: wrap_master(derive_slot_key(secret, slot), slot.aad(), master),
        };
        match slot {
            Slot::Recovery => self.recovery = Some(wrap),
            Slot::Platform => self.platform = Some(wrap),
        }
    }

    /// Removes a slot's wrap. Returns whether one was present.
    pub(crate) fn clear_slot(&mut self, slot: Slot) -> bool {
        match slot {
            Slot::Recovery => self.recovery.take().is_some(),
            Slot::Platform => self.platform.take().is_some(),
        }
    }

    /// Checks version and algorithm fields. Called on every load and unlock.
    fn validate(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(self.format_version));
        }
        if self.kdf.algorithm != KDF_ALGORITHM
            || self.content_cipher != CONTENT_CIPHER
            || self.name_cipher != NAME_CIPHER
        {
            return Err(VaultError::Config("unknown algorithm in vault.conf".into()));
        }
        Ok(())
    }

    /// Recovers the master key from the passphrase.
    pub(crate) fn unlock(&self, passphrase: &[u8]) -> Result<MasterKey> {
        self.validate()?;
        let wrap_key = derive_passphrase_key(passphrase, &self.kdf)?;
        unwrap_master(wrap_key, PASSPHRASE_AAD, &self.wrapped_master_key)?
            .ok_or(VaultError::WrongPassphrase)
    }

    /// Recovers the master key from a slot secret. A missing slot reports the same error as a
    /// wrong secret, so the two cannot be told apart from outside.
    pub(crate) fn unlock_slot(&self, slot: Slot, secret: &[u8; 32]) -> Result<MasterKey> {
        self.validate()?;
        let wrap = match slot {
            Slot::Recovery => self.recovery.as_ref(),
            Slot::Platform => self.platform.as_ref(),
        }
        .ok_or(VaultError::WrongPassphrase)?;
        unwrap_master(
            derive_slot_key(secret, slot),
            slot.aad(),
            &wrap.wrapped_master_key,
        )?
        .ok_or(VaultError::WrongPassphrase)
    }

    /// Reads and validates `vault.conf` from `path`.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        let config: VaultConfig = serde_json::from_str(&text)?;
        config.validate()?;
        Ok(config)
    }

    /// Reads `vault.conf`, sets the write ceiling, and writes it back. Callers hold the session's
    /// config lock, so no other update can be lost between the read and the write.
    pub(crate) fn store_write_ceiling(path: &Path, ceiling: u64) -> Result<()> {
        let mut config = Self::load(path)?;
        config.write_ceiling = ceiling;
        config.save_atomic(path)
    }

    /// Writes the config via a temp file and rename, so a crash never leaves a half-written
    /// `vault.conf`.
    pub(crate) fn save_atomic(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("conf.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }
}
