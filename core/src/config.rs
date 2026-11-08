// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! `vault.conf`: scrypt parameters and the wrapped master key.
//!
//! The file is JSON so it stays inspectable. The master key is wrapped twice, with AES-256-GCM:
//!
//! - under a scrypt-derived key from the passphrase (always present), and
//! - under an HKDF-derived key from the recovery-code secret (present once a code is issued).
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
/// Bound to each wrap so one wrapped key cannot be substituted for the other.
const PASSPHRASE_AAD: &[u8] = b"tpt-vault:vault.conf:v1:passphrase";
const RECOVERY_AAD: &[u8] = b"tpt-vault:vault.conf:v1:recovery";
const RECOVERY_WRAP_INFO: &[u8] = b"tpt-vault v1 recovery-code wrap";

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

/// The master key wrapped under the recovery-code secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RecoveryWrap {
    /// base64url (no padding) of `nonce || ciphertext || tag`.
    pub wrapped_master_key: String,
}

/// Parsed contents of `vault.conf`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct VaultConfig {
    pub format_version: u32,
    pub kdf: KdfConfig,
    pub content_cipher: String,
    pub name_cipher: String,
    /// base64url (no padding) of `nonce || ciphertext || tag`.
    pub wrapped_master_key: String,
    /// Absent until a recovery code has been issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryWrap>,
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

fn derive_recovery_key(secret: &[u8; 32]) -> [u8; MASTER_KEY_LEN] {
    let mut out = [0u8; MASTER_KEY_LEN];
    Hkdf::<Sha256>::new(None, secret)
        .expand(RECOVERY_WRAP_INFO, &mut out)
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
    /// Creates a new config wrapping a freshly generated master key. No recovery wrap yet.
    pub(crate) fn create(passphrase: &[u8], params: KdfParams) -> Result<(Self, MasterKey)> {
        let master = MasterKey::generate();
        let kdf = new_kdf(params);
        let wrap_key = derive_passphrase_key(passphrase, &kdf)?;
        let config = VaultConfig {
            format_version: FORMAT_VERSION,
            kdf,
            content_cipher: CONTENT_CIPHER.into(),
            name_cipher: NAME_CIPHER.into(),
            wrapped_master_key: wrap_master(wrap_key, PASSPHRASE_AAD, &master),
            recovery: None,
        };
        Ok((config, master))
    }

    /// Returns a copy protected by a new passphrase (new salt and cost), wrapping the same
    /// master key. The recovery wrap, if any, is kept unchanged.
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

    /// Wraps the master key under a recovery secret, replacing any previous recovery wrap.
    pub(crate) fn set_recovery(&mut self, master: &MasterKey, secret: &[u8; 32]) {
        let wrap_key = derive_recovery_key(secret);
        self.recovery = Some(RecoveryWrap {
            wrapped_master_key: wrap_master(wrap_key, RECOVERY_AAD, master),
        });
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

    /// Recovers the master key from the recovery secret.
    pub(crate) fn unlock_with_recovery(&self, secret: &[u8; 32]) -> Result<MasterKey> {
        self.validate()?;
        let recovery = self.recovery.as_ref().ok_or(VaultError::WrongPassphrase)?;
        let wrap_key = derive_recovery_key(secret);
        unwrap_master(wrap_key, RECOVERY_AAD, &recovery.wrapped_master_key)?
            .ok_or(VaultError::WrongPassphrase)
    }

    /// Reads and validates `vault.conf` from `path`.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        let config: VaultConfig = serde_json::from_str(&text)?;
        config.validate()?;
        Ok(config)
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
