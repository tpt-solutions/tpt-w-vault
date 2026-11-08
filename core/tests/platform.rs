// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Platform unlock at the vault level: the platform key is one more way to unwrap the master
//! key, and it does not replace the passphrase or the recovery code.

use tpt_vault_core::{FsVault, KdfParams, PlatformKey, VaultError};

const PASS: &[u8] = b"passphrase for platform tests";
const TEST_KDF: KdfParams = KdfParams {
    log_n: 10,
    r: 8,
    p: 1,
};

fn create(dir: &tempfile::TempDir) -> tpt_vault_core::RecoveryCode {
    FsVault::create(dir.path(), PASS, TEST_KDF).unwrap().1
}

#[test]
fn platform_key_unlocks_without_the_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    create(&dir);
    let vault = FsVault::open(dir.path(), PASS).unwrap();
    let key = vault.enable_platform_unlock(PASS).unwrap();
    vault.lock();

    let reopened = FsVault::open_with_platform_key(dir.path(), &key).unwrap();
    reopened.lock();
    // The passphrase still works alongside the platform key.
    assert!(FsVault::open(dir.path(), PASS).is_ok());
}

#[test]
fn wrong_platform_key_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    create(&dir);
    let vault = FsVault::open(dir.path(), PASS).unwrap();
    let _real = vault.enable_platform_unlock(PASS).unwrap();
    let forged = PlatformKey::from_bytes([0xAB; 32]);
    assert!(matches!(
        FsVault::open_with_platform_key(dir.path(), &forged),
        Err(VaultError::WrongPassphrase)
    ));
}

#[test]
fn enabling_requires_the_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    create(&dir);
    let vault = FsVault::open(dir.path(), PASS).unwrap();
    assert!(matches!(
        vault.enable_platform_unlock(b"wrong"),
        Err(VaultError::WrongPassphrase)
    ));
}

#[test]
fn re_enabling_invalidates_the_previous_key() {
    let dir = tempfile::tempdir().unwrap();
    create(&dir);
    let vault = FsVault::open(dir.path(), PASS).unwrap();
    let old = vault.enable_platform_unlock(PASS).unwrap();
    let _new = vault.enable_platform_unlock(PASS).unwrap();
    assert!(matches!(
        FsVault::open_with_platform_key(dir.path(), &old),
        Err(VaultError::WrongPassphrase)
    ));
}

#[test]
fn disabling_stops_platform_unlock_but_keeps_the_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    create(&dir);
    let vault = FsVault::open(dir.path(), PASS).unwrap();
    let key = vault.enable_platform_unlock(PASS).unwrap();
    vault.disable_platform_unlock(PASS).unwrap();

    assert!(matches!(
        FsVault::open_with_platform_key(dir.path(), &key),
        Err(VaultError::WrongPassphrase)
    ));
    assert!(FsVault::open(dir.path(), PASS).is_ok());
}

#[test]
fn unenrolled_vault_rejects_any_platform_key() {
    let dir = tempfile::tempdir().unwrap();
    create(&dir);
    let key = PlatformKey::from_bytes([1; 32]);
    assert!(matches!(
        FsVault::open_with_platform_key(dir.path(), &key),
        Err(VaultError::WrongPassphrase)
    ));
}

#[test]
fn vault_id_is_stable_and_readable_without_the_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    create(&dir);
    let id = FsVault::read_vault_id(dir.path()).unwrap();
    assert!(!id.is_empty());
    assert_eq!(FsVault::read_vault_id(dir.path()).unwrap(), id);

    let other = tempfile::tempdir().unwrap();
    create(&other);
    assert_ne!(FsVault::read_vault_id(other.path()).unwrap(), id);
}

#[test]
fn passphrase_change_keeps_the_platform_key_valid() {
    let dir = tempfile::tempdir().unwrap();
    create(&dir);
    let vault = FsVault::open(dir.path(), PASS).unwrap();
    let key = vault.enable_platform_unlock(PASS).unwrap();
    vault
        .change_passphrase(PASS, b"new passphrase", TEST_KDF)
        .unwrap();
    assert!(FsVault::open_with_platform_key(dir.path(), &key).is_ok());
}
