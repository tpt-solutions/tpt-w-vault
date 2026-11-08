// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Key lifecycle: passphrase change, recovery codes, lock, and the guarantee that file
//! contents are untouched by key-management operations.

use std::fs;

use tpt_vault_core::{
    CONFIG_FILE_NAME, FsVault, KdfParams, RecoveryCode, VaultBackend, VaultError, VaultFile,
    copy_from_file,
};

const PASS: &[u8] = b"first passphrase";
const NEW_PASS: &[u8] = b"second passphrase";
const TEST_KDF: KdfParams = KdfParams {
    log_n: 10,
    r: 8,
    p: 1,
};

fn create(dir: &tempfile::TempDir) -> (FsVault, RecoveryCode) {
    FsVault::create(dir.path(), PASS, TEST_KDF).expect("create")
}

fn read_all(vault: &FsVault, path: &str) -> Vec<u8> {
    let mut f = vault.open_file(path).unwrap();
    let mut out = Vec::new();
    copy_from_file(&mut f, &mut out).unwrap();
    out
}

fn write_file(vault: &FsVault, path: &str, data: &[u8]) {
    vault.create_file(path).unwrap().write_at(0, data).unwrap();
}

/// Every encrypted file under the vault root except vault.conf, with its raw bytes.
fn encrypted_snapshot(root: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().unwrap() != CONFIG_FILE_NAME {
                out.push((p.clone(), fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn passphrase_change_takes_effect_and_old_passphrase_stops_working() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _code) = create(&dir);
    write_file(&vault, "note.md", b"keep me");

    vault.change_passphrase(PASS, NEW_PASS, TEST_KDF).unwrap();
    drop(vault);

    assert!(matches!(
        FsVault::open(dir.path(), PASS),
        Err(VaultError::WrongPassphrase)
    ));
    let vault = FsVault::open(dir.path(), NEW_PASS).unwrap();
    assert_eq!(read_all(&vault, "note.md"), b"keep me");
}

#[test]
fn passphrase_change_leaves_every_content_file_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _code) = create(&dir);
    write_file(&vault, "a.bin", &vec![0x42; 9000]);
    write_file(&vault, "b.bin", b"small");
    let before = encrypted_snapshot(dir.path());

    vault.change_passphrase(PASS, NEW_PASS, TEST_KDF).unwrap();

    assert_eq!(encrypted_snapshot(dir.path()), before);
}

#[test]
fn passphrase_change_requires_the_old_passphrase_and_changes_nothing_on_failure() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _code) = create(&dir);
    let conf_before = fs::read_to_string(dir.path().join(CONFIG_FILE_NAME)).unwrap();

    assert!(matches!(
        vault.change_passphrase(b"not the passphrase", NEW_PASS, TEST_KDF),
        Err(VaultError::WrongPassphrase)
    ));
    assert_eq!(
        fs::read_to_string(dir.path().join(CONFIG_FILE_NAME)).unwrap(),
        conf_before
    );
    assert!(FsVault::open(dir.path(), PASS).is_ok());
}

#[test]
fn recovery_code_opens_the_vault_without_the_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, code) = create(&dir);
    write_file(&vault, "secret.txt", b"recoverable");
    drop(vault);

    let vault = FsVault::open_with_recovery(dir.path(), code.as_str()).unwrap();
    assert_eq!(read_all(&vault, "secret.txt"), b"recoverable");
}

#[test]
fn recovery_code_survives_a_passphrase_change() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, code) = create(&dir);
    vault.change_passphrase(PASS, NEW_PASS, TEST_KDF).unwrap();
    drop(vault);

    assert!(FsVault::open_with_recovery(dir.path(), code.as_str()).is_ok());
}

#[test]
fn recovery_code_tolerates_hand_copying_mistakes() {
    let dir = tempfile::tempdir().unwrap();
    let (_vault, code) = create(&dir);
    let sloppy = code.as_str().to_lowercase().replace('-', " ");
    assert!(FsVault::open_with_recovery(dir.path(), &sloppy).is_ok());
}

#[test]
fn mistyped_recovery_code_is_reported_as_invalid_before_any_decryption() {
    let dir = tempfile::tempdir().unwrap();
    let (_vault, code) = create(&dir);
    let mut chars: Vec<char> = code.as_str().chars().collect();
    let i = chars.iter().position(|c| *c != '-').unwrap();
    chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
    let typed: String = chars.into_iter().collect();
    assert!(matches!(
        FsVault::open_with_recovery(dir.path(), &typed),
        Err(VaultError::InvalidRecoveryCode)
    ));
}

#[test]
fn well_formed_but_wrong_recovery_code_is_wrong_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    create(&dir);
    let other_code = unrelated_recovery_code();
    assert!(matches!(
        FsVault::open_with_recovery(dir.path(), other_code.as_str()),
        Err(VaultError::WrongPassphrase)
    ));
}

#[test]
fn rotating_the_recovery_code_invalidates_the_old_one() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, old_code) = create(&dir);
    let new_code = vault.rotate_recovery_code(PASS).unwrap();
    drop(vault);

    assert_ne!(old_code.as_str(), new_code.as_str());
    assert!(matches!(
        FsVault::open_with_recovery(dir.path(), old_code.as_str()),
        Err(VaultError::WrongPassphrase)
    ));
    assert!(FsVault::open_with_recovery(dir.path(), new_code.as_str()).is_ok());
}

#[test]
fn rotating_the_recovery_code_needs_the_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _code) = create(&dir);
    assert!(matches!(
        vault.rotate_recovery_code(b"wrong"),
        Err(VaultError::WrongPassphrase)
    ));
}

#[test]
fn lock_then_reopen_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _code) = create(&dir);
    write_file(&vault, "x", b"data");
    vault.lock();
    let vault = FsVault::open(dir.path(), PASS).unwrap();
    assert_eq!(read_all(&vault, "x"), b"data");
}

#[test]
fn config_without_recovery_rejects_recovery_codes() {
    // A vault created by an older build has no recovery wrap. A code must not unlock it.
    let dir = tempfile::tempdir().unwrap();
    let (_vault, code) = create(&dir);
    let conf = dir.path().join(CONFIG_FILE_NAME);
    let mut json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&conf).unwrap()).unwrap();
    json.as_object_mut().unwrap().remove("recovery");
    fs::write(&conf, serde_json::to_string(&json).unwrap()).unwrap();

    assert!(matches!(
        FsVault::open_with_recovery(dir.path(), code.as_str()),
        Err(VaultError::WrongPassphrase)
    ));
    assert!(FsVault::open(dir.path(), PASS).is_ok());
}

/// A well-formed code belonging to a different vault.
fn unrelated_recovery_code() -> RecoveryCode {
    let other = tempfile::tempdir().unwrap();
    let (_v, code) = FsVault::create(other.path(), b"x", TEST_KDF).unwrap();
    code
}

#[test]
fn rekey_preserves_contents_and_re_encrypts_everything() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, old_code) = create(&dir);
    vault.create_dir("sub").unwrap();
    write_file(&vault, "sub/a.md", &vec![7u8; 10_000]);
    write_file(&vault, "b.txt", b"bee");
    let before: Vec<Vec<u8>> = encrypted_snapshot(dir.path())
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect();

    let (vault, new_code) = vault.rekey(NEW_PASS, TEST_KDF).unwrap();
    assert_eq!(read_all(&vault, "sub/a.md"), vec![7u8; 10_000]);
    assert_eq!(read_all(&vault, "b.txt"), b"bee");

    let after: Vec<Vec<u8>> = encrypted_snapshot(dir.path())
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect();
    assert_eq!(after.len(), before.len());
    for bytes in &after {
        assert!(
            !before.contains(bytes),
            "a ciphertext survived the re-key unchanged"
        );
    }
    drop(vault);

    assert!(matches!(
        FsVault::open(dir.path(), PASS),
        Err(VaultError::WrongPassphrase)
    ));
    assert!(FsVault::open(dir.path(), NEW_PASS).is_ok());
    assert!(matches!(
        FsVault::open_with_recovery(dir.path(), old_code.as_str()),
        Err(VaultError::WrongPassphrase)
    ));
    assert!(FsVault::open_with_recovery(dir.path(), new_code.as_str()).is_ok());

    let name = dir
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    for suffix in ["rekey-tmp", "rekey-old"] {
        assert!(
            !dir.path()
                .with_file_name(format!("{name}.{suffix}"))
                .exists()
        );
    }
}
