// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! End-to-end tests of the on-disk vault through the public API only.

use std::{
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use tpt_vault_core::{
    CONFIG_FILE_NAME, EntryKind, FsVault, KdfParams, VaultBackend, VaultError, VaultFile,
    copy_from_file, copy_into_file,
};

const PASS: &[u8] = b"correct horse battery staple";
/// Cheap scrypt cost so the suite stays fast. Production uses KdfParams::RECOMMENDED.
const TEST_KDF: KdfParams = KdfParams {
    log_n: 10,
    r: 8,
    p: 1,
};
const BLOCK: usize = 4096;
const RECORD: usize = 4124; // nonce 12 + block 4096 + tag 16
const HEADER: usize = 21;

fn new_vault(dir: &tempfile::TempDir) -> FsVault {
    FsVault::create(dir.path(), PASS, TEST_KDF)
        .expect("create vault")
        .0
}

/// Deterministic, non-repeating-looking bytes for round-trip checks.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ ((i >> 8) as u8))
        .collect()
}

fn write_file(vault: &FsVault, path: &str, data: &[u8]) {
    let mut f = vault.create_file(path).expect("create");
    f.write_at(0, data).expect("write");
}

fn read_all(vault: &FsVault, path: &str) -> Vec<u8> {
    let mut f = vault.open_file(path).expect("open");
    let mut out = Vec::new();
    copy_from_file(&mut f, &mut out).expect("read");
    out
}

/// The single encrypted file on disk, for tests that tamper with raw bytes.
/// Only valid when the vault root holds exactly one entry besides vault.conf.
fn only_disk_file(root: &Path) -> PathBuf {
    let entries: Vec<PathBuf> = fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap() != CONFIG_FILE_NAME)
        .collect();
    assert_eq!(entries.len(), 1, "expected exactly one encrypted entry");
    entries.into_iter().next().unwrap()
}

fn all_bytes_under(root: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.extend_from_slice(p.file_name().unwrap().to_string_lossy().as_bytes());
                out.extend_from_slice(&fs::read(&p).unwrap());
            }
        }
    }
    out
}

// --- round trips and layout -------------------------------------------------

#[test]
fn round_trip_at_block_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    for (i, len) in [0, 1, BLOCK - 1, BLOCK, BLOCK + 1, 2 * BLOCK, 3 * BLOCK + 17]
        .into_iter()
        .enumerate()
    {
        let name = format!("f{i}.bin");
        let data = pattern(len, i as u8);
        write_file(&vault, &name, &data);
        assert_eq!(read_all(&vault, &name), data, "length {len}");
        assert_eq!(
            vault.stat(&name).unwrap().size,
            len as u64,
            "size for {len}"
        );
    }
}

#[test]
fn reopen_with_correct_passphrase_reads_back() {
    let dir = tempfile::tempdir().unwrap();
    {
        let vault = new_vault(&dir);
        vault.create_dir("notes").unwrap();
        write_file(&vault, "notes/todo.md", b"# hello\n");
    }
    let vault = FsVault::open(dir.path(), PASS).unwrap();
    assert_eq!(read_all(&vault, "notes/todo.md"), b"# hello\n");
}

#[test]
fn wrong_passphrase_is_reported_as_such() {
    let dir = tempfile::tempdir().unwrap();
    new_vault(&dir);
    assert!(matches!(
        FsVault::open(dir.path(), b"wrong"),
        Err(VaultError::WrongPassphrase)
    ));
}

#[test]
fn tampered_config_is_reported_as_wrong_passphrase_not_corruption() {
    let dir = tempfile::tempdir().unwrap();
    new_vault(&dir);
    let conf = dir.path().join(CONFIG_FILE_NAME);
    let text = fs::read_to_string(&conf).unwrap();
    // Corrupt the wrapped key by swapping one base64 character for a different one.
    let key_start = text.find("\"wrapped_master_key\": \"").unwrap() + 23;
    let mut bytes = text.into_bytes();
    bytes[key_start + 5] = if bytes[key_start + 5] == b'A' {
        b'B'
    } else {
        b'A'
    };
    fs::write(&conf, bytes).unwrap();
    assert!(matches!(
        FsVault::open(dir.path(), PASS),
        Err(VaultError::WrongPassphrase)
    ));
}

#[test]
fn unsupported_config_version_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    new_vault(&dir);
    let conf = dir.path().join(CONFIG_FILE_NAME);
    let text = fs::read_to_string(&conf)
        .unwrap()
        .replace("\"format_version\": 1", "\"format_version\": 2");
    fs::write(&conf, text).unwrap();
    assert!(matches!(
        FsVault::open(dir.path(), PASS),
        Err(VaultError::UnsupportedVersion(2))
    ));
}

#[test]
fn creating_over_an_existing_vault_fails() {
    let dir = tempfile::tempdir().unwrap();
    new_vault(&dir);
    assert!(matches!(
        FsVault::create(dir.path(), PASS, TEST_KDF),
        Err(VaultError::AlreadyExists(_))
    ));
}

// --- random access ----------------------------------------------------------

#[test]
fn overwrite_in_the_middle_changes_only_that_range() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    let mut expected = pattern(3 * BLOCK, 7);
    write_file(&vault, "a.bin", &expected);

    let patch = vec![0xEE; 300];
    let offset = BLOCK - 100; // straddles the block 0 / block 1 boundary
    let mut f = vault.open_file("a.bin").unwrap();
    f.write_at(offset as u64, &patch).unwrap();
    expected[offset..offset + patch.len()].copy_from_slice(&patch);

    assert_eq!(read_all(&vault, "a.bin"), expected);
}

#[test]
fn write_past_end_zero_fills_the_gap() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    write_file(&vault, "gap.bin", b"head");
    let mut f = vault.open_file("gap.bin").unwrap();
    f.write_at(10_000, b"tail").unwrap();

    let got = read_all(&vault, "gap.bin");
    assert_eq!(got.len(), 10_004);
    assert_eq!(&got[..4], b"head");
    assert!(got[4..10_000].iter().all(|&b| b == 0));
    assert_eq!(&got[10_000..], b"tail");
}

#[test]
fn read_past_end_returns_zero_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    write_file(&vault, "short.bin", b"abc");
    let mut f = vault.open_file("short.bin").unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(f.read_at(3, &mut buf).unwrap(), 0);
    assert_eq!(f.read_at(1, &mut buf).unwrap(), 2);
    assert_eq!(&buf[..2], b"bc");
}

// --- streaming --------------------------------------------------------------

/// A reader that produces `len` pseudo-random bytes without holding them in memory.
struct Generator {
    remaining: usize,
    state: u64,
}

impl Read for Generator {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.remaining);
        for b in &mut buf[..n] {
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            *b = self.state as u8;
        }
        self.remaining -= n;
        Ok(n)
    }
}

#[test]
fn large_file_streams_through_without_loading_whole() {
    const LEN: usize = 8 * 1024 * 1024 + 123;
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);

    let mut f = vault.create_file("big.bin").unwrap();
    let written = copy_into_file(
        &mut f,
        &mut Generator {
            remaining: LEN,
            state: 0x9E37_79B9_7F4A_7C15,
        },
    )
    .unwrap();
    assert_eq!(written, LEN as u64);
    assert_eq!(f.size().unwrap(), LEN as u64);

    // Hash the expected bytes independently, then compare with what the vault returns.
    let mut expected = Sha256::new();
    std::io::copy(
        &mut Generator {
            remaining: LEN,
            state: 0x9E37_79B9_7F4A_7C15,
        },
        &mut expected,
    )
    .unwrap();

    let mut got = Sha256::new();
    let mut r = vault.open_file("big.bin").unwrap();
    copy_from_file(&mut r, &mut got).unwrap();
    assert_eq!(got.finalize(), expected.finalize());
}

#[test]
fn copy_into_file_handles_short_reads() {
    // A reader that returns one byte at a time must still produce aligned, correct output.
    struct Trickle<'a>(Cursor<&'a [u8]>);
    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(1);
            self.0.read(&mut buf[..n])
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    let data = pattern(BLOCK + 500, 3);
    let mut f = vault.create_file("trickle.bin").unwrap();
    copy_into_file(&mut f, &mut Trickle(Cursor::new(&data))).unwrap();
    assert_eq!(read_all(&vault, "trickle.bin"), data);
}

// --- integrity --------------------------------------------------------------

#[test]
fn flipped_bit_in_one_block_is_corruption_and_other_blocks_still_read() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    let data = pattern(3 * BLOCK, 1);
    write_file(&vault, "t.bin", &data);

    let disk = only_disk_file(dir.path());
    let mut raw = fs::read(&disk).unwrap();
    // Flip a ciphertext byte in block 1.
    raw[HEADER + RECORD + 12 + 10] ^= 0x01;
    fs::write(&disk, raw).unwrap();

    let mut f = vault.open_file("t.bin").unwrap();
    let mut buf = vec![0u8; BLOCK];
    assert_eq!(f.read_at(0, &mut buf).unwrap(), BLOCK);
    assert_eq!(&buf[..], &data[..BLOCK], "block 0 is untouched");

    let err = f.read_at(BLOCK as u64, &mut buf).unwrap_err();
    assert!(
        matches!(err, VaultError::Corrupt { .. }),
        "expected Corrupt, got {err:?}"
    );
}

#[test]
fn swapping_two_blocks_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    write_file(&vault, "s.bin", &pattern(2 * BLOCK, 9));

    let disk = only_disk_file(dir.path());
    let mut raw = fs::read(&disk).unwrap();
    let (a, b) = (HEADER, HEADER + RECORD);
    let block0 = raw[a..a + RECORD].to_vec();
    let block1 = raw[b..b + RECORD].to_vec();
    raw[a..a + RECORD].copy_from_slice(&block1);
    raw[b..b + RECORD].copy_from_slice(&block0);
    fs::write(&disk, raw).unwrap();

    let mut f = vault.open_file("s.bin").unwrap();
    let mut buf = [0u8; 16];
    assert!(matches!(
        f.read_at(0, &mut buf),
        Err(VaultError::Corrupt { .. })
    ));
}

#[test]
fn truncating_at_a_block_boundary_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    write_file(&vault, "tr.bin", &pattern(2 * BLOCK, 4));

    // Drop the second record. Block 0 was sealed as a non-final block, so it must now fail.
    let disk = only_disk_file(dir.path());
    let file = fs::OpenOptions::new().write(true).open(&disk).unwrap();
    file.set_len((HEADER + RECORD) as u64).unwrap();
    drop(file);

    let mut f = vault.open_file("tr.bin").unwrap();
    let mut buf = [0u8; 16];
    assert!(matches!(
        f.read_at(0, &mut buf),
        Err(VaultError::Corrupt { .. })
    ));
}

// --- filenames and tree ----------------------------------------------------

#[test]
fn no_plaintext_names_or_contents_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    vault.create_dir("TOPSECRETDIR").unwrap();
    write_file(
        &vault,
        "TOPSECRETDIR/PLAINNAME-XYZ.md",
        b"CONTENT-MARKER-QQQ",
    );

    let on_disk = all_bytes_under(dir.path());
    for needle in [
        &b"TOPSECRETDIR"[..],
        b"PLAINNAME-XYZ",
        b"CONTENT-MARKER-QQQ",
    ] {
        assert!(
            !on_disk.windows(needle.len()).any(|w| w == needle),
            "plaintext {:?} found on disk",
            String::from_utf8_lossy(needle)
        );
    }
}

#[test]
fn same_name_is_stable_and_distinct_names_do_not_collide() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    vault.create_dir("d").unwrap();
    let names: Vec<String> = (0..1000).map(|i| format!("file-{i:04}.md")).collect();
    for n in &names {
        vault.create_file(&format!("d/{n}")).unwrap();
    }
    let mut disk_names: Vec<String> = fs::read_dir(dir.path().join(
        // The encrypted "d" directory is the only child of the root besides vault.conf.
        only_disk_dir_name(dir.path()),
    ))
    .unwrap()
    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
    .collect();
    disk_names.sort();
    disk_names.dedup();
    assert_eq!(disk_names.len(), names.len(), "encrypted names collided");

    // Stable: listing returns exactly the plaintext names, in sorted order.
    let listed: Vec<String> = vault
        .list_dir("d")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    let mut expected = names.clone();
    expected.sort();
    assert_eq!(listed, expected);
}

fn only_disk_dir_name(root: &Path) -> String {
    fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap())
        .find(|e| e.file_name() != CONFIG_FILE_NAME && e.path().is_dir())
        .unwrap()
        .file_name()
        .to_string_lossy()
        .into_owned()
}

#[test]
fn names_over_255_bytes_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    let too_long = "a".repeat(256);
    assert!(matches!(
        vault.create_file(&too_long),
        Err(VaultError::NameTooLong(_))
    ));
}

/// Names whose encrypted form exceeds 255 bytes are stored under hashed long names.
#[test]
fn long_names_round_trip_and_leave_no_orphans() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    let long_dir = "d".repeat(250);
    let long_file = format!("{}.md", "f".repeat(250));
    vault.create_dir(&long_dir).unwrap();
    write_file(&vault, &format!("{long_dir}/{long_file}"), b"long!");

    let names: Vec<String> = vault
        .list_dir(&long_dir)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec![long_file.clone()]);
    assert_eq!(
        read_all(&vault, &format!("{long_dir}/{long_file}")),
        b"long!"
    );

    // Rename a long-named file to another long name, then to a short one.
    let renamed = format!("{long_dir}/{}.md", "g".repeat(250));
    vault
        .rename(&format!("{long_dir}/{long_file}"), &renamed)
        .unwrap();
    vault
        .rename(&renamed, &format!("{long_dir}/short.md"))
        .unwrap();
    assert_eq!(read_all(&vault, &format!("{long_dir}/short.md")), b"long!");

    // Every sidecar must be gone once nothing long-named remains in that directory.
    vault.remove(&format!("{long_dir}/short.md")).unwrap();
    vault.remove(&long_dir).unwrap();
    assert!(vault.list_dir("").unwrap().is_empty());
    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != CONFIG_FILE_NAME)
        .collect();
    assert!(leftovers.is_empty(), "leftover entries: {leftovers:?}");
}

#[test]
fn tampered_long_name_sidecar_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    let name = "s".repeat(250);
    write_file(&vault, &name, b"x");

    let sidecar = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.to_string_lossy().ends_with(".name"))
        .expect("sidecar exists");
    fs::write(&sidecar, "AAAA").unwrap();

    assert!(matches!(
        vault.list_dir(""),
        Err(VaultError::Corrupt { .. })
    ));
}

#[test]
fn directory_tree_list_stat_rename_remove() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    vault.create_dir("a").unwrap();
    vault.create_dir("a/b").unwrap();
    write_file(&vault, "a/b/c.txt", b"hi");

    let root: Vec<_> = vault.list_dir("").unwrap();
    assert_eq!(root.len(), 1);
    assert_eq!(root[0].name, "a");
    assert_eq!(root[0].kind, EntryKind::Directory);

    // Renaming a directory keeps its subtree readable, since names are per-segment.
    vault.rename("a", "renamed").unwrap();
    assert_eq!(read_all(&vault, "renamed/b/c.txt"), b"hi");

    // Non-empty directories cannot be removed.
    assert!(matches!(
        vault.remove("renamed"),
        Err(VaultError::DirectoryNotEmpty(_))
    ));
    vault.remove("renamed/b/c.txt").unwrap();
    vault.remove("renamed/b").unwrap();
    vault.remove("renamed").unwrap();
    assert!(vault.list_dir("").unwrap().is_empty());
}

#[test]
fn rename_never_overwrites_and_missing_paths_are_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    write_file(&vault, "x", b"1");
    write_file(&vault, "y", b"2");
    assert!(matches!(
        vault.rename("x", "y"),
        Err(VaultError::AlreadyExists(_))
    ));
    assert!(matches!(
        vault.open_file("nope"),
        Err(VaultError::NotFound(_))
    ));
    assert!(matches!(
        vault.create_file("x"),
        Err(VaultError::AlreadyExists(_))
    ));
}

#[test]
fn rename_keeps_contents_because_names_are_not_bound_to_data() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    let data = pattern(BLOCK + 9, 2);
    write_file(&vault, "before.bin", &data);
    vault.rename("before.bin", "after.bin").unwrap();
    assert_eq!(read_all(&vault, "after.bin"), data);
}

#[test]
fn path_traversal_and_reserved_names_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    for bad in ["../escape", "a/../../b", "/abs", "x/", CONFIG_FILE_NAME] {
        assert!(
            matches!(vault.create_file(bad), Err(VaultError::InvalidPath { .. })),
            "should reject {bad:?}"
        );
    }
    assert!(!dir.path().parent().unwrap().join("escape").exists());
}

#[test]
fn listing_a_file_or_opening_a_directory_gives_typed_errors() {
    let dir = tempfile::tempdir().unwrap();
    let vault = new_vault(&dir);
    vault.create_dir("d").unwrap();
    write_file(&vault, "f", b"x");
    assert!(matches!(
        vault.list_dir("f"),
        Err(VaultError::NotADirectory(_))
    ));
    assert!(matches!(vault.open_file("d"), Err(VaultError::NotAFile(_))));
}

#[test]
fn each_block_write_is_counted_and_the_count_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let v = new_vault(&dir);
    assert_eq!(v.write_budget().writes, 0);

    let mut f = v.create_file("count.bin").unwrap();
    // 10 000 bytes from offset 0 span blocks 0, 1 and 2, so three nonces are used.
    f.write_at(0, &pattern(10_000, 1)).unwrap();
    assert_eq!(v.write_budget().writes, 3);
    drop(f);
    v.lock();

    let reopened = FsVault::open(dir.path(), PASS).unwrap();
    let status = reopened.write_budget();
    assert!(
        status.writes >= 3,
        "count fell to {} after reopen",
        status.writes
    );
    assert!(!status.soft_reached && !status.hard_reached);
}
