// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Write-ahead journal for file writes that change existing records.
//!
//! Before a write rewrites records that already exist, or cuts the file short, the original
//! bytes of the affected region are copied to `<disk file>.journal`. The copy is written to
//! `<disk file>.jtmp` and renamed into place, so a journal is either absent or complete. The
//! data is changed only after the journal is in place, and the journal is removed only after
//! the new data has been synced.
//!
//! If the process dies in between, the next open, rename or remove of that file restores the
//! saved bytes and the old length. An interrupted write is therefore undone, and the file is
//! left in the state readers saw before it. A write that returned an error is undone at once.
//!
//! The saved bytes are encrypted records, so the journal holds no plaintext. A journal does not
//! make rollback safe against an attacker who can write to the vault folder: such an attacker
//! can already replace whole files with older, valid versions.
//!
//! Journal layout: `"TPTJ" (4) | version (1) | file header (21) | old length (8) |
//! saved offset (8) | saved length (8) | saved bytes`. All integers are little-endian.

use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use crate::error::{Result, VaultError};
use crate::file::HEADER_LEN;

const JOURNAL_SUFFIX: &str = ".journal";
const TMP_SUFFIX: &str = ".jtmp";
const MAGIC: &[u8; 4] = b"TPTJ";
const VERSION: u8 = 1;
const PREFIX_LEN: usize = 4 + 1 + HEADER_LEN + 8 + 8 + 8;

/// Whether a directory entry name is journal bookkeeping rather than a vault entry.
///
/// Encrypted names use only the base64url alphabet, which has no `.`, so any name with these
/// suffixes cannot be an entry.
pub(crate) fn is_journal_name(name: &str) -> bool {
    name.ends_with(JOURNAL_SUFFIX) || name.ends_with(TMP_SUFFIX)
}

fn with_suffix(disk: &Path, suffix: &str) -> PathBuf {
    let mut s = OsString::from(disk.as_os_str());
    s.push(suffix);
    PathBuf::from(s)
}

fn corrupt(disk: &Path, detail: &str) -> VaultError {
    VaultError::Corrupt {
        path: disk.display().to_string(),
        detail: detail.to_owned(),
    }
}

/// Makes a directory entry change (create, rename, delete) durable on Unix.
///
/// Windows journals directory metadata itself, so there is nothing to sync there.
pub(crate) fn sync_parent(disk: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        if let Some(parent) = disk.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    let _ = disk;
    Ok(())
}

/// Temp file for a new encrypted file. Hidden from listings like the journal files.
pub(crate) fn creation_temp(disk: &Path) -> PathBuf {
    with_suffix(disk, TMP_SUFFIX)
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Records the bytes that a write is about to change, so they can be restored.
///
/// `saved_from..saved_to` are disk offsets. The range is clipped to the current length, so
/// bytes past the end need no saving: rollback truncates them away.
pub(crate) fn begin(
    disk: &Path,
    file: &mut File,
    header: &[u8; HEADER_LEN],
    old_total: u64,
    saved_from: u64,
    saved_to: u64,
) -> Result<()> {
    let saved_to = saved_to.min(old_total);
    let saved_from = saved_from.min(saved_to);
    let saved_len = saved_to - saved_from;

    let tmp = with_suffix(disk, TMP_SUFFIX);
    let mut out = File::create(&tmp)?;
    out.write_all(MAGIC)?;
    out.write_all(&[VERSION])?;
    out.write_all(header)?;
    out.write_all(&old_total.to_le_bytes())?;
    out.write_all(&saved_from.to_le_bytes())?;
    out.write_all(&saved_len.to_le_bytes())?;

    file.seek(SeekFrom::Start(saved_from))?;
    let copied = io::copy(&mut Read::take(&mut *file, saved_len), &mut out)?;
    if copied != saved_len {
        return Err(corrupt(disk, "file is shorter than its recorded length"));
    }
    out.sync_all()?;
    drop(out);

    fs::rename(&tmp, with_suffix(disk, JOURNAL_SUFFIX))?;
    sync_parent(disk)
}

/// Restores the journaled bytes into `file` and removes the journal.
///
/// `file` must be the open data file for `disk`. The journal's header must match `header`,
/// which stops a journal from being applied to a different file.
pub(crate) fn rollback(disk: &Path, file: &mut File, header: &[u8; HEADER_LEN]) -> Result<()> {
    let jpath = with_suffix(disk, JOURNAL_SUFFIX);
    let mut journal = match File::open(&jpath) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    let mut prefix = [0u8; PREFIX_LEN];
    journal
        .read_exact(&mut prefix)
        .map_err(|_| corrupt(disk, "journal is shorter than its header"))?;
    if &prefix[..4] != MAGIC || prefix[4] != VERSION {
        return Err(corrupt(disk, "not a tpt-vault journal"));
    }
    let hdr_at = 5;
    if prefix[hdr_at..hdr_at + HEADER_LEN] != header[..] {
        return Err(corrupt(disk, "journal belongs to a different file"));
    }
    let num = |at: usize| u64::from_le_bytes(prefix[at..at + 8].try_into().expect("8 bytes"));
    let base = hdr_at + HEADER_LEN;
    let old_total = num(base);
    let saved_from = num(base + 8);
    let saved_len = num(base + 16);

    file.seek(SeekFrom::Start(saved_from))?;
    let copied = io::copy(&mut Read::take(&mut journal, saved_len), file)?;
    if copied != saved_len {
        return Err(corrupt(disk, "journal ends before its saved bytes"));
    }
    file.set_len(old_total)?;
    file.sync_data()?;

    remove_if_exists(&jpath)?;
    sync_parent(disk)
}

/// Undoes an interrupted write on `disk`, if one left a journal behind.
///
/// Called before a file is opened, renamed or removed. Does nothing when no journal exists.
pub(crate) fn recover(disk: &Path) -> Result<()> {
    remove_if_exists(&with_suffix(disk, TMP_SUFFIX))?;
    let jpath = with_suffix(disk, JOURNAL_SUFFIX);
    if !jpath.exists() {
        return Ok(());
    }
    if !disk.exists() {
        // The data file was removed first. There is nothing left to restore.
        return remove_if_exists(&jpath);
    }
    let mut file = OpenOptions::new().read(true).write(true).open(disk)?;
    let mut header = [0u8; HEADER_LEN];
    file.read_exact(&mut header)
        .map_err(|_| corrupt(disk, "file is shorter than its header"))?;
    rollback(disk, &mut file, &header)
}

/// Removes any journal and temporary file for `disk`. Used when the data file is gone or is
/// about to be replaced, so an old journal cannot be applied to the new file.
pub(crate) fn discard(disk: &Path) -> Result<()> {
    remove_if_exists(&with_suffix(disk, TMP_SUFFIX))?;
    remove_if_exists(&with_suffix(disk, JOURNAL_SUFFIX))?;
    sync_parent(disk)
}

/// Deletes the journal after a successful write.
pub(crate) fn finish(disk: &Path) -> Result<()> {
    remove_if_exists(&with_suffix(disk, JOURNAL_SUFFIX))?;
    sync_parent(disk)
}

/// Test-only fault injection. Lets tests stop a write part-way, either as an ordinary error or
/// as a crash, where nothing is undone and the journal is left behind.
#[cfg(test)]
pub(crate) mod failpoint {
    use std::cell::Cell;

    use crate::error::{Result, VaultError};

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum Mode {
        Error,
        Crash,
    }

    thread_local! {
        static PLAN: Cell<Option<(usize, Mode)>> = const { Cell::new(None) };
        static CRASHED: Cell<bool> = const { Cell::new(false) };
    }

    /// Fails the `after`-th record write from now (0 = the next one).
    pub(crate) fn arm(after: usize, mode: Mode) {
        PLAN.with(|p| p.set(Some((after, mode))));
        CRASHED.with(|c| c.set(false));
    }

    pub(crate) fn disarm() {
        PLAN.with(|p| p.set(None));
        CRASHED.with(|c| c.set(false));
    }

    /// Called after each record write.
    pub(crate) fn tick() -> Result<()> {
        PLAN.with(|p| match p.get() {
            Some((0, mode)) => {
                p.set(None);
                if mode == Mode::Crash {
                    CRASHED.with(|c| c.set(true));
                }
                Err(VaultError::Io(std::io::Error::other("injected fault")))
            }
            Some((n, mode)) => {
                p.set(Some((n - 1, mode)));
                Ok(())
            }
            None => Ok(()),
        })
    }

    /// Whether the last failure was an injected crash. Clears the flag.
    pub(crate) fn take_crash() -> bool {
        CRASHED.with(|c| c.replace(false))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::failpoint::{self, Mode};
    use super::{JOURNAL_SUFFIX, TMP_SUFFIX, is_journal_name, with_suffix};
    use crate::backend::{VaultBackend, VaultFile};
    use crate::config::KdfParams;
    use crate::error::VaultError;
    use crate::fsvault::FsVault;

    const KDF: KdfParams = KdfParams {
        log_n: 10,
        r: 8,
        p: 1,
    };
    const BLOCK: usize = 4096;
    const PASS: &[u8] = b"journal-test-pass";

    fn vault(dir: &tempfile::TempDir) -> FsVault {
        FsVault::create(dir.path(), PASS, KDF).unwrap().0
    }

    fn content(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn read_all(v: &FsVault, path: &str) -> Vec<u8> {
        let mut f = v.open_file(path).unwrap();
        let len = f.size().unwrap() as usize;
        let mut buf = vec![0u8; len];
        let mut done = 0;
        while done < len {
            let n = f.read_at(done as u64, &mut buf[done..]).unwrap();
            if n == 0 {
                break;
            }
            done += n;
        }
        buf.truncate(done);
        buf
    }

    fn journal_of(v: &FsVault, path: &str) -> std::path::PathBuf {
        with_suffix(&v.disk_file(path).unwrap(), JOURNAL_SUFFIX)
    }

    #[test]
    fn crash_during_extend_is_undone_on_next_open() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let before = content(2 * BLOCK + 500);
        let mut f = v.create_file("f").unwrap();
        f.write_at(0, &before).unwrap();
        drop(f);
        let disk = v.disk_file("f").unwrap();
        let snapshot = fs::read(&disk).unwrap();

        let mut f = v.open_file("f").unwrap();
        // Rewrites the old last record, then dies while writing the next one.
        failpoint::arm(1, Mode::Crash);
        let grow = content(4 * BLOCK);
        let err = f.write_at(before.len() as u64, &grow).unwrap_err();
        assert!(matches!(err, VaultError::Io(_)));
        drop(f);
        failpoint::disarm();

        assert!(
            journal_of(&v, "f").exists(),
            "the crash must leave the journal behind"
        );
        assert_ne!(
            fs::read(&disk).unwrap(),
            snapshot,
            "the crash must leave a torn file"
        );

        let reopened = FsVault::open(dir.path(), PASS).unwrap();
        assert_eq!(read_all(&reopened, "f"), before);
        assert_eq!(
            fs::read(&disk).unwrap(),
            snapshot,
            "disk bytes restored exactly"
        );
        assert!(!journal_of(&reopened, "f").exists());
    }

    #[test]
    fn crash_during_shrink_is_undone_on_next_open() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let before = content(3 * BLOCK + 100);
        let mut f = v.create_file("f").unwrap();
        f.write_at(0, &before).unwrap();
        failpoint::arm(0, Mode::Crash);
        // Re-seals block 1 as the final block, then dies before the file is cut.
        assert!(f.truncate((BLOCK + 10) as u64).is_err());
        drop(f);
        failpoint::disarm();

        let reopened = FsVault::open(dir.path(), PASS).unwrap();
        assert_eq!(read_all(&reopened, "f"), before);
    }

    #[test]
    fn error_mid_write_is_undone_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let before = content(2 * BLOCK + 500);
        let mut f = v.create_file("f").unwrap();
        f.write_at(0, &before).unwrap();
        let disk = v.disk_file("f").unwrap();
        let snapshot = fs::read(&disk).unwrap();

        failpoint::arm(1, Mode::Error);
        assert!(f.write_at(10, &content(3 * BLOCK)).is_err());
        failpoint::disarm();

        assert!(
            !journal_of(&v, "f").exists(),
            "rollback removes the journal"
        );
        assert_eq!(fs::read(&disk).unwrap(), snapshot);
        assert_eq!(f.size().unwrap(), before.len() as u64);
    }

    #[test]
    fn successful_write_leaves_no_journal_behind() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let mut f = v.create_file("f").unwrap();
        f.write_at(0, &content(BLOCK + 7)).unwrap();
        f.write_at(BLOCK as u64, b"tail-edit").unwrap();
        drop(f);
        assert!(!journal_of(&v, "f").exists());
        assert!(!with_suffix(&v.disk_file("f").unwrap(), TMP_SUFFIX).exists());
        // The edit at BLOCK runs 9 bytes past the original end, so the file grows to BLOCK + 9.
        let mut expected = content(BLOCK + 7);
        expected.resize(BLOCK + 9, 0);
        expected[BLOCK..].copy_from_slice(b"tail-edit");
        assert_eq!(read_all(&v, "f"), expected);
    }

    #[test]
    fn journal_files_are_not_listed_as_entries() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        v.create_file("visible").unwrap();
        fs::write(dir.path().join("AbC_123.journal"), b"junk").unwrap();
        fs::write(dir.path().join("AbC_123.jtmp"), b"junk").unwrap();
        let names: Vec<String> = v
            .list_dir("")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["visible"]);
        assert!(is_journal_name("AbC_123.journal"));
        assert!(!is_journal_name("AbC_123"));
    }

    #[test]
    fn stale_journal_does_not_attach_to_a_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        v.create_file("g").unwrap().write_at(0, b"old").unwrap();
        // A journal from some earlier file at this path, left after a removal was interrupted.
        let disk = v.disk_file("g").unwrap();
        fs::write(with_suffix(&disk, JOURNAL_SUFFIX), b"TPTJ junk").unwrap();
        v.remove("g").unwrap();
        assert!(!with_suffix(&disk, JOURNAL_SUFFIX).exists());

        v.create_file("g").unwrap().write_at(0, b"new").unwrap();
        assert_eq!(read_all(&v, "g"), b"new");
    }

    #[test]
    fn small_write_rewrites_only_the_records_it_touches() {
        // Regression: a write used to re-encrypt every record from the touched block to the end
        // of the file, which made small writes in large files very slow.
        let dir = tempfile::tempdir().unwrap();
        let v = vault(&dir);
        let mut f = v.create_file("f").unwrap();
        f.write_at(0, &content(10 * BLOCK)).unwrap();
        let disk = v.disk_file("f").unwrap();
        let before = fs::read(&disk).unwrap();

        f.write_at((5 * BLOCK + 10) as u64, b"small").unwrap();
        drop(f);
        let after = fs::read(&disk).unwrap();
        assert_eq!(before.len(), after.len());

        let rec = crate::block::RECORD_LEN;
        let head = crate::file::HEADER_LEN;
        let record = |bytes: &[u8], i: usize| bytes[head + i * rec..head + (i + 1) * rec].to_vec();
        for i in (0..10).filter(|&i| i != 5) {
            assert_eq!(
                record(&before, i),
                record(&after, i),
                "record {i} was rewritten"
            );
        }
        assert_ne!(record(&before, 5), record(&after, 5));
    }
}

#[cfg(test)]
mod creation_tests {
    use super::{creation_temp, is_journal_name};
    use crate::backend::VaultBackend;
    use crate::config::KdfParams;
    use crate::fsvault::FsVault;
    use std::fs;

    const KDF: KdfParams = KdfParams {
        log_n: 10,
        r: 8,
        p: 1,
    };

    #[test]
    fn interrupted_creation_leaves_no_visible_entry_and_is_cleaned_up() {
        let dir = tempfile::tempdir().unwrap();
        let (v, _code) = FsVault::create(dir.path(), b"creation-test", KDF).unwrap();
        let disk = v.disk_file("fresh.bin").unwrap();

        // A create stopped before its final link leaves only its temp file behind.
        let stale = creation_temp(&disk);
        fs::write(&stale, b"half a header").unwrap();
        assert!(is_journal_name(
            stale.file_name().unwrap().to_str().unwrap()
        ));
        assert!(
            v.list_dir("")
                .unwrap()
                .iter()
                .all(|e| e.name != "fresh.bin")
        );

        v.create_file("fresh.bin").unwrap();
        assert!(!stale.exists(), "temp file was not cleaned up");
        assert!(
            v.list_dir("")
                .unwrap()
                .iter()
                .any(|e| e.name == "fresh.bin")
        );
    }

    #[test]
    fn creating_over_an_existing_name_is_refused_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let (v, _code) = FsVault::create(dir.path(), b"creation-test", KDF).unwrap();
        v.create_file("taken.bin").unwrap();
        assert!(v.create_file("taken.bin").is_err());
        let disk = v.disk_file("taken.bin").unwrap();
        assert!(!creation_temp(&disk).exists());
    }
}
