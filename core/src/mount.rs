// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Inode-level view of a vault, shared by the mount backends.
//!
//! WinFsp (Windows, Phase 5) and FUSE (Linux, Phase 6) both work with numeric inodes and
//! `(parent, name)` lookups. [`VaultTree`] turns those calls into [`VaultBackend`] operations
//! and keeps the inode table. It has no OS dependencies, so it is tested on every platform.
//!
//! Inode numbers are never reused within one mount, so a stale handle fails with `NotFound`
//! instead of silently pointing at a different file.

use std::collections::HashMap;

use crate::backend::{EntryInfo, EntryKind, VaultBackend, VaultFile};
use crate::error::{Result, VaultError};

/// Inode of the vault root, following the FUSE convention.
pub const ROOT_INO: u64 = 1;

/// Maps inode numbers to vault paths and forwards operations to a backend.
pub struct VaultTree<B: VaultBackend> {
    backend: B,
    by_ino: HashMap<u64, String>,
    by_path: HashMap<String, u64>,
    next_ino: u64,
}

fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

impl<B: VaultBackend> VaultTree<B> {
    pub fn new(backend: B) -> Self {
        let mut tree = VaultTree {
            backend,
            by_ino: HashMap::new(),
            by_path: HashMap::new(),
            next_ino: ROOT_INO + 1,
        };
        tree.by_ino.insert(ROOT_INO, String::new());
        tree.by_path.insert(String::new(), ROOT_INO);
        tree
    }

    /// The underlying backend, for operations that have no inode form.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    fn path_of(&self, ino: u64) -> Result<String> {
        self.by_ino
            .get(&ino)
            .cloned()
            .ok_or_else(|| VaultError::NotFound(format!("inode {ino}")))
    }

    /// Returns the inode for `path`, allocating one on first sight.
    fn intern(&mut self, path: String) -> u64 {
        if let Some(&ino) = self.by_path.get(&path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.by_ino.insert(ino, path.clone());
        self.by_path.insert(path, ino);
        ino
    }

    /// Drops `path` and everything beneath it from the inode table.
    fn forget(&mut self, path: &str) {
        let prefix = format!("{path}/");
        let doomed: Vec<String> = self
            .by_path
            .keys()
            .filter(|p| p.as_str() == path || p.starts_with(&prefix))
            .cloned()
            .collect();
        for p in doomed {
            if let Some(ino) = self.by_path.remove(&p) {
                self.by_ino.remove(&ino);
            }
        }
    }

    /// Looks up `name` under directory `parent`.
    pub fn lookup(&mut self, parent: u64, name: &str) -> Result<(u64, EntryInfo)> {
        let path = join(&self.path_of(parent)?, name);
        let info = self.backend.stat(&path)?;
        Ok((self.intern(path), info))
    }

    /// Inode of the directory containing `ino`. The root is its own parent.
    pub fn parent(&self, ino: u64) -> Result<u64> {
        let path = self.path_of(ino)?;
        let parent_path = path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        self.by_path
            .get(parent_path)
            .copied()
            .ok_or_else(|| VaultError::NotFound(format!("parent of inode {ino}")))
    }

    /// Metadata for an inode.
    pub fn getattr(&self, ino: u64) -> Result<EntryInfo> {
        self.backend.stat(&self.path_of(ino)?)
    }

    /// Children of directory `ino`, each with its inode.
    pub fn readdir(&mut self, ino: u64) -> Result<Vec<(u64, EntryInfo)>> {
        let dir = self.path_of(ino)?;
        let entries = self.backend.list_dir(&dir)?;
        Ok(entries
            .into_iter()
            .map(|info| {
                let child = self.intern(join(&dir, &info.name));
                (child, info)
            })
            .collect())
    }

    /// Creates an empty file and returns its inode.
    pub fn create(&mut self, parent: u64, name: &str) -> Result<u64> {
        let path = join(&self.path_of(parent)?, name);
        // The handle is dropped at once. Reads and writes open the file again by path.
        self.backend.create_file(&path)?;
        Ok(self.intern(path))
    }

    /// Creates a directory and returns its inode.
    pub fn mkdir(&mut self, parent: u64, name: &str) -> Result<u64> {
        let path = join(&self.path_of(parent)?, name);
        self.backend.create_dir(&path)?;
        Ok(self.intern(path))
    }

    /// Removes a file or an empty directory.
    pub fn remove(&mut self, parent: u64, name: &str) -> Result<()> {
        let path = join(&self.path_of(parent)?, name);
        self.backend.remove(&path)?;
        self.forget(&path);
        Ok(())
    }

    /// Moves an entry. Like POSIX `rename`, an existing file at the destination is replaced.
    /// An existing directory at the destination is an error.
    pub fn rename(
        &mut self,
        parent: u64,
        name: &str,
        new_parent: u64,
        new_name: &str,
    ) -> Result<()> {
        let from = join(&self.path_of(parent)?, name);
        let to = join(&self.path_of(new_parent)?, new_name);
        if from == to {
            return Ok(());
        }
        match self.backend.stat(&to) {
            Ok(existing) if existing.kind == EntryKind::File => {
                self.backend.remove(&to)?;
                self.forget(&to);
            }
            Ok(_) => return Err(VaultError::AlreadyExists(to)),
            Err(VaultError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        self.backend.rename(&from, &to)?;
        self.repath(&from, &to);
        Ok(())
    }

    /// Rewrites inode paths after a rename, keeping inode numbers.
    fn repath(&mut self, from: &str, to: &str) {
        let prefix = format!("{from}/");
        let moved: Vec<(String, u64)> = self
            .by_path
            .iter()
            .filter(|(p, _)| p.as_str() == from || p.starts_with(&prefix))
            .map(|(p, &ino)| (p.clone(), ino))
            .collect();
        for (old, ino) in moved {
            self.by_path.remove(&old);
            let new = format!("{to}{}", &old[from.len()..]);
            self.by_path.insert(new.clone(), ino);
            self.by_ino.insert(ino, new);
        }
    }

    /// Reads up to `size` bytes at `offset`. Returns fewer bytes at end of file.
    pub fn read(&mut self, ino: u64, offset: u64, size: usize) -> Result<Vec<u8>> {
        let path = self.path_of(ino)?;
        let mut file = self.backend.open_file(&path)?;
        let mut out = vec![0u8; size];
        let mut done = 0usize;
        while done < size {
            let n = file.read_at(offset + done as u64, &mut out[done..])?;
            if n == 0 {
                break;
            }
            done += n;
        }
        out.truncate(done);
        Ok(out)
    }

    /// Writes `data` at `offset`, returning the number of bytes written.
    pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize> {
        let path = self.path_of(ino)?;
        let mut file = self.backend.open_file(&path)?;
        file.write_at(offset, data)?;
        Ok(data.len())
    }

    /// Sets a file's length.
    pub fn truncate(&mut self, ino: u64, size: u64) -> Result<()> {
        let path = self.path_of(ino)?;
        let mut file = self.backend.open_file(&path)?;
        file.truncate(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FsVault, KdfParams};

    fn tree() -> (tempfile::TempDir, VaultTree<FsVault>) {
        let dir = tempfile::tempdir().unwrap();
        let params = KdfParams {
            log_n: 10,
            r: 8,
            p: 1,
        };
        let (vault, _code) = FsVault::create(dir.path(), b"pw", params).unwrap();
        (dir, VaultTree::new(vault))
    }

    #[test]
    fn create_write_read_through_inodes() {
        let (_dir, mut t) = tree();
        let ino = t.create(ROOT_INO, "note.md").unwrap();
        assert_eq!(t.write(ino, 0, b"hello").unwrap(), 5);
        assert_eq!(t.read(ino, 0, 100).unwrap(), b"hello");
        assert_eq!(t.getattr(ino).unwrap().size, 5);
    }

    #[test]
    fn directories_list_and_lookup_consistently() {
        let (_dir, mut t) = tree();
        let d = t.mkdir(ROOT_INO, "docs").unwrap();
        let f = t.create(d, "a.txt").unwrap();
        let (found, info) = t.lookup(d, "a.txt").unwrap();
        assert_eq!(found, f, "same path gives the same inode");
        assert_eq!(info.kind, EntryKind::File);
        let names: Vec<String> = t
            .readdir(d)
            .unwrap()
            .into_iter()
            .map(|(_, i)| i.name)
            .collect();
        assert_eq!(names, vec!["a.txt"]);
    }

    #[test]
    fn rename_keeps_inode_numbers_for_descendants() {
        let (_dir, mut t) = tree();
        let a = t.mkdir(ROOT_INO, "a").unwrap();
        let f = t.create(a, "inside.txt").unwrap();
        t.write(f, 0, b"kept").unwrap();
        t.rename(ROOT_INO, "a", ROOT_INO, "b").unwrap();

        // The old inode still refers to the same file, now under the new directory name.
        assert_eq!(t.read(f, 0, 10).unwrap(), b"kept");
        let (b_ino, _) = t.lookup(ROOT_INO, "b").unwrap();
        assert_eq!(t.lookup(b_ino, "inside.txt").unwrap().0, f);
    }

    #[test]
    fn rename_over_a_file_replaces_it_like_posix() {
        let (_dir, mut t) = tree();
        let src = t.create(ROOT_INO, "src").unwrap();
        t.write(src, 0, b"new").unwrap();
        let dst = t.create(ROOT_INO, "dst").unwrap();
        t.write(dst, 0, b"old").unwrap();
        t.rename(ROOT_INO, "src", ROOT_INO, "dst").unwrap();
        let (now, _) = t.lookup(ROOT_INO, "dst").unwrap();
        assert_eq!(t.read(now, 0, 10).unwrap(), b"new");
        assert!(t.getattr(dst).is_err(), "replaced inode is no longer valid");
    }

    #[test]
    fn rename_over_a_directory_is_refused() {
        let (_dir, mut t) = tree();
        t.create(ROOT_INO, "file").unwrap();
        t.mkdir(ROOT_INO, "dir").unwrap();
        assert!(matches!(
            t.rename(ROOT_INO, "file", ROOT_INO, "dir"),
            Err(VaultError::AlreadyExists(_))
        ));
    }

    #[test]
    fn removed_inodes_are_not_reused() {
        let (_dir, mut t) = tree();
        let first = t.create(ROOT_INO, "x").unwrap();
        t.remove(ROOT_INO, "x").unwrap();
        assert!(matches!(t.getattr(first), Err(VaultError::NotFound(_))));
        let second = t.create(ROOT_INO, "x").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn truncate_grows_and_shrinks() {
        let (_dir, mut t) = tree();
        let ino = t.create(ROOT_INO, "t").unwrap();
        t.write(ino, 0, &[1u8; 5000]).unwrap();
        t.truncate(ino, 10).unwrap();
        assert_eq!(t.read(ino, 0, 100).unwrap(), vec![1u8; 10]);
        t.truncate(ino, 20).unwrap();
        let got = t.read(ino, 0, 100).unwrap();
        assert_eq!(&got[..10], &[1u8; 10]);
        assert!(got[10..].iter().all(|&b| b == 0), "extension is zero-filled");
    }

    #[test]
    fn read_past_end_is_short_not_an_error() {
        let (_dir, mut t) = tree();
        let ino = t.create(ROOT_INO, "s").unwrap();
        t.write(ino, 0, b"abc").unwrap();
        assert_eq!(t.read(ino, 1, 100).unwrap(), b"bc");
        assert!(t.read(ino, 50, 10).unwrap().is_empty());
    }
}
