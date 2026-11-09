// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! The storage interface shared by every backend: on-disk (this crate), Archon (Phase 10),
//! and the mount backends (Phases 5 and 6) all implement [`VaultBackend`].
//!
//! Plaintext paths are `/`-separated, relative to the vault root, and have no leading or
//! trailing slash. The empty string is the root. `.` and `..` segments are rejected, so no
//! path can escape the vault.

use std::io::{self, Read, Write};

use crate::block::BLOCK_SIZE;
use crate::error::{Result, VaultError};

/// Bytes moved per call by [`copy_into_file`] and [`copy_from_file`]. Aligned to whole blocks
/// so sequential streaming encrypts each block once.
pub const STREAM_CHUNK: usize = BLOCK_SIZE * 256;

/// Kind of a vault entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}

/// Metadata for one vault entry, with its name already decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryInfo {
    /// Final path segment in plaintext. Empty for the root.
    pub name: String,
    pub kind: EntryKind,
    /// Plaintext length in bytes for files; 0 for directories.
    pub size: u64,
}

/// A random-access handle to one encrypted file.
pub trait VaultFile {
    /// Plaintext length in bytes.
    fn size(&self) -> Result<u64>;

    /// Reads up to `buf.len()` bytes starting at `offset`. Returns 0 at or past end of file.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Writes `data` at `offset`, extending the file (zero-filling any gap) as needed.
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()>;

    /// Sets the plaintext length: shrinks (discarding the tail) or extends with zero bytes.
    fn truncate(&mut self, len: u64) -> Result<()>;
}

/// Storage operations on a single unlocked vault.
pub trait VaultBackend {
    type File: VaultFile;

    /// Creates an empty directory. The parent must exist.
    fn create_dir(&self, path: &str) -> Result<()>;

    /// Lists the immediate children of a directory, sorted by name.
    fn list_dir(&self, path: &str) -> Result<Vec<EntryInfo>>;

    /// Creates a new empty file. Fails with `AlreadyExists` if the path is taken.
    fn create_file(&self, path: &str) -> Result<Self::File>;

    /// Opens an existing file for reading and writing.
    fn open_file(&self, path: &str) -> Result<Self::File>;

    /// Removes a file, or an empty directory.
    fn remove(&self, path: &str) -> Result<()>;

    /// Moves a file or directory. Fails with `AlreadyExists` if `to` is taken.
    fn rename(&self, from: &str, to: &str) -> Result<()>;

    /// Returns metadata for one entry.
    fn stat(&self, path: &str) -> Result<EntryInfo>;
}

/// A shared backend is a backend. This lets a mount and the app hold the same open vault.
impl<B: VaultBackend> VaultBackend for std::sync::Arc<B> {
    type File = B::File;

    fn create_dir(&self, path: &str) -> Result<()> {
        (**self).create_dir(path)
    }

    fn list_dir(&self, path: &str) -> Result<Vec<EntryInfo>> {
        (**self).list_dir(path)
    }

    fn create_file(&self, path: &str) -> Result<Self::File> {
        (**self).create_file(path)
    }

    fn open_file(&self, path: &str) -> Result<Self::File> {
        (**self).open_file(path)
    }

    fn remove(&self, path: &str) -> Result<()> {
        (**self).remove(path)
    }

    fn rename(&self, from: &str, to: &str) -> Result<()> {
        (**self).rename(from, to)
    }

    fn stat(&self, path: &str) -> Result<EntryInfo> {
        (**self).stat(path)
    }
}

/// Splits and validates a plaintext path into its segments. The root yields no segments.
pub fn split_path(path: &str) -> Result<Vec<&str>> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    let invalid = |reason: &'static str| VaultError::InvalidPath {
        path: path.to_owned(),
        reason,
    };
    let mut segments = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() {
            return Err(invalid("empty segment (leading, trailing or doubled '/')"));
        }
        if seg == "." || seg == ".." {
            return Err(invalid("'.' and '..' are not allowed"));
        }
        if seg.contains(['\\', ':', '\0']) {
            return Err(invalid("contains a reserved character (\\, : or NUL)"));
        }
        // Names are checked against Windows rules on every platform, so a vault made on Linux
        // still mounts on Windows.
        if seg.contains(['<', '>', '"', '|', '?', '*']) || seg.chars().any(|c| c < ' ') {
            return Err(invalid(
                "contains a character Windows does not allow (<>\"|?* or control)",
            ));
        }
        if seg.ends_with(['.', ' ']) {
            return Err(invalid(
                "ends with a dot or space, which Windows does not allow",
            ));
        }
        if is_windows_device_name(seg) {
            return Err(invalid(
                "is a reserved device name on Windows (CON, NUL, COM1, ...)",
            ));
        }
        segments.push(seg);
    }
    Ok(segments)
}

/// True if `seg` names a DOS device on Windows, with or without an extension: `CON`, `nul.txt`,
/// `COM5.md`, and so on. Windows compares these case-insensitively and ignores the extension.
pub fn is_windows_device_name(seg: &str) -> bool {
    let stem = seg
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    match stem.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        s if s.len() == 4 && (s.starts_with("COM") || s.starts_with("LPT")) => {
            s.as_bytes()[3].is_ascii_digit()
        }
        _ => false,
    }
}

/// Copies everything from `reader` into `file`, starting at offset 0. Streams in
/// [`STREAM_CHUNK`]-sized pieces, so memory use is bounded regardless of input size.
pub fn copy_into_file<F: VaultFile, R: Read>(file: &mut F, reader: &mut R) -> Result<u64> {
    let mut buf = vec![0u8; STREAM_CHUNK];
    let mut offset = 0u64;
    loop {
        let n = fill(reader, &mut buf)?;
        if n == 0 {
            break;
        }
        file.write_at(offset, &buf[..n])?;
        offset += n as u64;
    }
    Ok(offset)
}

/// Copies the whole of `file` into `writer`, streaming in [`STREAM_CHUNK`]-sized pieces.
pub fn copy_from_file<F: VaultFile, W: Write>(file: &mut F, writer: &mut W) -> Result<u64> {
    let mut buf = vec![0u8; STREAM_CHUNK];
    let mut offset = 0u64;
    loop {
        let n = file.read_at(offset, &mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        offset += n as u64;
    }
    Ok(offset)
}

/// Reads until `buf` is full or the reader is exhausted. Returns the bytes read.
fn fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Maps an OS error for a plaintext path onto the vault's error vocabulary.
pub(crate) fn map_io(path: &str, e: io::Error) -> VaultError {
    match e.kind() {
        io::ErrorKind::NotFound => VaultError::NotFound(path.to_owned()),
        io::ErrorKind::AlreadyExists => VaultError::AlreadyExists(path.to_owned()),
        io::ErrorKind::DirectoryNotEmpty => VaultError::DirectoryNotEmpty(path.to_owned()),
        _ => VaultError::Io(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_empty_segment_list() {
        assert!(split_path("").unwrap().is_empty());
    }

    #[test]
    fn splits_normal_paths() {
        assert_eq!(split_path("a/b/c.md").unwrap(), vec!["a", "b", "c.md"]);
    }

    #[test]
    fn rejects_names_windows_cannot_store() {
        for bad in [
            "CON",
            "nul.txt",
            "a/Com5.md",
            "lpt1",
            "AUX.tar.gz",
            "prn",
            "trailing.",
            "trailing ",
            "a/b /c",
            "x<y",
            "q?",
            "p*",
            "p|",
            "\"quoted\"",
            "tab\tname",
        ] {
            assert!(
                matches!(split_path(bad), Err(VaultError::InvalidPath { .. })),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn allows_names_that_only_look_like_device_names() {
        for ok in [
            "console.md",
            "COM10",
            "lpt",
            "null-notes.md",
            "my con.md",
            "a.b.c",
        ] {
            assert!(split_path(ok).is_ok(), "should accept {ok:?}");
        }
    }

    #[test]
    fn rejects_traversal_and_bad_separators() {
        for bad in [
            "..", "a/../b", "./a", "a//b", "/a", "a/", "a\\b", "c:x", "a\0b",
        ] {
            assert!(
                matches!(split_path(bad), Err(VaultError::InvalidPath { .. })),
                "should reject {bad:?}"
            );
        }
    }
}
