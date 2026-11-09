// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Note storage for the secure markdown editor (Phase 7).
//!
//! Notes are ordinary vault files, so they get the same encryption as every other entry. The
//! editor never writes plaintext to a temp file. The autosave timer lives in the editor
//! (`src/editor.ts`); the core has no timer of its own.

use crate::backend::{EntryKind, VaultBackend, VaultFile};
use crate::error::Result;

/// Replaces the contents of the note at `path` with `text`, creating the note if needed.
///
/// The write goes over the existing bytes and then truncates, so a shorter note never keeps
/// the tail of an older, longer version.
pub fn save_note<B: VaultBackend>(backend: &B, path: &str, text: &str) -> Result<()> {
    let mut file = match backend.open_file(path) {
        Ok(f) => f,
        Err(crate::error::VaultError::NotFound(_)) => backend.create_file(path)?,
        Err(e) => return Err(e),
    };
    let bytes = text.as_bytes();
    file.write_at(0, bytes)?;
    file.truncate(bytes.len() as u64)
}

/// Reads the note at `path` as UTF-8 text.
pub fn load_note<B: VaultBackend>(backend: &B, path: &str) -> Result<String> {
    let mut file = backend.open_file(path)?;
    let len = file.size()? as usize;
    let mut buf = vec![0u8; len];
    let mut done = 0;
    while done < len {
        let n = file.read_at(done as u64, &mut buf[done..])?;
        if n == 0 {
            break;
        }
        done += n;
    }
    buf.truncate(done);
    String::from_utf8(buf).map_err(|_| crate::error::VaultError::Corrupt {
        path: path.to_owned(),
        detail: "note is not valid UTF-8".into(),
    })
}

/// Whether `name` is a markdown note by extension (`.md`, case-insensitive).
pub fn is_note_name(name: &str) -> bool {
    name.len() > 3
        && name.is_char_boundary(name.len() - 3)
        && name[name.len() - 3..].eq_ignore_ascii_case(".md")
}

/// Lists every markdown note under `dir` (the vault root for `""`), recursively.
///
/// Returns full vault paths, sorted, with `/` separators. Non-note files are skipped.
pub fn list_notes<B: VaultBackend>(backend: &B, dir: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.trim_matches('/').to_owned()];
    while let Some(current) = stack.pop() {
        for entry in backend.list_dir(&current)? {
            let path = if current.is_empty() {
                entry.name.clone()
            } else {
                format!("{current}/{}", entry.name)
            };
            match entry.kind {
                EntryKind::Directory => stack.push(path),
                EntryKind::File if is_note_name(&entry.name) => out.push(path),
                EntryKind::File => {}
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_names_are_matched_by_extension() {
        assert!(is_note_name("a.md"));
        assert!(is_note_name("README.MD"));
        assert!(!is_note_name(".md"));
        assert!(!is_note_name("a.txt"));
        assert!(!is_note_name("md"));
    }
}
