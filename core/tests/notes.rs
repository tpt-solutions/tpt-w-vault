// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Note storage through the vault: round trips, shrinking saves, and no plaintext on disk.

use std::fs;

use tpt_vault_core::notes::{list_notes, load_note, save_note};
use tpt_vault_core::{FsVault, KdfParams, VaultBackend};

const TEST_KDF: KdfParams = KdfParams {
    log_n: 10,
    r: 8,
    p: 1,
};

fn vault(dir: &tempfile::TempDir) -> FsVault {
    FsVault::create(dir.path(), b"notes-pass", TEST_KDF)
        .unwrap()
        .0
}

#[test]
fn save_then_load_round_trips_markdown() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(&dir);
    let text = "# Heading\n\n- item one\n- item two\n\n```rust\nfn main() {}\n```\n";
    save_note(&v, "notes.md", text).unwrap();
    assert_eq!(load_note(&v, "notes.md").unwrap(), text);
}

#[test]
fn a_shorter_save_does_not_keep_the_old_tail() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(&dir);
    let long = "x".repeat(10_000);
    save_note(&v, "n.md", &long).unwrap();
    save_note(&v, "n.md", "short").unwrap();
    assert_eq!(load_note(&v, "n.md").unwrap(), "short");
    assert_eq!(v.stat("n.md").unwrap().size, 5);
}

#[test]
fn multibyte_text_survives_block_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(&dir);
    // Mixed 1-, 2-, 3- and 4-byte characters, long enough to span several 4 KiB blocks.
    let text = "héllo wörld — 日本語 🙂 ".repeat(800);
    save_note(&v, "u.md", &text).unwrap();
    assert_eq!(load_note(&v, "u.md").unwrap(), text);
}

#[test]
fn listing_returns_only_markdown_notes_recursively() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(&dir);
    v.create_dir("work").unwrap();
    v.create_dir("work/deep").unwrap();
    save_note(&v, "root.md", "r").unwrap();
    save_note(&v, "work/a.MD", "a").unwrap();
    save_note(&v, "work/deep/b.md", "b").unwrap();
    v.create_file("work/image.png").unwrap();
    v.create_file("notes.txt").unwrap();

    assert_eq!(
        list_notes(&v, "").unwrap(),
        vec!["root.md", "work/a.MD", "work/deep/b.md"]
    );
    assert_eq!(
        list_notes(&v, "work/").unwrap(),
        vec!["work/a.MD", "work/deep/b.md"]
    );
}

#[test]
fn note_text_never_appears_in_plaintext_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(&dir);
    save_note(&v, "secret-title.md", "SECRET-NOTE-BODY-ZQX").unwrap();

    let mut stack = vec![dir.path().to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let raw = fs::read(&p).unwrap();
            for needle in [&b"SECRET-NOTE-BODY-ZQX"[..], b"secret-title"] {
                assert!(
                    !raw.windows(needle.len()).any(|w| w == needle),
                    "plaintext found in {}",
                    p.display()
                );
            }
        }
    }
}
