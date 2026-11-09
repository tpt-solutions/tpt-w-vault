// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Manual check of the WinFsp mount: needs WinFsp installed. Run with
//! `cargo run -p tpt-vault-platform-windows --example mount_selftest -- V`.
//!
//! It creates a throwaway vault, mounts it as the given drive, exercises the usual file
//! operations through the drive, unmounts, and reopens the vault to confirm the data is on disk.

use std::{fs, sync::Arc, time::Duration};

use tpt_vault_core::{FsVault, KdfParams, VaultBackend, VaultFile};
use tpt_vault_platform_windows::WinFspMount;

const PASS: &[u8] = b"mount-selftest";

fn main() {
    let drive = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "V".into())
        .chars()
        .next()
        .expect("drive letter");
    let root = std::env::temp_dir().join(format!("tpt-mount-selftest-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let params = KdfParams {
        log_n: 10,
        r: 8,
        p: 1,
    };
    let (vault, _code) = FsVault::create(&root, PASS, params).expect("create vault");

    let shared = Arc::new(vault);
    let mount = match WinFspMount::mount(Arc::clone(&shared), drive) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("mount failed: {e}");
            std::process::exit(1);
        }
    };
    println!("mounted at {drive}:");
    std::thread::sleep(Duration::from_millis(500));

    let p = |s: &str| format!("{drive}:\\{s}");
    fs::create_dir(p("docs")).expect("create directory");
    fs::write(p("docs\\plan.md"), b"hello vault").expect("write file");
    assert_eq!(fs::read(p("docs\\plan.md")).expect("read"), b"hello vault");

    let names: Vec<String> = fs::read_dir(p("docs"))
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["plan.md"], "listing");

    fs::rename(p("docs\\plan.md"), p("docs\\renamed.md")).expect("rename");
    assert!(
        fs::metadata(p("docs\\plan.md")).is_err(),
        "old name still exists"
    );

    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(p("big.bin"), &big).expect("write large file");
    assert_eq!(fs::read(p("big.bin")).expect("read large file"), big);

    assert!(
        fs::remove_dir(p("docs")).is_err(),
        "non-empty directory was removed"
    );
    fs::remove_file(p("docs\\renamed.md")).expect("delete file");
    fs::remove_dir(p("docs")).expect("delete directory");
    println!("file operations passed");

    mount.unmount();
    drop(shared);

    // Reopen from disk: the large file must be intact after the unmount.
    let reopened = FsVault::open(&root, PASS).expect("reopen vault");
    let mut file = reopened.open_file("big.bin").expect("open big.bin");
    assert_eq!(file.size().expect("size"), big.len() as u64);
    let mut back = vec![0u8; big.len()];
    let mut done = 0;
    while done < back.len() {
        let n = file.read_at(done as u64, &mut back[done..]).expect("read");
        assert!(n > 0, "short read");
        done += n;
    }
    assert_eq!(back, big, "content changed across unmount");
    println!("reopened vault: data intact");

    let _ = fs::remove_dir_all(&root);
    println!("ok");
}
