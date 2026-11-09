// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Manual check of the FUSE mount: needs `/dev/fuse` and `fusermount3`. Run with
//! `cargo run -p tpt-vault-platform-linux --example mount_selftest -- /tmp/tpt-mnt`.
//!
//! It creates a throwaway vault, mounts it at the given directory, runs the usual file operations
//! through the mount, unmounts, and reopens the vault to confirm the data reached disk.

#[cfg(target_os = "linux")]
fn main() {
    use std::{fs, path::PathBuf, sync::Arc, time::Duration};

    use tpt_vault_core::{FsVault, KdfParams, VaultBackend, VaultFile};
    use tpt_vault_platform_linux::FuseMount;

    const PASS: &[u8] = b"mount-selftest";
    let mountpoint = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: mount_selftest <empty mount directory>"),
    );
    fs::create_dir_all(&mountpoint).expect("mount directory");
    let root = std::env::temp_dir().join(format!("tpt-fuse-selftest-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let params = KdfParams {
        log_n: 10,
        r: 8,
        p: 1,
    };
    let (vault, _code) = FsVault::create(&root, PASS, params).expect("create vault");

    // Returns only once the mount is in the kernel's mount table, or with the error that stopped it.
    let mount = FuseMount::start(Arc::new(vault), mountpoint.clone()).expect("start mount");
    println!("mounted at {}", mount.mountpoint().display());
    std::thread::sleep(Duration::from_millis(50));

    let p = |s: &str| mountpoint.join(s);
    fs::create_dir(p("docs")).expect("create directory");
    fs::write(p("docs/plan.md"), b"hello vault").expect("write file");
    assert_eq!(fs::read(p("docs/plan.md")).expect("read"), b"hello vault");

    let names: Vec<String> = fs::read_dir(p("docs"))
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["plan.md"], "listing");

    fs::rename(p("docs/plan.md"), p("docs/renamed.md")).expect("rename");
    assert!(
        p("docs/plan.md").metadata().is_err(),
        "old name still exists"
    );

    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(p("big.bin"), &big).expect("write large file");
    assert_eq!(fs::read(p("big.bin")).expect("read large file"), big);

    assert!(
        fs::remove_dir(p("docs")).is_err(),
        "non-empty directory was removed"
    );
    fs::remove_file(p("docs/renamed.md")).expect("delete file");
    fs::remove_dir(p("docs")).expect("delete directory");
    println!("file operations passed");

    mount.unmount().expect("unmount");

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

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the FUSE self-test runs on Linux only");
}
