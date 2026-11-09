// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Throughput check for the file layer. Run with `cargo run --release -p tpt-vault-core --example throughput`.
//!
//! Measures large sequential writes and reads, and small random overwrites. The small
//! overwrites are the case the write journal affects most, since each one fsyncs twice.

use std::{
    io::{self, Read},
    time::Instant,
};

use tpt_vault_core::{FsVault, KdfParams, VaultBackend, VaultFile, copy_from_file, copy_into_file};

const LARGE: u64 = 256 * 1024 * 1024;
const SMALL_WRITES: u32 = 2_000;
const SMALL_SPAN: u64 = 16 * 1024 * 1024;

fn mib_per_s(bytes: u64, secs: f64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0) / secs
}

fn main() {
    let dir = std::env::temp_dir().join(format!("tpt-vault-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (vault, _) = FsVault::create(&dir, b"bench-pass", KdfParams::RECOMMENDED).expect("create");

    let mut f = vault.create_file("large.bin").expect("create file");
    let t = Instant::now();
    let written = copy_into_file(&mut f, &mut io::repeat(0x5a).take(LARGE)).expect("write");
    let w = t.elapsed().as_secs_f64();
    drop(f);
    println!(
        "large write: {:.1} MiB/s ({} MiB in {:.2} s)",
        mib_per_s(written, w),
        written >> 20,
        w
    );

    let mut f = vault.open_file("large.bin").expect("open");
    let t = Instant::now();
    let read = copy_from_file(&mut f, &mut io::sink()).expect("read");
    let r = t.elapsed().as_secs_f64();
    println!("large read:  {:.1} MiB/s", mib_per_s(read, r));
    drop(f);

    // Small overwrites at pseudo-random offsets inside the first SMALL_SPAN bytes.
    let mut f = vault.open_file("large.bin").expect("open");
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let payload = [0xa5u8; 512];
    let t = Instant::now();
    for _ in 0..SMALL_WRITES {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let offset = seed % (SMALL_SPAN - payload.len() as u64);
        f.write_at(offset, &payload).expect("small write");
    }
    let s = t.elapsed().as_secs_f64();
    println!(
        "small overwrites: {} x 512 B in {:.2} s = {:.0} writes/s ({:.2} ms each)",
        SMALL_WRITES,
        s,
        f64::from(SMALL_WRITES) / s,
        s * 1000.0 / f64::from(SMALL_WRITES)
    );
    drop(f);

    let _ = std::fs::remove_dir_all(&dir);
}
