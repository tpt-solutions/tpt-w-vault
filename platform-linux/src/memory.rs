// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Pins key pages in RAM with `mlock`, so they are not swapped out.

/// Pins `region` in RAM. Returns false if the kernel refused, for example at `RLIMIT_MEMLOCK`.
pub fn lock_pages(region: &[u8]) -> bool {
    // SAFETY: the pointer and length describe a live slice. mlock only pins its pages.
    unsafe { libc::mlock(region.as_ptr().cast(), region.len()) == 0 }
}

/// Releases a region pinned by [`lock_pages`].
pub fn unlock_pages(region: &[u8]) {
    // SAFETY: as in `lock_pages`. The result is ignored because nothing can be done if the
    // region was already released.
    let _ = unsafe { libc::munlock(region.as_ptr().cast(), region.len()) };
}
