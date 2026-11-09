// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Pins key pages in RAM with `VirtualLock`, so they are not written to the page file.

use windows::Win32::System::Memory::{VirtualLock, VirtualUnlock};

/// Pins `region` in RAM. Returns false if Windows refused, for example at the working-set limit.
pub fn lock_pages(region: &[u8]) -> bool {
    // SAFETY: the pointer and length describe a live slice, and VirtualLock only reads the range
    // to pin its pages. It does not write to it.
    unsafe { VirtualLock(region.as_ptr().cast(), region.len()) }.is_ok()
}

/// Releases a region pinned by [`lock_pages`].
pub fn unlock_pages(region: &[u8]) {
    // SAFETY: as in `lock_pages`. The result is ignored because nothing can be done if the
    // region was already released.
    let _ = unsafe { VirtualUnlock(region.as_ptr().cast(), region.len()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_can_be_pinned_and_released() {
        let page = vec![0u8; 4096];
        assert!(lock_pages(&page), "VirtualLock refused a single page");
        unlock_pages(&page);
    }
}
