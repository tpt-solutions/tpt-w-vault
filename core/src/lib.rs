// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! tpt-vault core: vault format, crypto engine, key management.
//!
//! Phase 0 skeleton. The `VaultBackend` trait and crypto engine land in Phase 1.

/// Crate version, exposed so frontends and platform crates can report it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
