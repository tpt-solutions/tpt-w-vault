# Contributing to tpt-vault

tpt-vault is dual-licensed under MIT OR Apache-2.0 (see `LICENSE-MIT` and `LICENSE-APACHE`).
By contributing you agree that your contribution is licensed under the same terms.

## SPDX header convention

Every source file starts with an SPDX identifier and copyright line, using the comment syntax
of the file type:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions
```

```ts
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions
```

TOML/YAML use `#`, HTML uses `<!-- -->`. Generated files and lockfiles are exempt.

## Checks before opening a PR

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm ci && npm run build
```

The Rust toolchain is pinned in `rust-toolchain.toml`; MSRV is enforced via `clippy.toml`
and `rust-version` in the workspace `Cargo.toml`.
