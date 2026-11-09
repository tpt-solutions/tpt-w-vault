# tpt-vault

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![CI](https://github.com/tpt-solutions/tpt-w-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/tpt-solutions/tpt-w-vault/actions/workflows/ci.yml)

**Local-first encrypted vault and secure markdown notes editor.** A VeraCrypt alternative for
people who just want to hide a folder of sensitive files, without the intimidation.

- Per-file, gocryptfs-style encryption (AES-256-GCM per 4 KiB block, AES-SIV filenames)
- Windows Hello / Linux biometric unlock, with passphrase-only fallback
- Mounts as a drive letter (Windows, WinFsp) or FUSE mount (Linux)
- Built-in encrypted markdown editor
- Archon backend over the tpt-archon page cache (feature `archon`, Phase 10)

Targets Windows and Linux for v1. Install steps are in [docs/install.md](docs/install.md); the
user guide is in [docs/user-guide.md](docs/user-guide.md). Part of the TPT Solutions project family; see the
[tpt-archon](https://github.com/tpt-solutions/tpt-archon) platform.

**Status:** pre-alpha. The roadmap is in [todo.md](todo.md); the original design is in
[spec.txt](spec.txt).

## Repository layout

| Path | Purpose |
|------|---------|
| `core/` | Vault format, crypto engine, key management, `VaultBackend` trait |
| `platform-windows/` | Windows Hello, DPAPI/CNG, Credential Manager, WinFsp |
| `platform-linux/` | Secret Service (D-Bus), fprintd, FUSE |
| `platform-archon/` | Archon page-cache backend (feature-gated) |
| `src/` | Frontend (TypeScript + HTML, Vite, no framework) |
| `src-tauri/` | Tauri shell and IPC commands |

## Building

Prerequisites: Rust (version pinned in `rust-toolchain.toml`), Node.js 20.19+ or 22.

```sh
cargo test --workspace
npm ci
npm run build
```

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
Copyright (c) 2026 TPT Solutions. See [CONTRIBUTING.md](CONTRIBUTING.md) for the SPDX header
convention.
