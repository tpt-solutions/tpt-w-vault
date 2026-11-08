# tpt-vault — Project Checklist

TPT Solutions — dual-licensed under MIT OR Apache-2.0.
Local-first encrypted vault and secure markdown notes editor (VeraCrypt alternative for
non-technical users). Rust core (gocryptfs-style per-file AEAD encryption engine, key management)
+ Tauri UI (plain TS/HTML frontend). Targets Windows and Linux for v1, with a real (not stubbed)
Archon backend built on tpt-archon's existing capability-gated page cache — tpt-archon-core has no
crypto of its own, so tpt-vault's own crypto layer sits on top of it.

Reference: Archon platform — https://github.com/tpt-solutions/tpt-archon

Decisions locked in for this roadmap:
- **Per-file, gocryptfs-style vault format**, not a monolithic VeraCrypt-style volume file and not
  a SQLite blob store. Each vault entry is its own encrypted file on disk (content + filename both
  encrypted), which keeps crash-safety simple and makes the vault directory friendly to ordinary
  file-level cloud sync tools.
- **Content encryption**: AES-256-GCM per fixed-size block (4 KiB), nonce+tag stored inline per
  block, so partial-file reads/writes never require re-encrypting the whole file.
- **Filename encryption**: AES-SIV (EME mode), deterministic so directory listings stay stable
  without leaking plaintext names.
- **Master key wrapping**: a `vault.conf`-style config file (gocryptfs-style) holding the
  scrypt-derived-key-wrapped master key; passphrase change re-wraps the master key without
  re-encrypting file contents.
- **Windows unlock**: Windows Hello gates release of a CNG/DPAPI-protected key via
  `Windows.Security.Credentials.UI.UserConsentVerifier`, stored through Windows Credential Manager.
  No custom kernel driver.
- **Linux unlock**: key material stored via the Secret Service API (`zbus` + D-Bus
  `org.freedesktop.secrets`, GNOME Keyring/KWallet), biometric gating via `fprintd` D-Bus + PAM
  fingerprint where available.
- **Windows mount**: WinFsp (user-mode filesystem driver, Rust bindings) exposes the unlocked vault
  as a virtual drive letter — no custom kernel driver, matching tpt-netguard's driver-avoidance
  philosophy.
- **Linux mount**: FUSE via the `fuser` crate, matching spec.txt.
- **Archon integration is real, not design-only, but scoped to storage.** Investigation of the
  freshly-cloned `tpt-archon` repo confirmed `tpt-archon-bridge`'s `Capability`/`Resource::Page`
  and `UnifiedPageCache` (`map_read`/`map_write`/`unmap` over `CorePageCache<D: BlockDevice>`) are
  real and working today — but `tpt-archon-core` has zero cryptographic dependencies (only
  `memmap2`) and there is no `Resource::Block`/`Volume` variant for block-level encrypted storage.
  So the `platform-archon` backend implements tpt-vault's own crypto engine (Phase 1) layered over
  Archon's real page-cache/capability API for storage, rather than waiting on upstream primitives
  that don't exist yet. A `docs/archon-design.md` proposes a future `Resource::Block` and
  hardware-backed crypto primitive upstream, feature-flagged so real Archon-native crypto can swap
  in later.

---

## Status Summary

| Phase | Area | Progress |
|-------|------|----------|
| 0  | Project Setup & Licensing                          | 🟡 In Progress (local items done) |
| 1  | Core Vault Format & Crypto Engine                  | 🟡 In Progress (core implemented, tested) |
| 2  | Key Management & Unlock Flows                      | 🟡 In Progress (re-key, mlock open) |
| 3  | Windows Platform Integration                       | 🟡 In Progress (Hello prompt unverified by hand) |
| 4  | Linux Platform Integration                         | 🟡 In Progress (untested on Linux) |
| 5  | Windows Mount Backend                              | ⛔ Blocked (WinFsp not installed; needs approval) |
| 6  | Linux Mount Backend                                | 🟡 In Progress (adapter uncompiled; needs Linux) |
| 7  | Secure Markdown Editor                             | ❌ Not Started |
| 8  | Tauri Shell & IPC Layer                             | ❌ Not Started |
| 9  | Frontend (Vault Browser / Editor / Settings)       | ❌ Not Started |
| 10 | Archon Support (Real Page-Cache Integration)       | ❌ Not Started |
| 11 | Performance & Polish                               | ❌ Not Started |
| 12 | Testing & QA                                       | ❌ Not Started |
| 13 | Release v1                                         | ❌ Not Started |

---

## Phase 0 — Project Setup & Licensing
- [x] Init git repo, `.gitignore` (Rust + Node/Tauri targets + Windows/Linux build artifacts)
- [x] Add `LICENSE-MIT` and `LICENSE-APACHE` (dual license, TPT Solutions copyright)
- [x] Add SPDX dual-license header/notice convention for source files (see `CONTRIBUTING.md`)
- [~] Cargo workspace: `core/`, `platform-windows/`, `platform-linux/`, `platform-archon/` done
      (skeleton crates); `src/` (Vite) done; `src-tauri/` deferred to Phase 8; shared
      `[workspace.package]` done
- [x] `rust-toolchain.toml` (MSRV pin), `rustfmt.toml`, `clippy.toml`
- [ ] Configure `tauri.conf.json` (app id, window defaults, bundle identifiers) — Phase 8
- [x] TypeScript config (tsconfig, Vite, no framework)
- [x] `README.md` (from spec.txt), build instructions (license badges still to add)
- [x] Set up CI (GitHub Actions, build+lint+test on Windows + Linux runners) — workflow file
      added at `.github/workflows/ci.yml`; not yet run on GitHub
- [ ] Repo hosting under `tpt-solutions` GitHub org

## Phase 1 — Core Vault Format & Crypto Engine
- [x] `vault.conf`-style config file format: scrypt KDF parameters, wrapped master key
      (AES-256-GCM), vault format version (`core/src/config.rs`)
- [x] Per-file content encryption: fixed 4 KiB block size, AES-256-GCM per block with inline
      nonce+tag, streaming encrypt/decrypt so large files never load fully into memory
      (`core/src/file.rs`, `core/src/block.rs`)
- [x] Filename encryption: AES-SIV over path segments, base64url-safe encoding for on-disk
      names. Deviation: AES-SIV in the `aes-siv` crate is SIV (RFC 5297), not EME mode.
      Names over 175 bytes are rejected (no long-name files yet)
- [x] Directory structure mapping: encrypted vault tree mirrors plaintext tree shape.
      Decision: no per-directory IV file. SIV is deterministic and each segment is encrypted
      independently, so renames and moves need no re-encryption. Trade-off: equal names in
      different directories produce equal encrypted segments
- [x] Shared `trait VaultBackend` (create/list/stat/rename/remove, random-access `VaultFile`
      handles, streaming copy helpers) (`core/src/backend.rs`)
- [x] Integrity: per-block GCM tag verification on read, corrupt-block error surfaced distinctly
      from "wrong key" (`VaultError::Corrupt` vs `VaultError::WrongPassphrase`). Block AAD binds
      file id, block index and last-block flag, so reordering and truncation are detected
- [x] Core unit tests: round-trip encrypt/decrypt, tamper detection, large-file streaming,
      filename encryption collisions (`core/tests/vault.rs`, 22 integration tests)
- [x] Long filenames: encrypted names over 255 bytes use hashed `longname.*` entries with a
      verified `.name` sidecar (`core/src/fsvault.rs`). Plaintext segments up to 255 bytes work
- [~] Nonce budget: policy written in `docs/crypto.md` (soft 2^31, hard 2^32 block writes per
      content key). Not enforced in code: the write count needs persisting per key
- [ ] Crash consistency: an interrupted multi-block extend can leave the old last block
      sealed as non-final, so the file reads as `Corrupt`. Needs a write-ahead journal (see
      `docs/crypto.md`, "Known gaps")
- [x] Zeroize plaintext buffers in the file layer (`Zeroizing<Vec<u8>>`). Caller buffers are
      not covered

## Phase 2 — Key Management & Unlock Flows
- [x] Master key generation (CSPRNG), lifecycle: create vault, unlock, lock
- [x] Re-key: `FsVault::rekey` copies the vault into a sibling directory under new keys, then
      swaps it in. The original is untouched until the copy completes. Peak disk use is
      about 2x the vault size
- [x] Passphrase-based unlock: scrypt-derive a wrapping key from passphrase, unwrap master key
- [x] Passphrase change: re-wrap master key without touching file contents (verified byte-for-byte
      in `core/tests/keys.rs`)
- [x] Recovery key / paper backup: 256-bit secret shown as 55 Crockford base32 characters with a
      checksum (`core/src/recovery.rs`). Wraps the master key via HKDF, independent of the
      passphrase. Rotatable with `rotate_recovery_code`
- [~] Session key handling: the master key and subkeys are zeroized on drop, and `lock()` ends
      the session. Not done: page locking (mlock/VirtualLock) to keep keys out of swap, and
      zeroizing transient plaintext buffers (tracked under Phase 1)
- [x] Unit tests: passphrase change round-trip, recovery key round-trip (`core/tests/keys.rs`),
      wipe check (`keys.rs`). The wipe test calls the same zeroize as Drop, but it does not
      observe memory after drop

## Phase 3 — Windows Platform Integration
- [~] Windows Hello gate via `UserConsentVerifier` (`platform-windows/src/hello.rs`).
      Availability is confirmed on the dev machine. The prompt itself has not been approved by
      a person yet. Protection is DPAPI, not CNG: DPAPI is user-bound and needs no key-store
      setup, and it is what the roadmap's "CNG/DPAPI" line allows
- [x] Windows Credential Manager storage for the platform-wrapped key (`credman.rs`), verified
      live on the dev machine
- [x] Fallback path when Windows Hello is unavailable: `VaultError::PlatformUnavailable`
      from `PlatformUnlock`. Passphrase unlock is unaffected. UI wiring is Phase 9
- [x] Unit/integration tests against a mockable boundary: the orchestration is tested with
      fakes in `core/src/platform.rs`, and `core/tests/platform.rs` covers the vault-level flow.
      Live DPAPI and Credential Manager round trips run in `platform-windows`

## Phase 4 — Linux Platform Integration
- [~] Secret Service client via `zbus` (`platform-linux/src/secret_service.rs`) for storing
      the platform key in GNOME Keyring/KWallet. Written against the spec, and compiles on
      all platforms. Not yet run against a live keyring: the dev machine is Windows, and no
      Linux session is available here. Interactive keyring prompts are not supported
- [~] Biometric gating via `fprintd` (`platform-linux/src/fprintd.rs`), written against the
      `net.reactivated.Fprint` API, with the same caveat. PAM integration for system-level
      unlock is not started
- [x] Fallback path when no Secret Service provider or fingerprint reader is available:
      `platform_unlock_supported()` returns false, and `linux_unlock()` fails without a bus
- [ ] Verify behavior across at least one GNOME and one KDE session (needs real Linux sessions)
- [~] Unit tests: fallback detection and the key passthrough are tested. The Secret Service
      round trip needs a live bus or a mock of the D-Bus layer, which is not built yet

## Phase 5 — Windows Mount Backend
- [ ] WinFsp integration (Rust bindings) implementing a filesystem provider backed by
      `VaultBackend`. **Blocked:** WinFsp is not installed on the dev machine. Installing its
      driver is a system change that needs your approval
- [ ] Virtual drive letter assignment/lifecycle (mount on unlock, unmount on lock/app exit).
      Blocked on the same install
- [~] Handle Windows-specific filesystem semantics. The shared inode layer
      (`core/src/mount.rs`) covers rename and replace rules. Not yet handled: reserved device
      names (CON, NUL, ...), trailing dots and spaces, and attributes
- [ ] Clean unmount on crash/forced app termination (no orphaned drive letters). Blocked, as above
- [ ] Integration tests: file CRUD through the mounted drive, large-file streaming, crash-unmount
      recovery. Blocked, as above

## Phase 6 — Linux Mount Backend
- [~] FUSE integration via `fuser`. The inode layer is done and tested (`core/src/mount.rs`).
      The adapter is written (`platform-linux/src/fuse.rs`) but not compiled, since no Linux
      build environment is available. It is not wired into the crate yet, to keep the Linux
      CI job green
- [ ] Mount point lifecycle (mount on unlock, unmount on lock/app exit). Needs a Linux machine
- [~] Handle POSIX semantics. Rename, replace, and inode stability are covered. Permissions
      are fixed by the vault (0700 directories, 0600 files). Symlinks are not supported
- [ ] Clean unmount on crash/forced app termination (no stale mount points). `AutoUnmount` is
      set in the adapter. Unverified until run on Linux
- [ ] Integration tests: file CRUD through the FUSE mount, large-file streaming, crash-unmount
      recovery. Needs a Linux machine

## Phase 7 — Secure Markdown Editor
- [ ] In-app markdown editor component (edit + live preview) operating directly on vault entries
      (no plaintext temp files on disk)
- [ ] Autosave into the vault format on a debounce interval, using Phase 1's streaming
      encrypt/write path
- [ ] Note list/browser view scoped to markdown files within the open vault
- [ ] Basic markdown authoring features: headings, lists, code blocks, links, tables
- [ ] Unit tests: autosave debounce correctness, no-plaintext-on-disk verification

## Phase 8 — Tauri Shell & IPC Layer
- [ ] Tauri app scaffold wired to `core` (`VaultBackend`, key management)
- [ ] Command layer: vault create/unlock/lock, file browser operations, editor save/load
- [ ] Event push from Rust to frontend (mount status, lock timeout warnings)
- [ ] System tray icon with quick actions (lock vault now, open vault)
- [ ] Auto-lock on idle timeout (configurable)
- [ ] IPC boundary tests (command validation, no arbitrary path escape outside the open vault)

## Phase 9 — Frontend (Vault Browser / Editor / Settings)
- [ ] App shell (plain TS/HTML + Vite), light/dark theme
- [ ] Unlock screen: passphrase entry, Windows Hello/biometric prompt trigger, recovery key entry
- [ ] Vault browser: file/folder tree, create/rename/delete/move, drag-and-drop import of external
      files into the vault
- [ ] Markdown editor tab wired to Phase 7
- [ ] Settings: auto-lock timeout, recovery key management, platform unlock method toggle,
      vault location management (create/open additional vaults)
- [ ] First-run vault creation wizard (explains what a vault is, in plain non-technical language,
      per spec.txt's "less intimidating than VeraCrypt" goal)

## Phase 10 — Archon Support (Real Page-Cache Integration)
- [ ] `platform-archon` crate implementing `VaultBackend` over `tpt-archon-bridge`'s
      `UnifiedPageCache` (`map_read`/`map_write`/`unmap`) and `Capability`/`Resource::Page`,
      obtained via `CapabilityIssuer::mint`
- [ ] Layer tpt-vault's own crypto engine (Phase 1) on top of Archon's page cache, since
      `tpt-archon-core` has no cryptographic primitives of its own — pages are encrypted/decrypted
      by tpt-vault before/after `map_write`/`map_read`
- [ ] `docs/archon-design.md`: documents the real integration above, plus a proposal for a future
      `Resource::Block`/`Volume` capability variant and hardware-backed crypto primitive upstream
      in `tpt-archon-core`, so block-level encryption could eventually move into the kernel/core
      layer
- [ ] Cargo feature flag (`archon`) gating this backend; designed so a future upstream hardware
      crypto primitive can be swapped in without changing the `VaultBackend` interface
- [ ] Unit/integration tests against `tpt-archon-bridge`'s test capability issuer (CI-safe, no
      real Archon kernel required)

## Phase 11 — Performance & Polish
- [ ] Profile crypto engine throughput (block encrypt/decrypt, streaming large-file performance)
- [ ] App icon, branding assets (TPT Solutions)
- [ ] First-run onboarding polish (vault creation wizard, unlock method setup)
- [ ] Crash reporting / local error logging (opt-in only)
- [ ] Accessibility pass (keyboard navigation, screen reader labels across all views)

## Phase 12 — Testing & QA
- [ ] Unit tests: crypto engine, key management, filename encryption, mount backends (mocked
      per-platform boundaries)
- [ ] Integration tests: end-to-end create-vault → unlock → mount → file CRUD → lock, across
      Windows and Linux
- [ ] Manual QA: Windows 10/11 (Windows Hello unlock, WinFsp mount cleanup on exit/crash)
- [ ] Manual QA: Linux (X11 + Wayland, at least one GNOME and one KDE session, FUSE mount cleanup
      on exit/crash)
- [ ] Security review: crypto engine correctness (block cipher mode, nonce reuse avoidance, key
      zeroization), mount backend attack surface, IPC command validation, Archon capability
      boundary (no capability forgery/reuse across vaults)
- [ ] Data-loss recovery test: forced crash mid-write, verify vault integrity/recoverable state

## Phase 13 — Release v1
- [ ] Finalize versioning scheme (SemVer) and changelog process
- [ ] Windows installer (MSI/NSIS via Tauri bundler), WinFsp dependency bundling/detection
- [ ] Linux packaging (.deb/.rpm/AppImage via Tauri bundler), documented FUSE/Secret
      Service/fprintd dependency requirements
- [ ] Publish LICENSE files + notices in release artifacts
- [ ] User-facing docs (install guide, vault creation/unlock guide, recovery key guide, privacy
      explainer)
- [ ] Tag v1.0.0 release, publish to GitHub (tpt-solutions org)
- [ ] Post-release triage process for bug reports

---

## Backlog / Future Phases (post-v1)
- [ ] macOS support
- [ ] CLI (scriptable vault create/unlock/mount for power users)
- [ ] Cloud-sync-friendly container variant (conflict-safe per-file layout tuning for
      Dropbox/OneDrive/Syncthing-style sync)
- [ ] Hardware security key (FIDO2/YubiKey) unlock method
- [ ] Real Archon-native hardware-backed crypto once `tpt-archon-core` gains crypto primitives and
      a `Resource::Block`/`Volume` capability variant lands upstream
- [ ] Mobile companion app (view-only vault browser)
