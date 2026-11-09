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
- **Filename encryption**: AES-SIV (RFC 5297), deterministic so directory listings stay stable
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

Decisions made 2026-11-10:
- **Platforms for v1**: Windows and Linux both ship. Linux is checked on GitHub Actions, not on a local Linux machine.
- **Archon (Phase 10)**: deferred past v1.
- **Drag-and-drop import (Phase 9)**: deferred past v1.
- **WinFsp (Phase 5)**: approved for install on the dev machine. Mounting is in v1.
- **Repository**: https://github.com/tpt-solutions/tpt-w-vault (origin).
- **Nonce budget**: enforced in code. Limits and the stored counter are in `docs/crypto.md`.
- **Filename cipher**: AES-SIV (RFC 5297). The roadmap has been updated to match.
- **Windows key protection**: DPAPI, not CNG.
- **Journal**: one journal per `write_at` is kept. The cost is measured in `docs/performance.md`.
- **Vaults**: one open at a time, with a recent-vaults list on the unlock screen.
- **Autosave timer**: lives in the editor. The unused core `Autosave` type was removed.
- **Key memory**: keys are pinned in RAM when the OS allows (`VirtualLock` / `mlock`). The app warns when it cannot.

---

## Status Summary

| Phase | Area | Progress |
|-------|------|----------|
| 0  | Project Setup & Licensing                          | 🟡 In Progress (local items done) |
| 1  | Core Vault Format & Crypto Engine                  | 🟡 In Progress (core implemented, tested) |
| 2  | Key Management & Unlock Flows                      | 🟡 In Progress (key pages pinned; plaintext buffers open) |
| 3  | Windows Platform Integration                       | 🟡 In Progress (Hello prompt unverified by hand) |
| 4  | Linux Platform Integration                         | 🟡 In Progress (untested on Linux) |
| 5  | Windows Mount Backend                              | 🟡 Mount works and passes a file-operation self-test; crash-unmount and reserved names open |
| 6  | Linux Mount Backend                                | 🟡 Mount passes the file-operation self-test on a Linux kernel; crash cleanup open |
| 7  | Secure Markdown Editor                             | ✅ Done (live preview, toolbar, notes-only filter) |
| 8  | Tauri Shell & IPC Layer                             | 🟡 Built and tested (tray and lock flow not yet checked by hand) |
| 9  | Frontend (Vault Browser / Editor / Settings)       | 🟡 In Progress (drag-and-drop deferred; vault management open) |
| 10 | Archon Support (Real Page-Cache Integration)       | ⏸ Deferred past v1 |
| 11 | Performance & Polish                               | 🟡 In Progress (crypto throughput profiled and fixed; see `docs/performance.md`) |
| 12 | Testing & QA                                       | ❌ Not Started |
| 13 | Release v1                                         | ❌ Not Started |

---

## Phase 0 — Project Setup & Licensing
- [x] Init git repo, `.gitignore` (Rust + Node/Tauri targets + Windows/Linux build artifacts)
- [x] Add `LICENSE-MIT` and `LICENSE-APACHE` (dual license, TPT Solutions copyright)
- [x] Add SPDX dual-license header/notice convention for source files (see `CONTRIBUTING.md`)
- [x] Cargo workspace: `core/`, `platform-windows/`, `platform-linux/`, `platform-archon/`
      (skeleton crate), `src-tauri/` (Phase 8 app crate); `src/` (Vite) done; shared
      `[workspace.package]` done
- [x] `rust-toolchain.toml` (MSRV pin), `rustfmt.toml`, `clippy.toml`
- [x] Configure `tauri.conf.json` (app id, window defaults, bundle identifiers) — Phase 8
- [x] TypeScript config (tsconfig, Vite, no framework)
- [x] `README.md` (from spec.txt), build instructions (license badges still to add)
- [x] Set up CI (GitHub Actions, build+lint+test on Windows + Linux runners) — workflow file
      added at `.github/workflows/ci.yml`; not yet run on GitHub
- [x] Repo hosting under `tpt-solutions` GitHub org (https://github.com/tpt-solutions/tpt-w-vault)

## Phase 1 — Core Vault Format & Crypto Engine
- [x] `vault.conf`-style config file format: scrypt KDF parameters, wrapped master key
      (AES-256-GCM), vault format version (`core/src/config.rs`)
- [x] Per-file content encryption: fixed 4 KiB block size, AES-256-GCM per block with inline
      nonce+tag, streaming encrypt/decrypt so large files never load fully into memory
      (`core/src/file.rs`, `core/src/block.rs`)
- [x] Filename encryption: AES-SIV over path segments, base64url-safe encoding for on-disk
      names. Deviation: AES-SIV in the `aes-siv` crate is SIV (RFC 5297), not EME mode. Kept.
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
- [x] Nonce budget: soft 2^31 and hard 2^32 block writes per content key, enforced in
      `core/src/budget.rs`. The count is a ceiling stored in `vault.conf`, raised in 2^20 steps
      (see `docs/crypto.md`)
- [x] Crash consistency: writes that change existing records, and truncations, run under a
      write-ahead journal (`core/src/journal.rs`). An interrupted write is undone on the next
      open, stat, rename or remove. Tests simulate crashes and errors mid-write
      (`journal::tests`). File creation is atomic (temp file, then hard link). Each write fsyncs
      twice (see `docs/crypto.md`, "Known gaps"; cost in `docs/performance.md`)
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
      the session. Key pages are pinned with VirtualLock / mlock when the OS allows
      (`core/src/keys.rs`, `platform-*/src/memory.rs`). The app warns when it cannot. Not done:
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
- [x] WinFsp integration: own FFI over `winfsp-x64.dll` (`platform-windows/src/winfsp/`),
      loaded at run time with `libloading`. Layouts follow WinFsp's public API header. The
      GPL `winfsp` crate is not used, so no GPL code is in the tree.
- [x] Virtual drive letter lifecycle: the app mounts on unlock at the highest free letter, and
      unmounts when the session ends (lock, idle, tray, exit). Settings can mount and unmount by
      hand. A mount that fails leaves the vault open without a drive.
- [~] Handle Windows-specific filesystem semantics. The shared inode layer
      (`core/src/mount.rs`) covers rename and replace rules. Not yet handled: reserved device
      names (CON, NUL, ...), trailing dots and spaces, and attributes
- [ ] Clean unmount on crash/forced app termination (no orphaned drive letters). Not tested.
      A killed process should drop the drive when WinFsp notices the device is gone, but that is
      unverified.
- [~] Integration tests: file CRUD (create, read, write, rename, list, delete) and a 300 KB file
      through the drive, with the data checked after unmount, pass in
      `platform-windows/examples/mount_selftest.rs`. Not automated: it needs WinFsp and a drive
      letter. Crash-unmount recovery is not tested.

## Phase 6 — Linux Mount Backend
- [x] FUSE integration via `fuser` 0.15 (MIT). The adapter (`platform-linux/src/fuse.rs`)
      runs over the inode layer in `core/src/mount.rs`. It compiles and passes the file-operation
      self-test on a Linux kernel (the container run and the CI Linux job)
- [x] Mount point lifecycle: the app mounts on unlock at `~/tpt-vault` and unmounts when the
      session ends (lock, idle, tray, exit). The mount runs on a background thread (`FuseMount`),
      and `Drop` unmounts it. The app's lock and exit paths were not run by hand on Linux
- [~] Handle POSIX semantics. Rename, replace, and inode stability are covered. Permissions
      are fixed by the vault (0700 directories, 0600 files). Symlinks are not supported
- [~] Clean unmount on crash/forced app termination (no stale mount points). `AutoUnmount` is
      set in the adapter. A normal unmount leaves the mount point clean. A killed process has not
      been tested yet
- [~] Integration tests: file CRUD through the FUSE mount and a 300 KB file, with the data
      checked after unmount, pass in `platform-linux/examples/mount_selftest.rs`, which runs in
      the CI Linux job. Crash-unmount recovery is not tested

## Phase 7 — Secure Markdown Editor
- [x] In-app markdown editor component (edit + live preview) operating directly on vault entries
      (no plaintext temp files on disk). `src/editor.ts` shows the text and a rendered preview side
      by side, updated 150 ms after typing. The preview can be hidden. Stacks on narrow screens
- [x] Autosave into the vault format on a debounce interval. The editor debounces saves
      (`src/editor.ts`, same timing as `Autosave` in `core/src/notes.rs`), and each save goes
      through `save_note` to the encrypted write path. The core `Autosave` type is not used by
      the app; the timer lives in the editor
- [x] Note list/browser view scoped to markdown files within the open vault. A "Notes only"
      toggle in the browser shows `.md` notes and keeps folders visible. Default is all entries.
      Core listing (`notes::list_notes`) exists but the browser does not call it yet
- [x] Basic markdown authoring features: headings, lists, code blocks, links, tables. The editor
      toolbar inserts each one (`src/editor.ts`), and the renderer in `src/markdown.ts` shows them
- [x] Unit tests: autosave debounce correctness (`notes.rs`), no-plaintext-on-disk verification
      (`core/tests/notes.rs`)

## Phase 8 — Tauri Shell & IPC Layer
- [x] Tauri app scaffold wired to `core` (`VaultBackend`, key management) (`src-tauri/`)
- [x] Command layer: vault create/unlock/lock, file browser operations, editor save/load
      (`src-tauri/src/commands.rs`). Each command is a thin wrapper over a tested `*_impl`
- [~] Event push from Rust to frontend. `vault-locked` and `lock-warning` are emitted, and the
      frontend listens for both (`src/main.ts`). Mount status is not pushed yet (Phase 5/6)
- [~] System tray icon with quick actions (lock vault now, open vault). Built into `main.rs`.
      Not yet checked by clicking through it on the dev machine
- [x] Auto-lock on idle timeout (configurable) (`state.rs`, with bounded values and tests)
- [x] IPC boundary tests: invalid paths, NUL bytes, over-long paths, `../` traversal, and
      locked-state refusal, all checked before the vault is touched (`commands.rs` tests)

## Phase 9 — Frontend (Vault Browser / Editor / Settings)
- [x] App shell (plain TS/HTML + Vite), light/dark theme (`src/style.css`, tokens on `:root`)
- [x] Unlock screen: passphrase entry, Windows Hello trigger (shown when supported), recovery
      code entry, and new-vault creation with a one-time recovery code screen (`src/unlock.ts`)
- [~] Vault browser: folder navigation, create note/folder, rename, delete (two-step confirm),
      lock button (`src/browser.ts`). Move works through the rename field, which takes a full
      path. Drag-and-drop import is deferred past v1
- [x] Markdown editor tab wired to Phase 7 (`src/editor.ts`): textarea with a formatting toolbar,
      a live side-by-side preview, debounced autosave, and a visible save status
- [~] Settings (`src/settings.ts`): auto-lock timeout, passphrase change, recovery code rotation,
      Windows Hello on or off, and key rebuild. Recent vaults are listed on the unlock screen (one vault open
      at a time). Not done: forgetting or renaming recent vaults
- [x] First-run vault creation wizard (explains what a vault is, in plain non-technical language,
      per spec.txt's "less intimidating than VeraCrypt" goal). Shown on first run, from
      `src/wizard.ts`. Folder picker is the native dialog (`tauri-plugin-dialog`)

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
- [x] Profile crypto engine throughput (block encrypt/decrypt, streaming large-file performance).
      Found and fixed: writes re-encrypted the rest of the file, and streaming chunks were 64 KiB.
      Results in `docs/performance.md`. Journal flush cost measured and accepted there
- [ ] App icon, branding assets (TPT Solutions)
- [ ] First-run onboarding polish (vault creation wizard, unlock method setup)
- [ ] Crash reporting / local error logging (opt-in only). Not built yet. If built: local only,
      off by default, and never note text, names or paths
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
- [~] Data-loss recovery test: forced crash mid-write, verify vault integrity/recoverable state.
      Covered at the file layer with simulated crashes (`journal::tests`). Not yet a test of a
      killed process, or of the Tauri app

## Phase 13 — Release v1
- [x] Finalize versioning scheme (SemVer) and changelog process (policy in the `CHANGELOG.md`
      header; release steps still to write)
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
