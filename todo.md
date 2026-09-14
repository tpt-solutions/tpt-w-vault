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
| 0  | Project Setup & Licensing                          | ❌ Not Started |
| 1  | Core Vault Format & Crypto Engine                  | ❌ Not Started |
| 2  | Key Management & Unlock Flows                      | ❌ Not Started |
| 3  | Windows Platform Integration                       | ❌ Not Started |
| 4  | Linux Platform Integration                         | ❌ Not Started |
| 5  | Windows Mount Backend                              | ❌ Not Started |
| 6  | Linux Mount Backend                                | ❌ Not Started |
| 7  | Secure Markdown Editor                             | ❌ Not Started |
| 8  | Tauri Shell & IPC Layer                             | ❌ Not Started |
| 9  | Frontend (Vault Browser / Editor / Settings)       | ❌ Not Started |
| 10 | Archon Support (Real Page-Cache Integration)       | ❌ Not Started |
| 11 | Performance & Polish                               | ❌ Not Started |
| 12 | Testing & QA                                       | ❌ Not Started |
| 13 | Release v1                                         | ❌ Not Started |

---

## Phase 0 — Project Setup & Licensing
- [ ] Init git repo, `.gitignore` (Rust + Node/Tauri targets + Windows/Linux build artifacts)
- [ ] Add `LICENSE-MIT` and `LICENSE-APACHE` (dual license, TPT Solutions copyright)
- [ ] Add SPDX dual-license header/notice convention for source files
- [ ] Cargo workspace: `core/` (vault format, crypto engine, key management, `VaultBackend`
      trait), `platform-windows/`, `platform-linux/`, `platform-archon/`, `src-tauri/`, `src/`
      (TS/HTML frontend, Vite); shared `[workspace.package]` (`license`, `authors = ["TPT
      Solutions"]`, `repository`)
- [ ] `rust-toolchain.toml` (MSRV pin), `rustfmt.toml`, `clippy.toml`
- [ ] Configure `tauri.conf.json` (app id, window defaults, bundle identifiers)
- [ ] TypeScript config (tsconfig, Vite, no framework)
- [ ] `README.md` (from spec.txt), build instructions, license badges
- [ ] Set up CI (GitHub Actions, build+lint+test on Windows + Linux runners)
- [ ] Repo hosting under `tpt-solutions` GitHub org

## Phase 1 — Core Vault Format & Crypto Engine
- [ ] `vault.conf`-style config file format: scrypt KDF parameters, wrapped master key
      (AES-256-GCM), vault format version
- [ ] Per-file content encryption: fixed 4 KiB block size, AES-256-GCM per block with inline
      nonce+tag, streaming encrypt/decrypt so large files never load fully into memory
- [ ] Filename encryption: AES-SIV (EME mode) over path segments, base64url-safe encoding for
      on-disk names
- [ ] Directory structure mapping: encrypted vault tree mirrors plaintext tree shape (encrypted
      names), directory IV/metadata handling
- [ ] Shared `trait VaultBackend` (open/create vault, read/write/list/rename/delete entries,
      streaming file handles) so mount backends (Phase 5/6) and Archon (Phase 10) share one
      interface
- [ ] Integrity: per-block GCM tag verification on read, corrupt-block error surfaced distinctly
      from "wrong key"
- [ ] Core unit tests: round-trip encrypt/decrypt, tamper detection, large-file streaming,
      filename encryption collisions

## Phase 2 — Key Management & Unlock Flows
- [ ] Master key generation (CSPRNG), lifecycle: create vault, unlock, lock, re-key
- [ ] Passphrase-based unlock: scrypt-derive a wrapping key from passphrase, unwrap master key
- [ ] Passphrase change: re-wrap master key without touching file contents
- [ ] Recovery key / paper backup: generate a human-writable recovery code that can unwrap the
      master key independent of passphrase or platform unlock method
- [ ] Session key handling: master key held only in locked/zeroized memory (`zeroize` crate) while
      vault is mounted, cleared on lock/app exit
- [ ] Unit tests: passphrase change round-trip, recovery key round-trip, memory zeroization checks

## Phase 3 — Windows Platform Integration
- [ ] Windows Hello gate via `Windows.Security.Credentials.UI.UserConsentVerifier`
      (`RequestVerificationAsync`) protecting a CNG/DPAPI-wrapped key blob
- [ ] Windows Credential Manager storage for the platform-wrapped key
- [ ] Fallback path when Windows Hello is unavailable (passphrase-only unlock)
- [ ] Unit/integration tests against a mockable Windows Hello/DPAPI boundary (CI-safe)

## Phase 4 — Linux Platform Integration
- [ ] Secret Service client via `zbus` (D-Bus `org.freedesktop.secrets`) for storing the
      platform-wrapped key in GNOME Keyring/KWallet
- [ ] Biometric gating via `fprintd` D-Bus API where available; PAM fingerprint integration
      documented for system-level unlock flows
- [ ] Fallback path when no Secret Service provider or fingerprint reader is available
      (passphrase-only unlock)
- [ ] Verify behavior across at least one GNOME and one KDE session
- [ ] Unit tests: Secret Service round-trip (mocked D-Bus), fallback detection

## Phase 5 — Windows Mount Backend
- [ ] WinFsp integration (Rust bindings) implementing a filesystem provider backed by
      `VaultBackend`
- [ ] Virtual drive letter assignment/lifecycle (mount on unlock, unmount on lock/app exit)
- [ ] Handle Windows-specific filesystem semantics (attributes, reserved names, path length)
- [ ] Clean unmount on crash/forced app termination (no orphaned drive letters)
- [ ] Integration tests: file CRUD through the mounted drive, large-file streaming, crash-unmount
      recovery

## Phase 6 — Linux Mount Backend
- [ ] FUSE integration via the `fuser` crate implementing a filesystem provider backed by
      `VaultBackend`
- [ ] Mount point lifecycle (mount on unlock, unmount on lock/app exit)
- [ ] Handle POSIX filesystem semantics (permissions, symlinks within vault, path length)
- [ ] Clean unmount on crash/forced app termination (no stale mount points)
- [ ] Integration tests: file CRUD through the FUSE mount, large-file streaming, crash-unmount
      recovery

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
