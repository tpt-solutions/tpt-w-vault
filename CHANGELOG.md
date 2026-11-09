# Changelog

All notable changes to tpt-vault are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/) from 1.0.0 onward. Before 1.0.0, minor versions may
change the vault format; see the notes for each release.

## [Unreleased]

### Added
- Core: per-file write-ahead journal. An interrupted write is undone on the next open, stat,
  rename or remove (`core/src/journal.rs`).
- Core: note listing (`notes::list_notes`), markdown notes only, recursive.
- App: unlock screen with passphrase, recovery code, Windows Hello (when available), and vault
  creation with a one-time recovery code.
- App: first-run welcome that explains what a vault is.
- App: folder picker for choosing the vault folder.
- App: vault browser with folder navigation, create, rename and move (one action), and delete.
- App: note editor with debounced autosave, a markdown toolbar, and a live preview.
- App: settings for auto-lock, passphrase change, recovery code renewal, Windows Hello on or
  off, and key rebuild.
- Tray icon with lock action, and locking on idle, window close and quit.
- App: **Forget** on the recent vaults list removes a folder from the list. The vault's files are
  not touched.
- Docs: install guide (`docs/install.md`), recovery code guide (`docs/recovery-key.md`), release
  steps (`docs/release.md`) and post-release triage (`docs/triage.md`).

### Changed
- Linux: the vault can be mounted as a folder through FUSE (`platform-linux/src/fuse.rs`, `fuser` 0.15, MIT). The app mounts on unlock at `~/tpt-vault` and unmounts when the session ends.
- CI: the Linux job installs the GTK, WebKit and FUSE packages it needs, and runs the FUSE self-test.
- Windows: the vault can be mounted as a drive through WinFsp (`platform-windows/src/winfsp`). The app mounts on unlock and unmounts when the session ends. The WinFsp binding is written against WinFsp's API; the GPL `winfsp` crate is not used.
- Core: `VaultBackend` is implemented for `Arc<B>`, so the app and a mount can share one open vault.
- Core: the write count per content key is enforced. Soft limit 2^31 block writes (re-key
  recommended), hard limit 2^32 (writes refused until re-keyed). The count is stored in
  `vault.conf` (`core/src/budget.rs`). Vaults made before this change start at zero.
- Core: creating a file is atomic. The header is written to a temp file and hard-linked into
  place, so a crash leaves no half-made entry.
- Core and platform: key pages are pinned in RAM when the OS allows (`VirtualLock` on Windows,
  `mlock` on Linux). The app warns when it cannot.
- App: the unlock screen lists recent vault folders.
- App: the browser has a "Notes only" filter.
- App: the editor shows the text and a live preview side by side.
- App: the status shows when the vault should be re-keyed or has reached its write limit.

### Removed
- Core: the unused `Autosave` timing type. The editor keeps the autosave timer.

### Fixed
- Writes no longer re-encrypt the rest of the file. A small write in a large file now costs the
  same as in a small one (`docs/performance.md`).
- Names are checked against Windows rules on every platform, so a vault made on Linux still mounts
  on Windows. Refused: the device names (CON, NUL, COM1 to COM9, LPT1 to LPT9, with or without an
  extension), names ending in a dot or space, and the characters `<>"|?*`.
- Streaming writes use 1 MiB chunks instead of 64 KiB, which cuts the number of flushes.

### Known limitations
- Linux platform code is checked by CI (FUSE self-test), but has not been run on a Linux desktop
  session.
- Windows drive mounts need WinFsp installed separately. The installer does not bundle it yet.
- Symbolic links are not supported in the mounted view.
- A killed app process has not been tested for stale mounts on either platform.
