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

### Known limitations
- Mounting as a drive (WinFsp on Windows, FUSE on Linux) is not available yet.
- Linux platform code is written but has not been run on a Linux session.
- File creation is not journaled, so a crash during creation can leave an empty file.
- Vault folders are chosen by hand or with the picker. There is no list of recent vaults.
