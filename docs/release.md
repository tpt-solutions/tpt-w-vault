# Release steps

This is the checklist for a tagged release, such as v1.0.0. It is written for the maintainer.
Versions follow [SemVer](https://semver.org/). Before 1.0.0, a minor version may change the vault
format, so say so in the changelog.

## Before tagging

1. All phase items for the release are checked off in `todo.md`, or moved to the backlog.
2. `CHANGELOG.md`: move the **Unreleased** entries under a new `## [x.y.z] - YYYY-MM-DD` heading.
   Check the **Known limitations** list is still true.
3. Check the version in `Cargo.toml` (`[workspace.package]`) and `package.json`.
4. If the vault format changed, `docs/crypto.md` and the `vault.conf` version are up to date, and
   the changelog says how older vaults are handled.
5. CI is green on Windows and Linux (`.github/workflows/ci.yml`).
6. Manual checks that CI cannot do are done and recorded in `todo.md` Phase 12: Windows Hello
   unlock, WinFsp mount cleanup, the Linux desktop session checks, and the tray.

## Build the artifacts

1. Windows: build the installer with the Tauri bundler (NSIS or MSI). Confirm the installer
   detects WinFsp, or tells the user where to get it (see `docs/install.md`).
2. Linux: build the `.deb`, `.rpm` and AppImage with the Tauri bundler. Check the package lists
   FUSE 3 and a Secret Service provider as dependencies, or documents them.
3. Include `LICENSE-MIT`, `LICENSE-APACHE` and a third-party notice file in each artifact.
4. Install each artifact on a clean machine and create a vault, lock it, unlock it, and mount it.

## Publish

1. Tag the commit `vX.Y.Z` and push the tag.
2. Create the GitHub release for the tag in the `tpt-solutions` organisation, using the changelog
   section as the notes. Attach the artifacts and their SHA-256 checksums.
3. Link the install and recovery guides from the release notes.

## After tagging

Start the next **Unreleased** section in `CHANGELOG.md`. Follow [triage.md](triage.md) for bug
reports that come in after the release.
