# Installing tpt-vault

tpt-vault runs on Windows and Linux. It works without any extra software. Mounting the vault as a
drive or a folder needs one more component on each platform, described below. If that component
is missing, the vault still opens and you can use it from the app. Only the mount is skipped.

## Windows

1. Install **WinFsp** from <https://winfsp.dev/> (the default options are fine). WinFsp lets the
   app show the vault as a drive letter.
2. Run the tpt-vault installer.
3. Open the app. When you unlock a vault, it appears as a new drive at the highest free letter.

Without WinFsp, the app reports that the drive could not be mounted. Your vault is still open in
the app. Install WinFsp and unlock again to get the drive.

Windows Hello unlock needs Windows Hello to be set up (a PIN, fingerprint or face) in
**Settings → Accounts → Sign-in options**.

## Linux

Install FUSE 3 and make sure your user may mount:

```sh
# Debian and Ubuntu
sudo apt install fuse3
# Fedora
sudo dnf install fuse3
```

- The vault mounts at `~/tpt-vault` when you unlock it, and unmounts when the session ends.
- Unlock with the desktop keyring needs a Secret Service provider, such as GNOME Keyring or
  KWallet. Most desktop sessions already run one.
- Fingerprint unlock needs `fprintd` and an enrolled fingerprint. It is optional.

Linux support has been checked by automated tests on Linux, but not yet on a desktop session.
Please report problems with the issue tracker.

## Building from source

Prerequisites: the Rust toolchain pinned in `rust-toolchain.toml`, and Node.js 20.19+ or 22.

```sh
cargo test --workspace
npm ci
npm run build
```

On Linux, building the app also needs the GTK and WebKit development packages listed in
`.github/workflows/ci.yml`.
