// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Session state for the running app: the unlocked vault, idle tracking, and the auto-lock
//! policy. It also holds the input checks applied at the IPC boundary.
//!
//! The frontend is untrusted input. Every value it sends is checked here before any vault call.
//! The core library checks paths again, so this is a first line of defence, not the only one.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use serde::Serialize;
use tpt_vault_core::{FsVault, VaultError};

/// A vault mounted for a session. Dropping it removes the mount. Windows mounts with WinFsp
/// (a drive letter), and Linux mounts with FUSE (a folder).
#[cfg(windows)]
pub type DriveMount = tpt_vault_platform_windows::WinFspMount;
#[cfg(target_os = "linux")]
pub type DriveMount = tpt_vault_platform_linux::FuseMount;
#[cfg(not(any(windows, target_os = "linux")))]
pub type DriveMount = std::convert::Infallible;

/// Where a mount goes: a drive letter on Windows, a folder on Linux.
#[cfg(windows)]
pub type MountTarget = char;
#[cfg(target_os = "linux")]
pub type MountTarget = std::path::PathBuf;
#[cfg(not(any(windows, target_os = "linux")))]
pub type MountTarget = ();

/// Whether this build can mount a vault.
pub const MOUNT_SUPPORTED: bool = cfg!(any(windows, target_os = "linux"));

/// Where new mounts go by default: the highest free drive letter on Windows, and a `tpt-vault`
/// folder in the home directory on Linux. None if there is no place to mount.
#[cfg(windows)]
pub fn default_mount_target() -> Option<MountTarget> {
    free_drive_letter()
}

#[cfg(target_os = "linux")]
pub fn default_mount_target() -> Option<MountTarget> {
    let home = std::env::var_os("HOME")?;
    let dir = std::path::PathBuf::from(home).join("tpt-vault");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn default_mount_target() -> Option<MountTarget> {
    None
}

/// Idle time before the vault locks automatically.
pub const DEFAULT_AUTO_LOCK: Duration = Duration::from_secs(10 * 60);
/// Seconds before auto-lock at which the user is warned.
pub const LOCK_WARNING: Duration = Duration::from_secs(60);
pub const MIN_PASSPHRASE_CHARS: usize = 8;
pub const MAX_PASSPHRASE_BYTES: usize = 1024;
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_NOTE_BYTES: usize = 16 * 1024 * 1024;
pub const MIN_AUTO_LOCK_MINUTES: u32 = 1;
pub const MAX_AUTO_LOCK_MINUTES: u32 = 240;

/// An error the frontend can show. `code` is stable and meant for the UI to branch on.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AppError {
    pub code: String,
    pub message: String,
}

impl AppError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        AppError {
            code: code.to_owned(),
            message: message.into(),
        }
    }

    pub fn locked() -> Self {
        AppError::new("locked", "the vault is locked")
    }
}

impl From<VaultError> for AppError {
    fn from(e: VaultError) -> Self {
        let code = match &e {
            VaultError::WrongPassphrase => "wrong_passphrase",
            VaultError::InvalidRecoveryCode => "invalid_recovery_code",
            VaultError::UnsupportedVersion(_) => "unsupported_version",
            VaultError::Corrupt { .. } => "corrupt",
            VaultError::InvalidPath { .. } => "invalid_path",
            VaultError::NameTooLong(_) => "name_too_long",
            VaultError::NotFound(_) => "not_found",
            VaultError::AlreadyExists(_) => "already_exists",
            VaultError::NotAFile(_) => "not_a_file",
            VaultError::NotADirectory(_) => "not_a_directory",
            VaultError::DirectoryNotEmpty(_) => "directory_not_empty",
            VaultError::PlatformUnavailable => "platform_unavailable",
            VaultError::ConsentDenied => "consent_denied",
            VaultError::PlatformNotEnrolled => "platform_not_enrolled",
            VaultError::Platform(_) => "platform",
            VaultError::WriteLimitReached => "write_limit_reached",
            VaultError::Config(_) => "config",
            VaultError::Kdf(_) => "kdf",
            VaultError::Io(_) => "io",
        };
        AppError::new(code, e.to_string())
    }
}

/// The unlocked vault, where it lives, and its drive mount if one is up.
///
/// The mount is declared before the vault, so it is dropped first. Dropping the session therefore
/// removes the drive and then locks the vault.
pub struct Session {
    pub mount: Option<DriveMount>,
    /// Drive letter of the mount, for display.
    /// Where the vault is mounted, for display: a drive such as "V:" or a folder path.
    pub label: Option<String>,
    pub vault: Arc<FsVault>,
    pub root: PathBuf,
}

impl Session {
    pub fn new(vault: FsVault, root: PathBuf) -> Self {
        Session {
            mount: None,
            label: None,
            vault: Arc::new(vault),
            root,
        }
    }
}

/// Shared app state, managed by Tauri.
pub struct AppState {
    session: Mutex<Option<Session>>,
    last_activity: Mutex<Instant>,
    auto_lock: Mutex<Duration>,
    warned: Mutex<bool>,
}

fn lock_or_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while a lock is held should not wedge the app. The data is still valid here,
    // because every critical section leaves it consistent.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            session: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
            auto_lock: Mutex::new(DEFAULT_AUTO_LOCK),
            warned: Mutex::new(false),
        }
    }

    /// Records user activity, which resets the idle timer.
    pub fn touch(&self) {
        *lock_or_recover(&self.last_activity) = Instant::now();
        *lock_or_recover(&self.warned) = false;
    }

    pub fn is_unlocked(&self) -> bool {
        lock_or_recover(&self.session).is_some()
    }

    pub fn root(&self) -> Option<String> {
        lock_or_recover(&self.session)
            .as_ref()
            .map(|s| s.root.to_string_lossy().into_owned())
    }

    /// Makes `session` the current one, replacing any previous session. The old session's keys
    /// are zeroized when it is dropped.
    pub fn install(&self, session: Session) {
        *lock_or_recover(&self.session) = Some(session);
        self.touch();
    }

    /// Locks the vault. Returns whether a session was active.
    pub fn lock(&self) -> bool {
        let previous = lock_or_recover(&self.session).take();
        previous.is_some()
    }

    /// Removes the session and returns it, for operations that consume it (re-key).
    pub fn take_session(&self) -> Option<Session> {
        lock_or_recover(&self.session).take()
    }

    /// Mounts the open vault at `target`. Fails if no vault is open, if it is already mounted,
    /// or if the mount cannot be made.
    pub fn mount_drive(&self, target: MountTarget) -> Result<(), AppError> {
        let mut guard = lock_or_recover(&self.session);
        let session = guard.as_mut().ok_or_else(AppError::locked)?;
        if session.mount.is_some() {
            return Err(AppError::new(
                "already_mounted",
                "the vault is already mounted",
            ));
        }
        let (mount, label) = start_mount(Arc::clone(&session.vault), target)?;
        session.mount = Some(mount);
        session.label = Some(label);
        Ok(())
    }

    /// Removes the mount, if there is one. The vault stays open.
    pub fn unmount_drive(&self) {
        let mut guard = lock_or_recover(&self.session);
        if let Some(session) = guard.as_mut() {
            session.mount = None;
            session.label = None;
        }
    }

    /// Where the open vault is mounted, if it is mounted.
    pub fn mounted_drive(&self) -> Option<String> {
        lock_or_recover(&self.session)
            .as_ref()
            .and_then(|s| s.label.clone())
    }

    /// Whether the open vault's key bytes are pinned in RAM. False when no vault is open.
    pub fn keys_locked(&self) -> bool {
        lock_or_recover(&self.session)
            .as_ref()
            .is_some_and(|s| s.vault.keys_locked())
    }

    /// Write-budget position of the open vault, if one is open. Reading it is not activity.
    pub fn write_budget(&self) -> Option<tpt_vault_core::BudgetStatus> {
        let guard = lock_or_recover(&self.session);
        guard.as_ref().map(|session| session.vault.write_budget())
    }

    /// Runs `f` against the unlocked vault and counts the call as activity.
    pub fn with_vault<T>(
        &self,
        f: impl FnOnce(&FsVault) -> Result<T, VaultError>,
    ) -> Result<T, AppError> {
        let guard = lock_or_recover(&self.session);
        let session = guard.as_ref().ok_or_else(AppError::locked)?;
        self.touch();
        f(&session.vault).map_err(AppError::from)
    }

    pub fn auto_lock(&self) -> Duration {
        *lock_or_recover(&self.auto_lock)
    }

    pub fn set_auto_lock(&self, duration: Duration) {
        *lock_or_recover(&self.auto_lock) = duration;
    }

    pub fn idle_for(&self) -> Duration {
        lock_or_recover(&self.last_activity).elapsed()
    }

    /// Whether the idle limit has passed while unlocked.
    pub fn idle_expired(&self) -> bool {
        self.is_unlocked() && self.idle_for() >= self.auto_lock()
    }

    /// Seconds left before auto-lock, if the warning should be shown now. Returns it once per
    /// idle period.
    pub fn lock_warning_due(&self) -> Option<u64> {
        if !self.is_unlocked() {
            return None;
        }
        let limit = self.auto_lock();
        let idle = self.idle_for();
        if idle + LOCK_WARNING < limit {
            return None;
        }
        let mut warned = lock_or_recover(&self.warned);
        if *warned {
            return None;
        }
        *warned = true;
        Some(limit.saturating_sub(idle).as_secs())
    }
}

/// Rejects paths that are too long or contain NUL. Structure is checked by the core.
/// The highest free drive letter, counting down from Z. None if every letter is taken.
#[cfg(windows)]
pub fn free_drive_letter() -> Option<char> {
    ('D'..='Z')
        .rev()
        .find(|c| !std::path::Path::new(&format!("{c}:\\")).exists())
}

/// Starts a mount on Windows (WinFsp). The label is the drive letter.
#[cfg(windows)]
fn start_mount(vault: Arc<FsVault>, letter: MountTarget) -> Result<(DriveMount, String), AppError> {
    let mount = DriveMount::mount(vault, letter)
        .map_err(|e| AppError::new("mount_failed", e.to_string()))?;
    Ok((mount, format!("{}:", letter.to_ascii_uppercase())))
}

/// Starts a mount on Linux (FUSE). The label is the folder.
#[cfg(target_os = "linux")]
fn start_mount(vault: Arc<FsVault>, dir: MountTarget) -> Result<(DriveMount, String), AppError> {
    let label = dir.display().to_string();
    let mount =
        DriveMount::start(vault, dir).map_err(|e| AppError::new("mount_failed", e.to_string()))?;
    Ok((mount, label))
}

/// No mount backend on this platform.
#[cfg(not(any(windows, target_os = "linux")))]
fn start_mount(
    _vault: Arc<FsVault>,
    _target: MountTarget,
) -> Result<(DriveMount, String), AppError> {
    Err(AppError::new(
        "unsupported",
        "mounting is not available on this platform",
    ))
}

pub fn validate_path(path: &str) -> Result<(), AppError> {
    if path.len() > MAX_PATH_BYTES {
        return Err(AppError::new("invalid_path", "path is too long"));
    }
    if path.contains('\0') {
        return Err(AppError::new(
            "invalid_path",
            "path contains a NUL character",
        ));
    }
    Ok(())
}

/// Passphrase policy for new passphrases: at least 8 characters, and not absurdly long.
pub fn validate_new_passphrase(passphrase: &str) -> Result<(), AppError> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(AppError::new(
            "weak_passphrase",
            format!("the passphrase must be at least {MIN_PASSPHRASE_CHARS} characters"),
        ));
    }
    if passphrase.len() > MAX_PASSPHRASE_BYTES {
        return Err(AppError::new(
            "weak_passphrase",
            "the passphrase is too long",
        ));
    }
    Ok(())
}

pub fn validate_note_size(text: &str) -> Result<(), AppError> {
    if text.len() > MAX_NOTE_BYTES {
        return Err(AppError::new(
            "note_too_large",
            "the note is larger than 16 MiB",
        ));
    }
    Ok(())
}

pub fn validate_auto_lock_minutes(minutes: u32) -> Result<Duration, AppError> {
    if !(MIN_AUTO_LOCK_MINUTES..=MAX_AUTO_LOCK_MINUTES).contains(&minutes) {
        return Err(AppError::new(
            "invalid_setting",
            format!(
                "auto-lock must be between {MIN_AUTO_LOCK_MINUTES} and {MAX_AUTO_LOCK_MINUTES} minutes"
            ),
        ));
    }
    Ok(Duration::from_secs(u64::from(minutes) * 60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_paths_at_the_boundary() {
        assert!(validate_path("notes/today.md").is_ok());
        assert_eq!(validate_path("a\0b").unwrap_err().code, "invalid_path");
        let long = "a".repeat(MAX_PATH_BYTES + 1);
        assert_eq!(validate_path(&long).unwrap_err().code, "invalid_path");
    }

    #[test]
    fn passphrase_policy() {
        assert_eq!(
            validate_new_passphrase("short").unwrap_err().code,
            "weak_passphrase"
        );
        assert!(validate_new_passphrase("eight-chars").is_ok());
        // Eight characters, but more than 1024 bytes.
        let huge = "é".repeat(MAX_PASSPHRASE_BYTES);
        assert_eq!(
            validate_new_passphrase(&huge).unwrap_err().code,
            "weak_passphrase"
        );
    }

    #[test]
    fn auto_lock_is_bounded() {
        assert_eq!(
            validate_auto_lock_minutes(10).unwrap(),
            Duration::from_secs(600)
        );
        assert!(validate_auto_lock_minutes(0).is_err());
        assert!(validate_auto_lock_minutes(MAX_AUTO_LOCK_MINUTES + 1).is_err());
    }

    #[test]
    fn locked_state_refuses_vault_access() {
        let state = AppState::new();
        assert!(!state.is_unlocked());
        let err = state.with_vault(|_| Ok(())).unwrap_err();
        assert_eq!(err.code, "locked");
    }

    #[test]
    fn warning_fires_once_inside_the_window() {
        let state = AppState::new();
        let dir = tempfile::tempdir().unwrap();
        let params = tpt_vault_core::KdfParams {
            log_n: 10,
            r: 8,
            p: 1,
        };
        let (vault, _code) = FsVault::create(dir.path(), b"passphrase-1", params).unwrap();
        state.install(Session::new(vault, dir.path().to_path_buf()));
        state.set_auto_lock(Duration::from_secs(120));

        // Not yet inside the warning window: idle is about zero.
        assert_eq!(state.lock_warning_due(), None);
        // Simulate 90 seconds idle by moving the activity timestamp back.
        *lock_or_recover(&state.last_activity) = Instant::now() - Duration::from_secs(90);
        let remaining = state.lock_warning_due().expect("warning due");
        assert!((29..=31).contains(&remaining), "remaining {remaining}");
        assert_eq!(
            state.lock_warning_due(),
            None,
            "warned once per idle period"
        );
        state.touch();
        assert_eq!(state.lock_warning_due(), None);
    }

    #[test]
    fn idle_expiry_only_applies_while_unlocked() {
        let state = AppState::new();
        state.set_auto_lock(Duration::from_secs(1));
        *lock_or_recover(&state.last_activity) = Instant::now() - Duration::from_secs(5);
        assert!(
            !state.idle_expired(),
            "locked vaults have nothing to expire"
        );
    }
}
