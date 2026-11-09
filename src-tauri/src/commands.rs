// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Tauri command layer: the only way the frontend reaches the vault.
//!
//! Each command is a thin wrapper around an `*_impl` function that takes `&AppState`. The
//! wrappers handle Tauri types, and the `*_impl` functions hold the logic and the tests.

use std::{path::PathBuf, time::Duration};

use serde::Serialize;
use tauri::{State, WebviewWindow};
use tpt_vault_core::{EntryKind, FsVault, KdfParams, VaultBackend, notes};

use crate::platform;
use crate::state::{
    AppError, AppState, Session, validate_auto_lock_minutes, validate_new_passphrase,
    validate_note_size, validate_path,
};

/// KDF cost for new vaults and passphrase changes. Tests use a cheap setting.
fn kdf_for_new_vaults() -> KdfParams {
    #[cfg(test)]
    {
        KdfParams {
            log_n: 10,
            r: 8,
            p: 1,
        }
    }
    #[cfg(not(test))]
    {
        KdfParams::RECOMMENDED
    }
}

#[derive(Debug, Serialize)]
pub struct VaultStatus {
    pub unlocked: bool,
    pub root: Option<String>,
    pub auto_lock_minutes: u64,
    /// The key bytes could not be pinned in RAM, so they may be written to the page file.
    pub keys_locked: bool,
    /// The vault has passed the soft write limit. Offer a key rebuild.
    pub rekey_recommended: bool,
    /// The vault has passed the hard write limit. Saves fail until the keys are rebuilt.
    pub write_limit_reached: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct EntryDto {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

fn root_of(root: &str) -> Result<PathBuf, AppError> {
    validate_path(root)?;
    if root.is_empty() {
        return Err(AppError::new(
            "invalid_path",
            "choose a folder for the vault",
        ));
    }
    Ok(PathBuf::from(root))
}

// --- session -----------------------------------------------------------------

pub fn status_impl(state: &AppState) -> VaultStatus {
    let budget = state.write_budget();
    VaultStatus {
        unlocked: state.is_unlocked(),
        root: state.root(),
        auto_lock_minutes: state.auto_lock().as_secs() / 60,
        keys_locked: state.keys_locked(),
        rekey_recommended: budget.is_some_and(|b| b.soft_reached),
        write_limit_reached: budget.is_some_and(|b| b.hard_reached),
    }
}

/// Creates a vault and leaves it unlocked. Returns the recovery code, to be shown once.
pub fn create_vault_impl(
    state: &AppState,
    root: &str,
    passphrase: &str,
) -> Result<String, AppError> {
    let root = root_of(root)?;
    validate_new_passphrase(passphrase)?;
    let (vault, code) = FsVault::create(&root, passphrase.as_bytes(), kdf_for_new_vaults())
        .map_err(AppError::from)?;
    state.install(Session { vault, root });
    Ok(code.to_string())
}

pub fn unlock_vault_impl(state: &AppState, root: &str, passphrase: &str) -> Result<(), AppError> {
    let root = root_of(root)?;
    let vault = FsVault::open(&root, passphrase.as_bytes()).map_err(AppError::from)?;
    state.install(Session { vault, root });
    Ok(())
}

pub fn unlock_recovery_impl(state: &AppState, root: &str, code: &str) -> Result<(), AppError> {
    let root = root_of(root)?;
    let vault = FsVault::open_with_recovery(&root, code).map_err(AppError::from)?;
    state.install(Session { vault, root });
    Ok(())
}

// --- entries -----------------------------------------------------------------

pub fn list_entries_impl(state: &AppState, path: &str) -> Result<Vec<EntryDto>, AppError> {
    validate_path(path)?;
    let entries = state.with_vault(|v| v.list_dir(path))?;
    Ok(entries
        .into_iter()
        .map(|e| EntryDto {
            name: e.name,
            is_dir: e.kind == EntryKind::Directory,
            size: e.size,
        })
        .collect())
}

pub fn read_note_impl(state: &AppState, path: &str) -> Result<String, AppError> {
    validate_path(path)?;
    state.with_vault(|v| notes::load_note(v, path))
}

pub fn save_note_impl(state: &AppState, path: &str, text: &str) -> Result<(), AppError> {
    validate_path(path)?;
    validate_note_size(text)?;
    state.with_vault(|v| notes::save_note(v, path, text))
}

pub fn create_dir_impl(state: &AppState, path: &str) -> Result<(), AppError> {
    validate_path(path)?;
    state.with_vault(|v| v.create_dir(path))
}

pub fn create_file_impl(state: &AppState, path: &str) -> Result<(), AppError> {
    validate_path(path)?;
    state.with_vault(|v| v.create_file(path).map(|_| ()))
}

pub fn rename_impl(state: &AppState, from: &str, to: &str) -> Result<(), AppError> {
    validate_path(from)?;
    validate_path(to)?;
    state.with_vault(|v| v.rename(from, to))
}

pub fn remove_impl(state: &AppState, path: &str) -> Result<(), AppError> {
    validate_path(path)?;
    state.with_vault(|v| v.remove(path))
}

// --- key management ----------------------------------------------------------

pub fn change_passphrase_impl(state: &AppState, old: &str, new: &str) -> Result<(), AppError> {
    validate_new_passphrase(new)?;
    state.with_vault(|v| v.change_passphrase(old.as_bytes(), new.as_bytes(), kdf_for_new_vaults()))
}

pub fn rotate_recovery_impl(state: &AppState, passphrase: &str) -> Result<String, AppError> {
    state
        .with_vault(|v| v.rotate_recovery_code(passphrase.as_bytes()))
        .map(|code| code.to_string())
}

/// Re-keys the vault. The session is consumed, so the vault is re-opened under the new keys.
/// Returns the new recovery code.
pub fn rekey_impl(state: &AppState, passphrase: &str) -> Result<String, AppError> {
    validate_new_passphrase(passphrase)?;
    let Session { vault, root } = state.take_session().ok_or_else(AppError::locked)?;
    let (vault, code) = vault
        .rekey(passphrase.as_bytes(), kdf_for_new_vaults())
        .map_err(AppError::from)?;
    state.install(Session { vault, root });
    Ok(code.to_string())
}

pub fn set_auto_lock_impl(state: &AppState, minutes: u32) -> Result<(), AppError> {
    let duration: Duration = validate_auto_lock_minutes(minutes)?;
    state.set_auto_lock(duration);
    Ok(())
}

// --- Tauri commands ----------------------------------------------------------

#[tauri::command]
pub fn vault_status(state: State<'_, AppState>) -> VaultStatus {
    status_impl(&state)
}

#[tauri::command]
pub fn create_vault(
    state: State<'_, AppState>,
    root: String,
    passphrase: String,
) -> Result<String, AppError> {
    create_vault_impl(&state, &root, &passphrase)
}

#[tauri::command]
pub fn unlock_vault(
    state: State<'_, AppState>,
    root: String,
    passphrase: String,
) -> Result<(), AppError> {
    unlock_vault_impl(&state, &root, &passphrase)
}

#[tauri::command]
pub fn unlock_with_recovery(
    state: State<'_, AppState>,
    root: String,
    code: String,
) -> Result<(), AppError> {
    unlock_recovery_impl(&state, &root, &code)
}

/// Unlocks with the platform key after the consent check. Runs off the main thread, since the
/// consent prompt blocks until the user responds.
#[tauri::command]
pub async fn unlock_with_platform(
    window: WebviewWindow,
    state: State<'_, AppState>,
    root: String,
) -> Result<(), AppError> {
    let root_path = root_of(&root)?;
    let vault_id = FsVault::read_vault_id(&root_path).map_err(AppError::from)?;
    let key = tauri::async_runtime::spawn_blocking(move || platform::release(&window, &vault_id))
        .await
        .map_err(|e| AppError::new("internal", e.to_string()))??;
    let vault = FsVault::open_with_platform_key(&root_path, &key).map_err(AppError::from)?;
    state.install(Session {
        vault,
        root: root_path,
    });
    Ok(())
}

#[tauri::command]
pub async fn platform_unlock_supported(window: WebviewWindow) -> bool {
    tauri::async_runtime::spawn_blocking(move || platform::supported(&window))
        .await
        .unwrap_or(false)
}

/// Turns on platform unlock. Stores the platform key, and if storing fails, rolls back the
/// vault change so no unreachable key is left behind.
#[tauri::command]
pub fn enable_platform_unlock(
    window: WebviewWindow,
    state: State<'_, AppState>,
    passphrase: String,
) -> Result<(), AppError> {
    // The passphrase is the existing one, not a new one, so only basic input checks apply here.
    if passphrase.is_empty() || passphrase.len() > crate::state::MAX_PASSPHRASE_BYTES {
        return Err(AppError::new("weak_passphrase", "enter your passphrase"));
    }
    let root = state.root().ok_or_else(AppError::locked)?;
    let vault_id = FsVault::read_vault_id(&root).map_err(AppError::from)?;
    let key = state.with_vault(|v| v.enable_platform_unlock(passphrase.as_bytes()))?;
    if let Err(e) = platform::enroll(&window, &vault_id, &key) {
        let _ = state.with_vault(|v| v.disable_platform_unlock(passphrase.as_bytes()));
        return Err(e);
    }
    Ok(())
}

#[tauri::command]
pub fn disable_platform_unlock(
    window: WebviewWindow,
    state: State<'_, AppState>,
    passphrase: String,
) -> Result<(), AppError> {
    let root = state.root().ok_or_else(AppError::locked)?;
    let vault_id = FsVault::read_vault_id(&root).map_err(AppError::from)?;
    state.with_vault(|v| v.disable_platform_unlock(passphrase.as_bytes()))?;
    platform::remove(&window, &vault_id)
}

#[tauri::command]
pub fn lock_vault(state: State<'_, AppState>) {
    state.lock();
}

#[tauri::command]
pub fn touch_activity(state: State<'_, AppState>) {
    state.touch();
}

#[tauri::command]
pub fn list_entries(state: State<'_, AppState>, path: String) -> Result<Vec<EntryDto>, AppError> {
    list_entries_impl(&state, &path)
}

#[tauri::command]
pub fn read_note(state: State<'_, AppState>, path: String) -> Result<String, AppError> {
    read_note_impl(&state, &path)
}

#[tauri::command]
pub fn save_note(state: State<'_, AppState>, path: String, text: String) -> Result<(), AppError> {
    save_note_impl(&state, &path, &text)
}

#[tauri::command]
pub fn create_dir(state: State<'_, AppState>, path: String) -> Result<(), AppError> {
    create_dir_impl(&state, &path)
}

#[tauri::command]
pub fn create_file(state: State<'_, AppState>, path: String) -> Result<(), AppError> {
    create_file_impl(&state, &path)
}

#[tauri::command]
pub fn rename_entry(state: State<'_, AppState>, from: String, to: String) -> Result<(), AppError> {
    rename_impl(&state, &from, &to)
}

#[tauri::command]
pub fn remove_entry(state: State<'_, AppState>, path: String) -> Result<(), AppError> {
    remove_impl(&state, &path)
}

#[tauri::command]
pub fn change_passphrase(
    state: State<'_, AppState>,
    old_passphrase: String,
    new_passphrase: String,
) -> Result<(), AppError> {
    change_passphrase_impl(&state, &old_passphrase, &new_passphrase)
}

#[tauri::command]
pub fn rotate_recovery_code(
    state: State<'_, AppState>,
    passphrase: String,
) -> Result<String, AppError> {
    rotate_recovery_impl(&state, &passphrase)
}

#[tauri::command]
pub fn rekey_vault(state: State<'_, AppState>, passphrase: String) -> Result<String, AppError> {
    rekey_impl(&state, &passphrase)
}

#[tauri::command]
pub fn set_auto_lock_minutes(state: State<'_, AppState>, minutes: u32) -> Result<(), AppError> {
    set_auto_lock_impl(&state, minutes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "first-passphrase";
    const NEW: &str = "second-passphrase";

    fn temp_root() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault").to_string_lossy().into_owned();
        (dir, root)
    }

    #[test]
    fn full_flow_create_edit_rename_remove_lock_unlock() {
        let state = AppState::new();
        let (_dir, root) = temp_root();
        let code = create_vault_impl(&state, &root, PASS).unwrap();
        assert!(code.contains('-'), "recovery code is grouped for display");
        assert!(status_impl(&state).unlocked);

        create_dir_impl(&state, "notes").unwrap();
        save_note_impl(&state, "notes/a.md", "# A\nbody").unwrap();
        assert_eq!(read_note_impl(&state, "notes/a.md").unwrap(), "# A\nbody");
        rename_impl(&state, "notes/a.md", "notes/b.md").unwrap();
        let names: Vec<String> = list_entries_impl(&state, "notes")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["b.md"]);
        remove_impl(&state, "notes/b.md").unwrap();

        state.lock();
        assert_eq!(read_note_impl(&state, "notes").unwrap_err().code, "locked");
        let wrong = unlock_vault_impl(&state, &root, "not-the-passphrase").unwrap_err();
        assert_eq!(wrong.code, "wrong_passphrase");
        unlock_vault_impl(&state, &root, PASS).unwrap();
        assert!(status_impl(&state).unlocked);
    }

    #[test]
    fn recovery_code_and_passphrase_change_and_rekey() {
        let state = AppState::new();
        let (_dir, root) = temp_root();
        let code = create_vault_impl(&state, &root, PASS).unwrap();
        create_file_impl(&state, "keep.txt").unwrap();
        save_note_impl(&state, "keep.txt", "still here").unwrap();

        change_passphrase_impl(&state, PASS, NEW).unwrap();
        state.lock();
        assert_eq!(
            unlock_vault_impl(&state, &root, PASS).unwrap_err().code,
            "wrong_passphrase"
        );
        unlock_recovery_impl(&state, &root, &code).unwrap();
        assert_eq!(read_note_impl(&state, "keep.txt").unwrap(), "still here");

        let new_code = rekey_impl(&state, NEW).unwrap();
        assert_ne!(new_code, code);
        state.lock();
        unlock_vault_impl(&state, &root, NEW).unwrap();
        assert_eq!(read_note_impl(&state, "keep.txt").unwrap(), "still here");
        state.lock();
        assert_eq!(
            unlock_recovery_impl(&state, &root, &code).unwrap_err().code,
            "wrong_passphrase",
            "old recovery code stops working after re-key"
        );
    }

    #[test]
    fn boundary_checks_run_before_the_vault_is_touched() {
        let state = AppState::new();
        let (_dir, root) = temp_root();
        assert_eq!(
            create_vault_impl(&state, &root, "short").unwrap_err().code,
            "weak_passphrase"
        );
        assert_eq!(
            create_vault_impl(&state, "", PASS).unwrap_err().code,
            "invalid_path"
        );
        assert!(!state.is_unlocked());
        create_vault_impl(&state, &root, PASS).unwrap();
        assert_eq!(
            save_note_impl(&state, "../escape", "x").unwrap_err().code,
            "invalid_path"
        );
        assert_eq!(
            save_note_impl(&state, "vault.conf", "x").unwrap_err().code,
            "invalid_path"
        );
        assert_eq!(
            set_auto_lock_impl(&state, 0).unwrap_err().code,
            "invalid_setting"
        );
    }

    #[test]
    fn oversized_notes_are_refused() {
        let state = AppState::new();
        let (_dir, root) = temp_root();
        create_vault_impl(&state, &root, PASS).unwrap();
        let too_big = "a".repeat(crate::state::MAX_NOTE_BYTES + 1);
        assert_eq!(
            save_note_impl(&state, "big.md", &too_big).unwrap_err().code,
            "note_too_large"
        );
    }
}
