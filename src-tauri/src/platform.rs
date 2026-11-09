// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Per-OS glue for platform unlock. The commands call these functions, so they stay the same on
//! every OS. Where a platform is missing, the functions report it as unavailable and passphrase
//! unlock still works.

use tpt_vault_core::PlatformKey;

use crate::state::AppError;

/// Whether this device can run platform unlock.
#[cfg(windows)]
pub fn supported(window: &tauri::WebviewWindow) -> bool {
    use tpt_vault_core::ConsentGate;
    let hwnd = window.hwnd().map(|h| h.0 as isize).ok();
    let gate = match hwnd {
        Some(raw) => tpt_vault_platform_windows::WindowsHello::for_window(raw),
        None => tpt_vault_platform_windows::WindowsHello::default(),
    };
    gate.is_available()
}

#[cfg(target_os = "linux")]
pub fn supported(_window: &tauri::WebviewWindow) -> bool {
    tpt_vault_platform_linux::platform_unlock_supported()
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn supported(_window: &tauri::WebviewWindow) -> bool {
    false
}

/// Stores a platform key for `vault_id`.
#[cfg(windows)]
pub fn enroll(
    window: &tauri::WebviewWindow,
    vault_id: &str,
    key: &PlatformKey,
) -> Result<(), AppError> {
    let hwnd = window.hwnd().map(|h| h.0 as isize).ok();
    tpt_vault_platform_windows::windows_unlock(hwnd)
        .enroll(vault_id, key)
        .map_err(AppError::from)
}

#[cfg(target_os = "linux")]
pub fn enroll(
    _window: &tauri::WebviewWindow,
    vault_id: &str,
    key: &PlatformKey,
) -> Result<(), AppError> {
    tpt_vault_platform_linux::linux_unlock()
        .map_err(AppError::from)?
        .enroll(vault_id, key)
        .map_err(AppError::from)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn enroll(
    _window: &tauri::WebviewWindow,
    _vault_id: &str,
    _key: &PlatformKey,
) -> Result<(), AppError> {
    Err(AppError::from(
        tpt_vault_core::VaultError::PlatformUnavailable,
    ))
}

/// Removes the stored platform key for `vault_id`. A missing entry is not an error.
#[cfg(windows)]
pub fn remove(window: &tauri::WebviewWindow, vault_id: &str) -> Result<(), AppError> {
    let hwnd = window.hwnd().map(|h| h.0 as isize).ok();
    tpt_vault_platform_windows::windows_unlock(hwnd)
        .remove(vault_id)
        .map_err(AppError::from)
}

#[cfg(target_os = "linux")]
pub fn remove(_window: &tauri::WebviewWindow, vault_id: &str) -> Result<(), AppError> {
    tpt_vault_platform_linux::linux_unlock()
        .map_err(AppError::from)?
        .remove(vault_id)
        .map_err(AppError::from)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn remove(_window: &tauri::WebviewWindow, _vault_id: &str) -> Result<(), AppError> {
    Err(AppError::from(
        tpt_vault_core::VaultError::PlatformUnavailable,
    ))
}

/// Runs the consent check and releases the platform key for `vault_id`. Blocks until the user
/// responds, so call it from a blocking thread.
#[cfg(windows)]
pub fn release(window: &tauri::WebviewWindow, vault_id: &str) -> Result<PlatformKey, AppError> {
    let hwnd = window.hwnd().map(|h| h.0 as isize).ok();
    tpt_vault_platform_windows::windows_unlock(hwnd)
        .unlock(vault_id)
        .map_err(AppError::from)
}

#[cfg(target_os = "linux")]
pub fn release(_window: &tauri::WebviewWindow, vault_id: &str) -> Result<PlatformKey, AppError> {
    tpt_vault_platform_linux::linux_unlock()
        .map_err(AppError::from)?
        .unlock(vault_id)
        .map_err(AppError::from)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn release(_window: &tauri::WebviewWindow, _vault_id: &str) -> Result<PlatformKey, AppError> {
    Err(AppError::from(
        tpt_vault_core::VaultError::PlatformUnavailable,
    ))
}
