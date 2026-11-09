// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! tpt-vault desktop app: Tauri shell, tray icon, idle auto-lock.
//!
//! Hides the console window in release builds on Windows.
#![cfg_attr(all(not(debug_assertions), windows), windows_subsystem = "windows")]

mod commands;
mod platform;
mod state;

use std::time::Duration;

use tauri::{
    AppHandle, Emitter, Manager, RunEvent, WindowEvent,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
};

use state::AppState;

/// How often the idle watcher checks the timers.
const WATCH_INTERVAL: Duration = Duration::from_secs(5);

fn lock_now(app: &AppHandle, reason: &str) {
    let state = app.state::<AppState>();
    if state.lock() {
        let _ = app.emit("vault-locked", reason);
    }
}

fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Background watcher: warns before the idle limit, and locks at the limit.
fn spawn_idle_watcher(app: AppHandle) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(WATCH_INTERVAL);
            let state = app.state::<AppState>();
            if let Some(seconds) = state.lock_warning_due() {
                let _ = app.emit("lock-warning", seconds);
            }
            if state.idle_expired() {
                lock_now(&app, "idle");
            }
        }
    });
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let show = MenuItemBuilder::with_id("show", "Show tpt-vault").build(app)?;
    let lock = MenuItemBuilder::with_id("lock", "Lock vault").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
    let menu = MenuBuilder::new(app)
        .item(&show)
        .item(&lock)
        .separator()
        .item(&quit)
        .build()?;

    let mut tray = TrayIconBuilder::with_id("main-tray")
        .menu(&menu)
        .tooltip("tpt-vault")
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main(app),
            "lock" => lock_now(app, "tray"),
            "quit" => {
                lock_now(app, "quit");
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click {
                button: tauri::tray::MouseButton::Left,
                button_state: tauri::tray::MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

/// Gives core the platform's way of pinning key pages in RAM. Core cannot call the OS itself.
fn install_page_locker() {
    #[cfg(windows)]
    tpt_vault_core::install_page_locker(tpt_vault_core::PageLocker {
        lock: tpt_vault_platform_windows::lock_pages,
        unlock: tpt_vault_platform_windows::unlock_pages,
    });
    #[cfg(target_os = "linux")]
    tpt_vault_core::install_page_locker(tpt_vault_core::PageLocker {
        lock: tpt_vault_platform_linux::lock_pages,
        unlock: tpt_vault_platform_linux::unlock_pages,
    });
}

fn main() {
    install_page_locker();
    let app = tauri::Builder::default()
        .manage(AppState::new())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            setup_tray(app)?;
            spawn_idle_watcher(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window locks the vault before the app goes away.
            if let WindowEvent::CloseRequested { .. } = event {
                lock_now(window.app_handle(), "window-closed");
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::create_vault,
            commands::unlock_vault,
            commands::unlock_with_recovery,
            commands::unlock_with_platform,
            commands::platform_unlock_supported,
            commands::enable_platform_unlock,
            commands::disable_platform_unlock,
            commands::lock_vault,
            commands::touch_activity,
            commands::list_entries,
            commands::read_note,
            commands::save_note,
            commands::create_dir,
            commands::create_file,
            commands::rename_entry,
            commands::remove_entry,
            commands::change_passphrase,
            commands::rotate_recovery_code,
            commands::rekey_vault,
            commands::set_auto_lock_minutes,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tpt-vault");

    app.run(|app, event| {
        if let RunEvent::ExitRequested { .. } = event {
            lock_now(app, "exit");
        }
    });
}
