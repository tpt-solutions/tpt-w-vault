// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

// Typed wrappers over the Tauri command layer (src-tauri/src/commands.rs). The Rust side
// returns `AppError { code, message }` on failure; `call` turns that into a thrown `AppError`.

interface TauriGlobal {
  core: { invoke: (cmd: string, args?: Record<string, unknown>) => Promise<unknown> };
  dialog: {
    open: (opts: { directory?: boolean; multiple?: boolean; title?: string }) => Promise<
      string | string[] | null
    >;
  };
  event: {
    listen: (name: string, cb: (e: { payload: unknown }) => void) => Promise<() => void>;
  };
}

declare global {
  interface Window {
    __TAURI__?: TauriGlobal;
  }
}

export class AppError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "AppError";
    this.code = code;
  }
}

function tauri(): TauriGlobal {
  if (!window.__TAURI__) {
    throw new AppError("no_runtime", "This page must run inside the tpt-vault app.");
  }
  return window.__TAURI__;
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return (await tauri().core.invoke(cmd, args)) as T;
  } catch (e) {
    if (e && typeof e === "object" && "code" in e && "message" in e) {
      const err = e as { code: string; message: string };
      throw new AppError(err.code, err.message);
    }
    throw new AppError("internal", String(e));
  }
}

export interface VaultStatus {
  unlocked: boolean;
  root: string | null;
  auto_lock_minutes: number;
}

export interface EntryDto {
  name: string;
  is_dir: boolean;
  size: number;
}

export const api = {
  status: () => call<VaultStatus>("vault_status"),
  createVault: (root: string, passphrase: string) =>
    call<string>("create_vault", { root, passphrase }),
  unlockVault: (root: string, passphrase: string) =>
    call<void>("unlock_vault", { root, passphrase }),
  unlockWithRecovery: (root: string, code: string) =>
    call<void>("unlock_with_recovery", { root, code }),
  unlockWithPlatform: (root: string) => call<void>("unlock_with_platform", { root }),
  platformUnlockSupported: () => call<boolean>("platform_unlock_supported"),
  lock: () => call<void>("lock_vault"),
  touch: () => call<void>("touch_activity"),
  list: (path: string) => call<EntryDto[]>("list_entries", { path }),
  readNote: (path: string) => call<string>("read_note", { path }),
  saveNote: (path: string, text: string) => call<void>("save_note", { path, text }),
  createDir: (path: string) => call<void>("create_dir", { path }),
  createFile: (path: string) => call<void>("create_file", { path }),
  rename: (from: string, to: string) => call<void>("rename_entry", { from, to }),
  remove: (path: string) => call<void>("remove_entry", { path }),
  setAutoLock: (minutes: number) => call<void>("set_auto_lock_minutes", { minutes }),
  changePassphrase: (oldPassphrase: string, newPassphrase: string) =>
    call<void>("change_passphrase", { oldPassphrase, newPassphrase }),
  rotateRecoveryCode: (passphrase: string) =>
    call<string>("rotate_recovery_code", { passphrase }),
  rekeyVault: (passphrase: string) => call<string>("rekey_vault", { passphrase }),
  enablePlatformUnlock: (passphrase: string) =>
    call<void>("enable_platform_unlock", { passphrase }),
  disablePlatformUnlock: (passphrase: string) =>
    call<void>("disable_platform_unlock", { passphrase }),
};

/** Opens the system folder picker. Resolves to the chosen folder, or null if cancelled. */
export async function pickFolder(title: string): Promise<string | null> {
  const result = await tauri().dialog.open({ directory: true, multiple: false, title });
  return typeof result === "string" ? result : null;
}

/** Subscribes to a backend event. Returns an unsubscribe function. */
export function onEvent(name: string, cb: (payload: unknown) => void): Promise<() => void> {
  return tauri().event.listen(name, (e) => cb(e.payload));
}
