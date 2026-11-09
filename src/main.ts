// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

// App entry. Shows the unlock screen or the vault browser, depending on the backend session,
// and reacts to the backend's lock and lock-warning events.

import { api, onEvent, type VaultStatus } from "./api";
import { Browser } from "./browser";
import { el, mount, setStatus } from "./dom";
import { hasRememberedRoot, renderUnlock } from "./unlock";
import { renderWelcome } from "./wizard";
import "./style.css";

const app = document.getElementById("app");
if (!app) throw new Error("missing #app element");
const root: HTMLElement = app;
root.dataset.ready = "true";

const banner = el("p", { class: "banner", role: "alert", hidden: true });
const screen = el("main", { class: "screen" });
mount(root, banner, screen);

let browser: Browser | null = null;

function showBanner(text: string | null): void {
  banner.hidden = text === null;
  setStatus(banner, text ?? "");
}

async function platformSupported(): Promise<boolean> {
  try {
    return await api.platformUnlockSupported();
  } catch {
    // Platform unlock is optional. The passphrase path still works.
    return false;
  }
}

async function showUnlock(notice?: string): Promise<void> {
  browser = null;
  showBanner(null);
  renderUnlock(screen, {
    notice,
    platformSupported: await platformSupported(),
    onUnlocked: () => void showBrowser(),
  });
}

async function showWelcome(): Promise<void> {
  browser = null;
  showBanner(null);
  renderWelcome(screen, {
    platformSupported: await platformSupported(),
    onUnlocked: () => void showBrowser(),
  });
}

async function showBrowser(): Promise<void> {
  showBanner(null);
  const status: VaultStatus = await api.status();
  browser = new Browser({
    autoLockMinutes: status.auto_lock_minutes,
    platformSupported: await platformSupported(),
    onLocked: (reason) => void showUnlock(reason),
  });
  mount(screen, browser.node);
  await browser.start();
}

const LOCK_REASONS: Record<string, string> = {
  idle: "The vault locked after a period of inactivity.",
  "window-closed": "The vault locked when the window closed.",
  quit: "The vault locked when the app quit.",
  exit: "The vault locked when the app quit.",
  tray: "You locked the vault from the tray menu.",
};

async function boot(): Promise<void> {
  // Activity from the user keeps the idle timer from locking the vault mid-task.
  let lastTouch = 0;
  const touch = () => {
    // Any activity answers a lock warning, so the banner clears at once.
    if (!banner.hidden && browser) showBanner(null);
    const now = Date.now();
    if (now - lastTouch < 5_000) return;
    lastTouch = now;
    void api.touch().catch(() => undefined);
  };
  document.addEventListener("pointerdown", touch, true);
  document.addEventListener("keydown", touch, true);

  await onEvent("vault-locked", (payload) => {
    const reason = typeof payload === "string" ? payload : "";
    // The backend locked, so a save would fail. Drop the open note without saving.
    browser?.dropEditor();
    void showUnlock(LOCK_REASONS[reason] ?? "The vault is locked.");
  });
  await onEvent("lock-warning", (payload) => {
    const seconds = typeof payload === "number" ? payload : 0;
    showBanner(
      `Locking in ${seconds} second${seconds === 1 ? "" : "s"} due to inactivity. Move the mouse or press a key to stay unlocked.`,
    );
  });

  try {
    const status = await api.status();
    if (status.unlocked) {
      await showBrowser();
    } else if (hasRememberedRoot()) {
      await showUnlock();
    } else {
      // First run on this viewer: explain the vault before asking for anything.
      await showWelcome();
    }
  } catch (e) {
    mount(screen, el("p", { class: "notice", role: "alert" }, `Could not start: ${(e as Error).message}`));
  }
}

void boot();
