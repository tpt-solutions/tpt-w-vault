// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

// Unlock screen: passphrase, recovery code, platform unlock, and first-run vault creation.

import { api, AppError, pickFolder } from "./api";
import { el, mount, setStatus } from "./dom";

const LAST_ROOT_KEY = "tpt-vault.lastRoot";
const RECENT_ROOTS_KEY = "tpt-vault.recentRoots";
const MAX_RECENT_ROOTS = 5;

/** The vault folder remembered from the last session. A per-viewer convenience only. */
function rememberedRoot(): string {
  try {
    return localStorage.getItem(LAST_ROOT_KEY) ?? "";
  } catch {
    return "";
  }
}

/** Whether this viewer has opened a vault before. Used to decide on the first-run welcome. */
export function hasRememberedRoot(): boolean {
  return rememberedRoot() !== "";
}

/** Vault folders opened on this viewer, most recent first. A per-viewer convenience only. */
function recentRoots(): string[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(RECENT_ROOTS_KEY) ?? "[]");
    return Array.isArray(parsed) ? parsed.filter((r): r is string => typeof r === "string") : [];
  } catch {
    return [];
  }
}

function remember(root: string): void {
  try {
    localStorage.setItem(LAST_ROOT_KEY, root);
    const next = [root, ...recentRoots().filter((r) => r !== root)].slice(0, MAX_RECENT_ROOTS);
    localStorage.setItem(RECENT_ROOTS_KEY, JSON.stringify(next));
  } catch {
    // Storage can be blocked. The field simply starts empty next time.
  }
}

/**
 * Removes a folder from this viewer's recent list and from the "remembered" folder. The vault's
 * files are not touched. Returns the list that remains.
 */
export function forgetRecentRoot(root: string): string[] {
  const remaining = recentRoots().filter((r) => r !== root);
  try {
    localStorage.setItem(RECENT_ROOTS_KEY, JSON.stringify(remaining));
    if (rememberedRoot() === root) localStorage.removeItem(LAST_ROOT_KEY);
  } catch {
    // Storage can be blocked. The entry then reappears next time, which is harmless.
  }
  return remaining;
}

export interface UnlockOptions {
  notice?: string;
  platformSupported: boolean;
  onUnlocked: () => void;
  /** Which form to show first. Defaults to passphrase unlock. */
  initialMode?: Mode;
  /** Shown above the form, for example a Back link from the first-run welcome. */
  header?: HTMLElement;
}

export type Mode = "passphrase" | "recovery" | "create";

export function renderUnlock(container: HTMLElement, opts: UnlockOptions): void {
  let mode: Mode = opts.initialMode ?? "passphrase";
  const status = el("p", { class: "muted", role: "status" });
  const rootInput = el("input", { id: "root", type: "text", autocomplete: "off", required: true });
  rootInput.value = rememberedRoot();
  const browseButton = el(
    "button",
    {
      type: "button",
      on: {
        click: async () => {
          try {
            const picked = await pickFolder(
              mode === "create" ? "Choose an empty folder for the new vault" : "Choose your vault folder",
            );
            if (picked) rootInput.value = picked;
          } catch (e) {
            setStatus(status, messageFor(e), true);
          }
        },
      },
    },
    "Browse…",
  );
  // Picking a recent vault fills the folder field. Locking returns here, so this is how to switch.
  const recent = recentRoots();
  const recentSelect = el(
    "select",
    {
      "aria-label": "Recent vaults",
      on: {
        change: () => {
          if (recentSelect.value) rootInput.value = recentSelect.value;
          forgetButton.disabled = !recentSelect.value;
        },
      },
    },
    el("option", { value: "" }, "Recent vaults…"),
    ...recent.map((r) => el("option", { value: r }, r)),
  ) as HTMLSelectElement;
  const forgetButton: HTMLButtonElement = el(
    "button",
    {
      type: "button",
      disabled: true,
      on: {
        click: () => {
          const root = recentSelect.value;
          if (!root) return;
          const remaining = forgetRecentRoot(root);
          recentSelect.querySelector(`option[value="${CSS.escape(root)}"]`)?.remove();
          if (rootInput.value.trim() === root) rootInput.value = "";
          recentSelect.value = "";
          forgetButton.disabled = true;
          recentRow.hidden = remaining.length === 0;
          setStatus(
            status,
            "Removed from the recent list. The vault folder and its files were not changed.",
          );
        },
      },
    },
    "Forget",
  ) as HTMLButtonElement;
  const recentRow = el("div", { class: "row", hidden: recent.length === 0 }, recentSelect, forgetButton);
  const passInput = el("input", { id: "pass", type: "password", autocomplete: "current-password" });
  const confirmInput = el("input", { id: "confirm", type: "password", autocomplete: "new-password" });
  const codeInput = el("input", { id: "code", type: "text", autocomplete: "off", spellcheck: false });

  const modeButtons = el("div", { class: "row" });
  const form = el("form", { class: "stack" });

  const busy = (on: boolean) => {
    for (const b of form.querySelectorAll("button")) b.disabled = on;
  };

  const submit = async (ev: Event) => {
    ev.preventDefault();
    const root = rootInput.value.trim();
    if (!root) return setStatus(status, "Enter the vault folder.", true);
    busy(true);
    try {
      if (mode === "create") {
        if (passInput.value !== confirmInput.value) {
          return setStatus(status, "The two passphrases do not match.", true);
        }
        setStatus(status, "Creating vault. This can take up to a minute on a slow computer…");
        const code = await api.createVault(root, passInput.value);
        remember(root);
        return showRecoveryCode(container, code, opts.onUnlocked);
      }
      if (mode === "recovery") {
        setStatus(status, "Checking recovery code…");
        await api.unlockWithRecovery(root, codeInput.value.trim());
      } else {
        setStatus(status, "Unlocking…");
        await api.unlockVault(root, passInput.value);
      }
      remember(root);
      opts.onUnlocked();
    } catch (e) {
      setStatus(status, messageFor(e, mode), true);
    } finally {
      busy(false);
    }
  };

  const platformButton: HTMLButtonElement | null = opts.platformSupported
    ? el(
        "button",
        {
          type: "button",
          on: {
            click: async () => {
              const root = rootInput.value.trim();
              if (!root) return setStatus(status, "Enter the vault folder.", true);
              busy(true);
              setStatus(status, "Waiting for your confirmation…");
              try {
                await api.unlockWithPlatform(root);
                remember(root);
                opts.onUnlocked();
              } catch (e) {
                setStatus(status, messageFor(e), true);
              } finally {
                busy(false);
              }
            },
          },
        },
        "Unlock with Windows Hello",
      )
    : null;

  const setMode = (next: Mode) => {
    mode = next;
    setStatus(status, "");
    const showPass = mode !== "recovery";
    const showCode = mode === "recovery";
    const showConfirm = mode === "create";
    passInput.closest("label")!.hidden = !showPass;
    confirmInput.closest("label")!.hidden = !showConfirm;
    codeInput.closest("label")!.hidden = !showCode;
    submitButton.textContent = mode === "create" ? "Create vault" : "Unlock";
    // Windows Hello only unlocks an existing vault with its enrolled key, so only show it there.
    if (platformButton) platformButton.hidden = mode !== "passphrase";
    if (mode === "create") {
      setStatus(
        status,
        "Choose an empty folder. Your passphrase unlocks the vault, so pick a sentence you can remember (at least 8 characters). You will be shown a recovery code next.",
      );
    } else {
      setStatus(status, "");
    }
    for (const b of modeButtons.querySelectorAll("button")) {
      b.setAttribute("aria-pressed", String(b.dataset.mode === mode));
    }
  };

  const submitButton = el("button", { type: "submit", class: "primary" }, "Unlock");
  const modeButton = (m: Mode, label: string) =>
    el("button", { type: "button", "data-mode": m, on: { click: () => setMode(m) } }, label);
  mount(
    modeButtons,
    modeButton("passphrase", "Passphrase"),
    modeButton("recovery", "Recovery code"),
    modeButton("create", "New vault"),
  );

  mount(
    form,
    el("label", {}, "Vault folder", el("div", { class: "row" }, rootInput, browseButton)),
    recentRow,
    el("label", {}, "Passphrase", passInput),
    el("label", {}, "Confirm passphrase", confirmInput),
    el("label", {}, "Recovery code (with hyphens or without)", codeInput),
    el("div", { class: "row" }, submitButton, platformButton),
  );
  form.addEventListener("submit", (ev) => void submit(ev));

  mount(
    container,
    el(
      "section",
      { class: "unlock card" },
      el("h1", {}, "tpt-vault"),
      opts.header ?? null,
      opts.notice ? el("p", { class: "notice", role: "alert" }, opts.notice) : null,
      modeButtons,
      form,
      status,
    ),
  );
  setMode(mode);
  rootInput.focus();
}

/** Shows the recovery code once. The user has to confirm they stored it before continuing. */
function showRecoveryCode(container: HTMLElement, code: string, onDone: () => void): void {
  mount(container, recoveryCodeCard(code, onDone, "unlock card"));
}

/** The one-time recovery code card. `onDone` runs once the user confirms they stored the code. */
export function recoveryCodeCard(code: string, onDone: () => void, className: string): HTMLElement {
  const confirmBox = el("input", { type: "checkbox", id: "saved" });
  const doneButton = el(
    "button",
    {
      type: "button",
      class: "primary",
      disabled: true,
      on: { click: onDone },
    },
    "Continue",
  );
  confirmBox.addEventListener("change", () => {
    doneButton.disabled = !(confirmBox as HTMLInputElement).checked;
  });
  return el(
    "section",
    { class: className },
    el("h2", {}, "Save your recovery code"),
    el(
      "p",
      {},
      "This code can open the vault if you forget your passphrase. It is shown only once. Write it down or print it, and store it somewhere safe that is not on this computer.",
    ),
    el("pre", { class: "recovery-code", "aria-label": "Recovery code" }, code),
    el("label", { class: "row" }, confirmBox, "I have stored my recovery code"),
    doneButton,
  );
}

function messageFor(e: unknown, mode: Mode = "passphrase"): string {
  if (e instanceof AppError) {
    switch (e.code) {
      case "wrong_passphrase":
        // A wrong recovery code also reports wrong_passphrase from the core, so word it by mode.
        return mode === "recovery"
          ? "That recovery code does not match this vault."
          : "That passphrase did not match this vault.";
      case "invalid_recovery_code":
        return "That recovery code is not valid. Check it and try again.";
      case "platform_not_enrolled":
        return "Windows Hello is not set up for this vault. Unlock with your passphrase.";
      case "corrupt":
        return "This vault appears damaged. Nothing was changed.";
      case "platform_unavailable":
        return "Windows Hello is not available. Use your passphrase instead.";
      default:
        return e.message;
    }
  }
  return String(e);
}
