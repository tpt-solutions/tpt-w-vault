// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

// Settings panel for an unlocked vault: auto-lock, passphrase, recovery code, Windows Hello,
// and rebuilding the vault's keys. Each action checks its own inputs, then calls the backend.

import { api, AppError } from "./api";
import { el, mount, setStatus } from "./dom";
import { recoveryCodeCard } from "./unlock";

export const MIN_PASSPHRASE_CHARS = 8;

export interface SettingsOptions {
  autoLockMinutes: number;
  platformSupported: boolean;
  onAutoLockChanged?: (minutes: number) => void;
  onClose: () => void;
}

/** Client-side passphrase check. The backend enforces the same rule. */
export function passphraseProblem(passphrase: string, confirm: string): string | null {
  if ([...passphrase].length < MIN_PASSPHRASE_CHARS) {
    return `Use at least ${MIN_PASSPHRASE_CHARS} characters.`;
  }
  if (passphrase !== confirm) {
    return "The two passphrases do not match.";
  }
  return null;
}

function labelled(text: string, input: HTMLInputElement): HTMLElement {
  return el("label", {}, text, input);
}

function passwordInput(id: string, autocomplete: string): HTMLInputElement {
  return el("input", { id, type: "password", autocomplete }) as HTMLInputElement;
}

function section(title: string, ...children: (Node | string)[]): HTMLElement {
  return el("section", { class: "settings-section" }, el("h3", {}, title), ...children);
}

export function renderSettings(opts: SettingsOptions): HTMLElement {
  const host = el("div", { class: "settings-body" });

  const close = () => opts.onClose();
  const rerender = () => mount(host, ...sections());

  function sections(): HTMLElement[] {
    return [
      autoLockSection(),
      passphraseSection(),
      recoverySection(),
      ...(opts.platformSupported ? [platformSection()] : []),
      rebuildSection(),
    ];
  }

  function autoLockSection(): HTMLElement {
    const minutes = el("input", {
      type: "number",
      min: 1,
      max: 240,
      value: opts.autoLockMinutes,
      "aria-label": "Lock after idle, in minutes",
    }) as HTMLInputElement;
    const status = el("span", { class: "muted", role: "status" });
    return section(
      "Auto-lock",
      el(
        "div",
        { class: "row" },
        el("label", { class: "row" }, "Lock after idle (minutes)", minutes),
        el(
          "button",
          {
            type: "button",
            on: {
              click: async () => {
                try {
                  await api.setAutoLock(Number(minutes.value));
                  opts.onAutoLockChanged?.(Number(minutes.value));
                  setStatus(status, "Saved.");
                } catch (e) {
                  setStatus(status, messageFor(e), true);
                }
              },
            },
          },
          "Save",
        ),
        status,
      ),
    );
  }

  function passphraseSection(): HTMLElement {
    const oldPass = passwordInput("old-pass", "current-password");
    const newPass = passwordInput("new-pass", "new-password");
    const confirm = passwordInput("confirm-pass", "new-password");
    const status = el("p", { class: "muted", role: "status" });
    const form = el(
      "form",
      { class: "stack" },
      labelled("Current passphrase", oldPass),
      labelled("New passphrase", newPass),
      labelled("Confirm new passphrase", confirm),
      el("div", { class: "row" }, el("button", { type: "submit", class: "primary" }, "Change passphrase")),
      status,
    );
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const problem = passphraseProblem(newPass.value, confirm.value);
      if (problem) return setStatus(status, problem, true);
      try {
        await api.changePassphrase(oldPass.value, newPass.value);
        setStatus(status, "Passphrase changed. Your recovery code still works.");
        oldPass.value = newPass.value = confirm.value = "";
      } catch (e) {
        setStatus(status, messageFor(e), true);
      }
    });
    return section("Passphrase", form);
  }

  function recoverySection(): HTMLElement {
    const pass = passwordInput("recovery-pass", "current-password");
    const status = el("p", { class: "muted", role: "status" });
    const form = el(
      "form",
      { class: "stack" },
      labelled("Passphrase", pass),
      el(
        "p",
        { class: "muted" },
        "Making a new recovery code makes the old one stop working.",
      ),
      el("div", { class: "row" }, el("button", { type: "submit" }, "Make a new recovery code")),
      status,
    );
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      try {
        const code = await api.rotateRecoveryCode(pass.value);
        pass.value = "";
        mount(
          host,
          recoveryCodeCard(
            code,
            () => rerender(),
            "card settings-card",
          ),
        );
      } catch (e) {
        setStatus(status, messageFor(e), true);
      }
    });
    return section("Recovery code", form);
  }

  function platformSection(): HTMLElement {
    const pass = passwordInput("platform-pass", "current-password");
    const status = el("p", { class: "muted", role: "status" });
    const run = (action: "enable" | "disable") => async () => {
      if (!pass.value) return setStatus(status, "Enter your passphrase first.", true);
      setStatus(status, action === "enable" ? "Waiting for your confirmation…" : "Turning off…");
      try {
        if (action === "enable") {
          await api.enablePlatformUnlock(pass.value);
          setStatus(status, "Windows Hello is on for this vault.");
        } else {
          await api.disablePlatformUnlock(pass.value);
          setStatus(status, "Windows Hello is off for this vault.");
        }
        pass.value = "";
      } catch (e) {
        setStatus(status, messageFor(e), true);
      }
    };
    return section(
      "Windows Hello",
      el(
        "p",
        { class: "muted" },
        "Unlock with your fingerprint or face instead of typing the passphrase. Turning it on asks for your passphrase once.",
      ),
      labelled("Passphrase", pass),
      el(
        "div",
        { class: "row" },
        el("button", { type: "button", on: { click: run("enable") } }, "Turn on"),
        el("button", { type: "button", on: { click: run("disable") } }, "Turn off"),
      ),
      status,
    );
  }

  function rebuildSection(): HTMLElement {
    const pass = passwordInput("rekey-pass", "current-password");
    const ack = el("input", { type: "checkbox" }) as HTMLInputElement;
    const status = el("p", { class: "muted", role: "status" });
    const go = el(
      "button",
      { type: "button", class: "danger", disabled: true },
      "Rebuild vault keys",
    ) as HTMLButtonElement;
    ack.addEventListener("change", () => (go.disabled = !ack.checked));
    go.addEventListener("click", async () => {
      if (!pass.value) return setStatus(status, "Enter your passphrase first.", true);
      const problem = passphraseProblem(pass.value, pass.value);
      if (problem) return setStatus(status, problem, true);
      go.disabled = true;
      setStatus(status, "Rebuilding. This copies every file, so it can take a while. Keep the app open.");
      try {
        const code = await api.rekeyVault(pass.value);
        pass.value = "";
        mount(host, recoveryCodeCard(code, () => rerender(), "card settings-card"));
      } catch (e) {
        go.disabled = !ack.checked;
        setStatus(status, messageFor(e), true);
      }
    });
    return section(
      "Rebuild vault keys",
      el(
        "p",
        { class: "muted" },
        "Re-encrypts the whole vault under new keys and makes a new recovery code. Use this if you think the keys were exposed. It needs free disk space about twice the vault's size while it runs.",
      ),
      labelled("Passphrase", pass),
      el("label", { class: "row" }, ack, "I understand, and I have enough free disk space"),
      el("div", { class: "row" }, go),
      status,
    );
  }

  mount(
    host,
    ...sections(),
  );

  return el(
    "section",
    { class: "card settings" },
    el(
      "div",
      { class: "row" },
      el("h2", {}, "Settings"),
      el("button", { type: "button", on: { click: close } }, "Close settings"),
    ),
    host,
  );
}

function messageFor(e: unknown): string {
  if (e instanceof AppError) {
    switch (e.code) {
      case "wrong_passphrase":
        return "That passphrase is not correct.";
      case "weak_passphrase":
        return e.message;
      case "platform_not_enrolled":
        return "Windows Hello is not set up for this vault yet.";
      case "consent_denied":
        return "Windows Hello was cancelled.";
      case "locked":
        return "The vault is locked.";
      default:
        return e.message;
    }
  }
  return String(e);
}
