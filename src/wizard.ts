// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

// First-run welcome. Explains what a vault is in plain language, then hands off to the
// create or unlock form. Shown only when this viewer has no remembered vault folder.

import { el, mount } from "./dom";
import { renderUnlock, type UnlockOptions } from "./unlock";

export type WelcomeOptions = Pick<UnlockOptions, "platformSupported" | "onUnlocked">;

export function renderWelcome(container: HTMLElement, opts: WelcomeOptions): void {
  const start = (initialMode: "create" | "passphrase") => {
    const back = el(
      "button",
      { type: "button", class: "link", on: { click: () => renderWelcome(container, opts) } },
      "← Back to welcome",
    );
    renderUnlock(container, { ...opts, initialMode, header: el("div", { class: "row" }, back) });
  };

  mount(
    container,
    el(
      "section",
      { class: "unlock card welcome" },
      el("h1", {}, "Welcome to tpt-vault"),
      el(
        "p",
        {},
        "tpt-vault keeps your private files and notes in an encrypted vault. Without your passphrase, the files look like scrambled data. Nothing is uploaded: the vault lives in a folder on this computer.",
      ),
      el("h2", {}, "Getting started"),
      el(
        "ol",
        { class: "steps" },
        el("li", {}, "Choose an empty folder to hold the vault."),
        el(
          "li",
          {},
          "Pick a passphrase you will remember. It is the everyday key, so use a sentence of at least 8 characters.",
        ),
        el(
          "li",
          {},
          "Save the recovery code you are shown. If you forget your passphrase, it is the only other way back in, and it is never shown again.",
        ),
      ),
      el(
        "div",
        { class: "row" },
        el(
          "button",
          { type: "button", class: "primary", on: { click: () => start("create") } },
          "Create my vault",
        ),
        el(
          "button",
          { type: "button", on: { click: () => start("passphrase") } },
          "I already have a vault",
        ),
      ),
    ),
  );
}
