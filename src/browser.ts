// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

// Vault browser: folder navigation, note open/create/rename/delete, auto-lock setting, lock.

import { api, AppError, type EntryDto } from "./api";
import { el, mount, setStatus } from "./dom";
import { NoteEditor } from "./editor";
import { renderSettings } from "./settings";

export interface BrowserOptions {
  autoLockMinutes: number;
  platformSupported: boolean;
  /** The key bytes could not be pinned in RAM, so they may reach the page file. */
  keysLocked: boolean;
  /** The vault has passed the soft write limit. Offer a key rebuild. */
  rekeyRecommended: boolean;
  /** Drive letter the vault is mounted on, or null. */
  mountedDrive: string | null;
  /** Whether this build can mount the vault as a drive. */
  mountSupported: boolean;
  /** The vault has passed the hard write limit. Saves are refused until the keys are rebuilt. */
  writeLimitReached: boolean;
  onLocked: (reason: string) => void;
}

/** Vault paths use `/`. The root is the empty string. */
export function joinPath(dir: string, name: string): string {
  return dir ? `${dir}/${name}` : name;
}

/** Client-side check for a single entry name. The core checks again; this gives faster feedback. */
export function validName(name: string): string | null {
  if (name.length === 0) return "Enter a name.";
  if (name === "." || name === "..") return "That name is not allowed.";
  if (/[\\/\0]/.test(name)) return "Names cannot contain / or \\.";
  return null;
}

/** Checks a full vault path such as `work/plan.md`, segment by segment. */
export function validPath(path: string): string | null {
  if (path.trim() === "") return "Enter a name.";
  for (const segment of path.split("/")) {
    const problem = validName(segment);
    if (problem) {
      return problem === "Enter a name."
        ? "A path cannot have an empty part, such as // or a trailing /."
        : problem;
    }
  }
  return null;
}

export function isNote(name: string): boolean {
  return name.toLowerCase().endsWith(".md") && name.length > 3;
}

export class Browser {
  private dir = "";
  private editor: NoteEditor | null = null;
  private readonly listArea = el("div", { class: "entries" });
  private lastEntries: EntryDto[] = [];
  private notesOnly = false;
  private readonly notesButton: HTMLButtonElement;
  private readonly budgetNotice: HTMLElement;
  private readonly driveLabel = el("span", { class: "muted", role: "status" });
  private readonly driveButton: HTMLButtonElement;
  private mountedDrive: string | null;
  private readonly editorArea = el("div", { class: "editor-host" });
  private readonly status = el("p", { class: "muted", role: "status" });
  private readonly pathLabel = el("nav", { class: "crumbs", "aria-label": "Current folder" });
  private readonly settings: HTMLElement;
  private readonly newInput = el("input", { type: "text", "aria-label": "New name", autocomplete: "off" });
  private newKind: "note" | "folder" = "note";
  private readonly newForm: HTMLFormElement;

  readonly node: HTMLElement;

  constructor(private readonly opts: BrowserOptions) {
    this.settings = el("div", { class: "settings-host", hidden: true });

    this.newForm = el(
      "form",
      { class: "row new-item", hidden: true },
      this.newInput,
      el(
        "button",
        {
          type: "submit",
          class: "primary",
        },
        "Create",
      ),
      el(
        "button",
        { type: "button", on: { click: () => this.hideNewForm() } },
        "Cancel",
      ),
    );
    this.newForm.addEventListener("submit", (ev) => {
      ev.preventDefault();
      void this.createNew();
    });

    this.notesButton = el(
      "button",
      {
        type: "button",
        "aria-pressed": "false",
        on: { click: () => this.toggleNotesOnly() },
      },
      "Notes only",
    ) as HTMLButtonElement;

    this.mountedDrive = opts.mountedDrive;
    this.driveButton = el(
      "button",
      { type: "button", on: { click: () => void this.toggleDrive() } },
    ) as HTMLButtonElement;
    this.showDrive();

    const notices: string[] = [];
    if (opts.writeLimitReached) {
      notices.push("This vault cannot take more saves until its keys are rebuilt. Open Settings and choose Rebuild vault keys.");
    } else if (opts.rekeyRecommended) {
      notices.push("This vault has been written to a lot. Rebuild its keys in Settings when convenient.");
    }
    if (!opts.keysLocked) {
      notices.push("This computer would not pin the vault keys in memory, so they may be written to the page file. Lock the vault when you step away.");
    }
    this.budgetNotice = el(
      "p",
      { class: "notice", role: "status", hidden: notices.length === 0 },
      notices.join(" "),
    );

    this.node = el(
      "section",
      { class: "browser" },
      el(
        "header",
        { class: "toolbar" },
        el("strong", {}, "tpt-vault"),
        el(
          "button",
          { type: "button", on: { click: () => this.toggleSettings() } },
          "Settings",
        ),
        el(
          "button",
          { type: "button", class: "primary", on: { click: () => void this.lockNow() } },
          "Lock",
        ),
      ),
      el("div", { class: "row drive", hidden: !opts.mountSupported }, this.driveLabel, this.driveButton),
      this.budgetNotice,
      this.settings,
      this.editorArea,
      el(
        "div",
        { class: "list-view" },
        this.pathLabel,
        el(
          "div",
          { class: "row" },
          el(
            "button",
            { type: "button", on: { click: () => this.showNewForm("note") } },
            "New note",
          ),
          el(
            "button",
            { type: "button", on: { click: () => this.showNewForm("folder") } },
            "New folder",
          ),
          this.notesButton,
        ),
        this.newForm,
        this.status,
        this.listArea,
      ),
    );
  }

  /** Shows whether the vault is mounted, and the button that changes that. */
  private showDrive(): void {
    if (this.mountedDrive) {
      this.driveLabel.textContent = `Mounted at ${this.mountedDrive}`;
      this.driveButton.textContent = "Unmount";
    } else {
      this.driveLabel.textContent = "Not mounted";
      this.driveButton.textContent = "Mount vault";
    }
  }

  private async toggleDrive(): Promise<void> {
    this.driveButton.disabled = true;
    try {
      if (this.mountedDrive) {
        await api.unmountDrive();
        this.mountedDrive = null;
      } else {
        // An empty letter asks the app to pick the highest free one.
        await api.mountDrive("");
        this.mountedDrive = (await api.status()).mounted_drive;
      }
      setStatus(this.status, "");
    } catch (e) {
      setStatus(this.status, messageFor(e), true);
    } finally {
      this.driveButton.disabled = false;
      this.showDrive();
    }
  }

  /** Loads the root listing. Call once after unlock. */
  async start(): Promise<void> {
    await this.open("");
  }

  /** Stops any open editor without saving. Called when the vault locks by itself. */
  dropEditor(): void {
    this.editor?.discard();
    this.editor = null;
  }

  private toggleSettings(): void {
    if (!this.settings.hidden) {
      this.closeSettings();
      return;
    }
    mount(
      this.settings,
      renderSettings({
        autoLockMinutes: this.opts.autoLockMinutes,
        platformSupported: this.opts.platformSupported,
        onAutoLockChanged: (minutes) => (this.opts.autoLockMinutes = minutes),
        onClose: () => this.closeSettings(),
      }),
    );
    this.settings.hidden = false;
  }

  private closeSettings(): void {
    this.settings.hidden = true;
    mount(this.settings);
  }

  private showNewForm(kind: "note" | "folder"): void {
    this.newKind = kind;
    this.newForm.hidden = false;
    this.newInput.placeholder = kind === "note" ? "note name, e.g. ideas.md" : "folder name";
    this.newInput.value = "";
    this.newInput.focus();
  }

  private hideNewForm(): void {
    this.newForm.hidden = true;
  }

  private async createNew(): Promise<void> {
    let name = this.newInput.value.trim();
    const problem = validName(name);
    if (problem) return setStatus(this.status, problem, true);
    if (this.newKind === "note" && !isNote(name)) name += ".md";
    const path = joinPath(this.dir, name);
    try {
      if (this.newKind === "folder") {
        await api.createDir(path);
      } else {
        await api.createFile(path);
      }
      this.hideNewForm();
      await this.refresh();
      if (this.newKind === "note") await this.openNote(path);
    } catch (e) {
      setStatus(this.status, messageFor(e), true);
    }
  }

  /** Navigates to a folder. Any open note is saved first. */
  async open(dir: string): Promise<void> {
    await this.closeEditor();
    this.dir = dir;
    this.hideNewForm();
    await this.refresh();
  }

  private async refresh(): Promise<void> {
    this.renderCrumbs();
    try {
      const entries = await api.list(this.dir);
      this.lastEntries = entries;
      this.renderEntries(entries);
      setStatus(this.status, this.folderStatus(entries));
    } catch (e) {
      mount(this.listArea);
      setStatus(this.status, messageFor(e), true);
    }
  }

  private renderCrumbs(): void {
    const parts = this.dir ? this.dir.split("/") : [];
    const crumbs: (Node | string)[] = [
      el("button", { type: "button", on: { click: () => void this.open("") } }, "Vault"),
    ];
    parts.forEach((part, i) => {
      const target = parts.slice(0, i + 1).join("/");
      crumbs.push(" / ");
      crumbs.push(
        el("button", { type: "button", on: { click: () => void this.open(target) } }, part),
      );
    });
    mount(this.pathLabel, ...crumbs);
  }

  private renderEntries(entries: EntryDto[]): void {
    const sorted = [...entries].sort((a, b) =>
      a.is_dir === b.is_dir ? a.name.localeCompare(b.name) : a.is_dir ? -1 : 1,
    );
    const rows = this.visible(sorted).map((entry) => this.renderRow(entry));
    mount(this.listArea, ...rows);
  }

  /** Notes-only keeps folders, so the user can still navigate to their notes. */
  private visible(sorted: EntryDto[]): EntryDto[] {
    return this.notesOnly ? sorted.filter((e) => e.is_dir || isNote(e.name)) : sorted;
  }

  private folderStatus(entries: EntryDto[]): string {
    if (entries.length === 0) return "This folder is empty.";
    if (this.notesOnly && this.visible(entries).length === 0) return "No notes in this folder.";
    return "";
  }

  private toggleNotesOnly(): void {
    this.notesOnly = !this.notesOnly;
    this.notesButton.setAttribute("aria-pressed", String(this.notesOnly));
    this.renderEntries(this.lastEntries);
    setStatus(this.status, this.folderStatus(this.lastEntries));
  }

  private renderRow(entry: EntryDto): HTMLElement {
    const path = joinPath(this.dir, entry.name);
    let label: HTMLElement;
    if (entry.is_dir) {
      label = el(
        "button",
        { type: "button", class: "entry-name", on: { click: () => void this.open(path) } },
        `${entry.name}/`,
      );
    } else if (isNote(entry.name)) {
      label = el(
        "button",
        { type: "button", class: "entry-name", on: { click: () => void this.openNote(path) } },
        entry.name,
      );
    } else {
      label = el("span", { class: "entry-name muted" }, `${entry.name} (${formatSize(entry.size)}, not a note)`);
    }
    const renameButton = el(
      "button",
      {
        type: "button",
        on: { click: () => this.startRename(path, entry.name, row) },
      },
      "Rename",
    );
    const row: HTMLElement = el("div", { class: "entry" }, label, renameButton, this.deleteButton(path));
    return row;
  }

  private deleteButton(path: string): HTMLElement {
    let armed = false;
    const button: HTMLButtonElement = el(
      "button",
      {
        type: "button",
        class: "danger",
        on: {
          click: async () => {
            if (!armed) {
              armed = true;
              button.textContent = "Confirm delete";
              return;
            }
            try {
              await api.remove(path);
              await this.refresh();
            } catch (e) {
              setStatus(this.status, messageFor(e), true);
            }
          },
        },
      },
      "Delete",
    );
    return button;
  }

  private startRename(path: string, currentName: string, row: HTMLElement): void {
    // The field takes a full path, so one action both renames and moves between folders.
    const input = el("input", {
      type: "text",
      "aria-label": "New path, for example work/plan.md",
      autocomplete: "off",
    });
    input.value = path || currentName;
    const form = el(
      "form",
      { class: "stack" },
      el("label", {}, "Rename or move to (folder/name)", input),
      el(
        "div",
        { class: "row" },
        el("button", { type: "submit", class: "primary" }, "Save"),
        el("button", { type: "button", on: { click: () => void this.refresh() } }, "Cancel"),
      ),
    );
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const to = input.value.trim();
      const problem = validPath(to);
      if (problem) return setStatus(this.status, problem, true);
      if (to === path) return void this.refresh();
      try {
        await api.rename(path, to);
        await this.refresh();
      } catch (e) {
        setStatus(this.status, messageFor(e), true);
      }
    });
    // Put the form in place of the row being renamed.
    row.replaceWith(form);
    input.focus();
    input.select();
  }

  private async openNote(path: string): Promise<void> {
    await this.closeEditor();
    try {
      const text = await api.readNote(path);
      this.editor = new NoteEditor(path, text, () => {
        this.editor = null;
        this.editorArea.replaceChildren();
        void this.refresh();
      });
      this.editorArea.replaceChildren(this.editor.node);
      this.listArea.replaceChildren();
      setStatus(this.status, "");
    } catch (e) {
      setStatus(this.status, messageFor(e), true);
    }
  }

  private async closeEditor(): Promise<void> {
    if (this.editor) {
      await this.editor.flush();
      this.editor = null;
      this.editorArea.replaceChildren();
    }
  }

  private async lockNow(): Promise<void> {
    try {
      await this.editor?.flush();
    } catch {
      // A failed save is shown in the editor. Locking proceeds, so unsaved text is lost.
    }
    this.dropEditor();
    try {
      await api.lock();
    } finally {
      this.opts.onLocked("You locked the vault.");
    }
  }
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function messageFor(e: unknown): string {
  if (e instanceof AppError) {
    switch (e.code) {
      case "already_exists":
        return "An item with that name already exists here.";
      case "directory_not_empty":
        return "That folder is not empty. Remove its contents first.";
      case "locked":
        return "The vault is locked.";
      case "note_too_large":
        return "That note is too large to save.";
      case "write_limit_reached":
        return "This vault cannot take more saves until its keys are rebuilt. Open Settings and choose Rebuild vault keys.";
      default:
        return e.message;
    }
  }
  return String(e);
}
