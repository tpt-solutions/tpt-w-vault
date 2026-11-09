// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

// Note editor with debounced autosave. The timing matches `core/src/notes.rs` (`Autosave`):
// a save runs after a 1.5 s pause, or 10 s after the first unsaved edit, whichever is first.

import { api } from "./api";
import { el, mount, setStatus } from "./dom";
import { renderMarkdown } from "./markdown";

export const DEBOUNCE_MS = 1500;
export const MAX_WAIT_MS = 10_000;

/** Markdown snippets for the authoring toolbar. `{}` marks where the selected text goes. */
export const SNIPPETS = {
  heading: "## {}\n",
  list: "- {}\n",
  code: "```\n{}\n```\n",
  link: "[{}](https://)",
  table: "| Column | Column |\n| --- | --- |\n| {} |  |\n",
} as const;

export type SnippetName = keyof typeof SNIPPETS;

/**
 * Replaces `start..end` of `text` with a snippet. The selected text fills `{}`, and the cursor
 * is left just after the inserted snippet.
 */
export function insertSnippet(
  text: string,
  start: number,
  end: number,
  snippet: string,
): { text: string; cursor: number } {
  const selected = text.slice(start, end);
  const body = snippet.replace("{}", selected);
  const at = snippet.indexOf("{}");
  const next = text.slice(0, start) + body + text.slice(end);
  // Place the cursor on the placeholder when there is no selection, so the user can type there.
  const cursor = selected === "" ? start + at : start + body.length;
  return { text: next, cursor };
}

export class NoteEditor {
  readonly path: string;
  private readonly area: HTMLTextAreaElement;
  private readonly status: HTMLElement;
  private readonly preview: HTMLElement;
  private readonly previewButton: HTMLButtonElement;
  private previewing = false;
  private debounceTimer: number | undefined;
  private maxWaitTimer: number | undefined;
  private dirty = false;
  private queue: Promise<void> = Promise.resolve();
  private lastActivity = 0;

  /** Element to insert into the page. */
  readonly node: HTMLElement;

  constructor(path: string, text: string, onClose: () => void) {
    this.path = path;
    this.area = el("textarea", { class: "editor-area", spellcheck: true, "aria-label": "Note text" });
    this.area.value = text;
    this.status = el("span", { class: "muted", role: "status" });
    setStatus(this.status, "Saved");
    this.preview = el("div", { class: "editor-preview", hidden: true, "aria-label": "Preview" });

    this.area.addEventListener("input", () => this.edited());

    this.previewButton = el(
      "button",
      { type: "button", "aria-pressed": "false", on: { click: () => this.togglePreview() } },
      "Preview",
    ) as HTMLButtonElement;

    const snippetButtons = (Object.keys(SNIPPETS) as SnippetName[]).map((name) =>
      el(
        "button",
        {
          type: "button",
          class: "snippet",
          on: { click: () => this.insert(name) },
          title: `Insert ${name}`,
        },
        name[0].toUpperCase() + name.slice(1),
      ),
    );

    this.node = el(
      "section",
      { class: "editor" },
      el(
        "header",
        { class: "toolbar" },
        el("button", { type: "button", on: { click: () => void this.close(onClose) } }, "Close note"),
        el("strong", { class: "note-title" }, path),
        this.status,
      ),
      el(
        "div",
        { class: "row", role: "toolbar", "aria-label": "Markdown" },
        this.previewButton,
        ...snippetButtons,
      ),
      this.area,
      this.preview,
    );
    // The node is not in the page yet, so focus only works once the caller has inserted it.
    requestAnimationFrame(() => this.area.focus());
  }

  private togglePreview(): void {
    this.previewing = !this.previewing;
    this.previewButton.setAttribute("aria-pressed", String(this.previewing));
    this.previewButton.textContent = this.previewing ? "Edit" : "Preview";
    this.area.hidden = this.previewing;
    this.preview.hidden = !this.previewing;
    if (this.previewing) {
      mount(this.preview, renderMarkdown(this.area.value));
    } else {
      this.area.focus();
    }
  }

  private insert(name: SnippetName): void {
    if (this.previewing) this.togglePreview();
    const value = this.area.value;
    const start = this.area.selectionStart ?? value.length;
    const end = this.area.selectionEnd ?? start;
    const { text, cursor } = insertSnippet(value, start, end, SNIPPETS[name]);
    this.area.value = text;
    this.area.setSelectionRange(cursor, cursor);
    this.area.focus();
    // Setting the value does not fire `input`, so report the edit directly.
    this.edited();
  }

  private edited(): void {
    const now = Date.now();
    // Tell the Rust idle timer about typing, at most every 5 seconds.
    if (now - this.lastActivity > 5_000) {
      this.lastActivity = now;
      void api.touch().catch(() => undefined);
    }
    if (!this.dirty) {
      this.dirty = true;
      this.maxWaitTimer = window.setTimeout(() => void this.flush(), MAX_WAIT_MS);
      setStatus(this.status, "Unsaved changes");
    }
    window.clearTimeout(this.debounceTimer);
    this.debounceTimer = window.setTimeout(() => void this.flush(), DEBOUNCE_MS);
  }

  /** Saves pending edits. Saves run one at a time, in order. */
  flush(): Promise<void> {
    this.queue = this.queue.then(() => this.save());
    return this.queue;
  }

  private async save(): Promise<void> {
    if (!this.dirty) return;
    window.clearTimeout(this.debounceTimer);
    window.clearTimeout(this.maxWaitTimer);
    // Capture the text first, so edits made during the save stay marked dirty.
    const text = this.area.value;
    this.dirty = false;
    setStatus(this.status, "Saving…");
    try {
      await api.saveNote(this.path, text);
      if (!this.dirty) setStatus(this.status, "Saved");
    } catch (e) {
      this.dirty = true;
      setStatus(this.status, `Save failed: ${(e as Error).message}`, true);
    }
  }

  /** Flushes, then hands control back. The caller decides what to show next. */
  async close(onClose: () => void): Promise<void> {
    await this.flush();
    onClose();
  }

  /** Drops the editor without saving. Used when the vault locks, since saving would fail. */
  discard(): void {
    window.clearTimeout(this.debounceTimer);
    window.clearTimeout(this.maxWaitTimer);
    this.dirty = false;
  }

  hasUnsavedChanges(): boolean {
    return this.dirty;
  }
}
