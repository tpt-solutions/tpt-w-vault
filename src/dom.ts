// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

// Minimal DOM helper. Text children become text nodes, so vault names and note contents are
// never parsed as HTML. The UI never uses innerHTML.

export type Child = Node | string | null | false | undefined;

type Props = {
  class?: string;
  on?: Record<string, EventListener>;
  [attr: string]: unknown;
};

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Props = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class" && typeof value === "string") {
      node.className = value;
    } else if (key === "on" && value && typeof value === "object") {
      for (const [ev, fn] of Object.entries(value as Record<string, EventListener>)) {
        node.addEventListener(ev, fn);
      }
    } else if (value === true) {
      node.setAttribute(key, "");
    } else if (value !== undefined && value !== null && value !== false) {
      node.setAttribute(key, String(value));
    }
  }
  for (const child of children) {
    if (child !== null && child !== undefined && child !== false) {
      node.append(child);
    }
  }
  return node;
}

/** Replaces the children of `parent` with `...nodes`. */
export function mount(parent: HTMLElement, ...nodes: Child[]): void {
  parent.replaceChildren(...nodes.filter((n): n is Node | string => n !== null && n !== undefined && n !== false));
}

/** Shows a short message in a status line. Pass an empty string to clear. */
export function setStatus(node: HTMLElement, text: string, isError = false): void {
  node.textContent = text;
  node.classList.toggle("error", isError);
}
