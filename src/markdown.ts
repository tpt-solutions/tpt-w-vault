// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

// A small markdown renderer for note previews. It covers headings, paragraphs, lists, fenced
// code, quotes, rules, pipe tables, and inline code, bold, italic and links.
//
// Output is DOM nodes built with `el`, never HTML strings. Links are shown as text with the
// address in brackets, not as anchors: an anchor in the Tauri webview would navigate the app
// away from the vault. Only http, https and mailto addresses are shown, and the rest are text.

import { el } from "./dom";

export type Inline =
  | { kind: "text"; text: string }
  | { kind: "code"; text: string }
  | { kind: "strong"; text: string }
  | { kind: "em"; text: string }
  | { kind: "link"; text: string; href: string };

export type Block =
  | { type: "heading"; level: number; text: string }
  | { type: "paragraph"; text: string }
  | { type: "code"; lang: string; text: string }
  | { type: "list"; ordered: boolean; items: string[] }
  | { type: "quote"; text: string }
  | { type: "hr" }
  | { type: "table"; header: string[]; rows: string[][] };

const INLINE_RE =
  /`([^`\n]+)`|\[([^\]\n]+)\]\(([^)\s]+)\)|\*\*([^*\n]+)\*\*|\*([^*\n]+)\*/g;

/** Splits one line of text into styled spans. Nesting is not supported. */
export function parseInline(src: string): Inline[] {
  const out: Inline[] = [];
  let last = 0;
  for (const m of src.matchAll(INLINE_RE)) {
    const at = m.index ?? 0;
    if (at > last) out.push({ kind: "text", text: src.slice(last, at) });
    if (m[1] !== undefined) out.push({ kind: "code", text: m[1] });
    else if (m[2] !== undefined) out.push({ kind: "link", text: m[2], href: m[3] });
    else if (m[4] !== undefined) out.push({ kind: "strong", text: m[4] });
    else if (m[5] !== undefined) out.push({ kind: "em", text: m[5] });
    last = at + m[0].length;
  }
  if (last < src.length) out.push({ kind: "text", text: src.slice(last) });
  return out;
}

const FENCE_OPEN = /^\s*```\s*([\w+.-]*)\s*$/;
const FENCE_CLOSE = /^\s*```\s*$/;
const HEADING = /^(#{1,6})\s+(.+?)\s*$/;
const HR = /^\s*([-*_])(\s*\1){2,}\s*$/;
const QUOTE = /^\s*>\s?/;
const BULLET = /^\s*[-*+]\s+/;
const ORDERED = /^\s*\d+[.)]\s+/;
const TABLE_RULE = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;

function splitRow(line: string): string[] {
  let s = line.trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|")) s = s.slice(0, -1);
  return s.split("|").map((cell) => cell.trim());
}

function startsBlock(line: string): boolean {
  return (
    FENCE_OPEN.test(line) ||
    HEADING.test(line) ||
    HR.test(line) ||
    QUOTE.test(line) ||
    BULLET.test(line) ||
    ORDERED.test(line)
  );
}

/** Parses markdown source into blocks. Unknown syntax is kept as paragraph text. */
export function parseMarkdown(source: string): Block[] {
  const lines = source.replace(/\r\n?/g, "\n").split("\n");
  const blocks: Block[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    if (line.trim() === "") {
      i++;
      continue;
    }

    const fence = FENCE_OPEN.exec(line);
    if (fence) {
      const body: string[] = [];
      i++;
      // An unclosed fence runs to the end of the note, as in CommonMark.
      while (i < lines.length && !FENCE_CLOSE.test(lines[i])) {
        body.push(lines[i]);
        i++;
      }
      i++;
      blocks.push({ type: "code", lang: fence[1], text: body.join("\n") });
      continue;
    }

    const heading = HEADING.exec(line);
    if (heading) {
      blocks.push({ type: "heading", level: heading[1].length, text: heading[2] });
      i++;
      continue;
    }

    if (HR.test(line)) {
      blocks.push({ type: "hr" });
      i++;
      continue;
    }

    if (QUOTE.test(line)) {
      const parts: string[] = [];
      while (i < lines.length && QUOTE.test(lines[i])) {
        parts.push(lines[i].replace(QUOTE, ""));
        i++;
      }
      blocks.push({ type: "quote", text: parts.join(" ") });
      continue;
    }

    if (BULLET.test(line) || ORDERED.test(line)) {
      const ordered = ORDERED.test(line);
      const marker = ordered ? ORDERED : BULLET;
      const items: string[] = [];
      while (i < lines.length && marker.test(lines[i])) {
        items.push(lines[i].replace(marker, ""));
        i++;
      }
      blocks.push({ type: "list", ordered, items });
      continue;
    }

    if (line.includes("|") && i + 1 < lines.length && TABLE_RULE.test(lines[i + 1])) {
      const header = splitRow(line);
      const rows: string[][] = [];
      i += 2;
      while (i < lines.length && lines[i].includes("|") && lines[i].trim() !== "") {
        rows.push(splitRow(lines[i]));
        i++;
      }
      blocks.push({ type: "table", header, rows });
      continue;
    }

    // Paragraph: consecutive lines up to a blank line or the start of another block.
    const parts = [line.trim()];
    i++;
    while (i < lines.length && lines[i].trim() !== "" && !startsBlock(lines[i])) {
      parts.push(lines[i].trim());
      i++;
    }
    blocks.push({ type: "paragraph", text: parts.join(" ") });
  }
  return blocks;
}

const SAFE_HREF = /^(https?:|mailto:)/i;

function inlineNodes(text: string): (Node | string)[] {
  return parseInline(text).map((span) => {
    switch (span.kind) {
      case "code":
        return el("code", {}, span.text);
      case "strong":
        return el("strong", {}, span.text);
      case "em":
        return el("em", {}, span.text);
      case "link": {
        // Shown as text. The address follows in brackets, and only safe schemes are shown.
        if (!SAFE_HREF.test(span.href)) return span.text;
        return el("span", { class: "md-link", title: span.href }, `${span.text} (${span.href})`);
      }
      default:
        return span.text;
    }
  });
}

function blockNode(block: Block): Node {
  switch (block.type) {
    case "heading": {
      const level = Math.min(Math.max(block.level, 1), 6);
      return el(`h${level}` as "h1", {}, ...inlineNodes(block.text));
    }
    case "paragraph":
      return el("p", {}, ...inlineNodes(block.text));
    case "code":
      return el(
        "pre",
        { class: "md-code", "data-lang": block.lang || null },
        el("code", {}, block.text),
      );
    case "list":
      return el(
        block.ordered ? "ol" : "ul",
        {},
        ...block.items.map((item) => el("li", {}, ...inlineNodes(item))),
      );
    case "quote":
      return el("blockquote", {}, ...inlineNodes(block.text));
    case "hr":
      return el("hr", {});
    case "table":
      return el(
        "table",
        {},
        el(
          "thead",
          {},
          el("tr", {}, ...block.header.map((cell) => el("th", {}, ...inlineNodes(cell)))),
        ),
        el(
          "tbody",
          {},
          ...block.rows.map((row) =>
            el("tr", {}, ...row.map((cell) => el("td", {}, ...inlineNodes(cell)))),
          ),
        ),
      );
  }
}

/** Renders markdown source as a DOM tree. Safe for untrusted note text. */
export function renderMarkdown(source: string): HTMLElement {
  return el("div", { class: "markdown" }, ...parseMarkdown(source).map(blockNode));
}
