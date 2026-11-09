// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseInline, parseMarkdown } from "../../src/markdown";

test("headings keep their level and text", () => {
  assert.deepEqual(parseMarkdown("## Title here"), [
    { type: "heading", level: 2, text: "Title here" },
  ]);
});

test("a hash without a space is not a heading", () => {
  assert.deepEqual(parseMarkdown("#tag"), [{ type: "paragraph", text: "#tag" }]);
});

test("consecutive lines form one paragraph, a blank line ends it", () => {
  assert.deepEqual(parseMarkdown("one\ntwo\n\nthree"), [
    { type: "paragraph", text: "one two" },
    { type: "paragraph", text: "three" },
  ]);
});

test("bullet and numbered lists", () => {
  assert.deepEqual(parseMarkdown("- a\n- b\n\n1. x\n2. y"), [
    { type: "list", ordered: false, items: ["a", "b"] },
    { type: "list", ordered: true, items: ["x", "y"] },
  ]);
});

test("fenced code keeps its text verbatim, including markdown inside", () => {
  const src = "```rust\n# not a heading\n- not a list\n```";
  assert.deepEqual(parseMarkdown(src), [
    { type: "code", lang: "rust", text: "# not a heading\n- not a list" },
  ]);
});

test("an unclosed fence runs to the end of the note", () => {
  assert.deepEqual(parseMarkdown("```\nline"), [{ type: "code", lang: "", text: "line" }]);
});

test("quotes, rules and tables", () => {
  const src = "> quoted\n> more\n\n---\n\n| Name | Qty |\n| :--- | ---: |\n| apple | 3 |\n| pear | 5 |";
  assert.deepEqual(parseMarkdown(src), [
    { type: "quote", text: "quoted more" },
    { type: "hr" },
    {
      type: "table",
      header: ["Name", "Qty"],
      rows: [
        ["apple", "3"],
        ["pear", "5"],
      ],
    },
  ]);
});

test("a pipe line without a rule under it is a paragraph", () => {
  assert.deepEqual(parseMarkdown("a | b"), [{ type: "paragraph", text: "a | b" }]);
});

test("inline code, bold, italic and links", () => {
  assert.deepEqual(parseInline("use `x` and **bold** and *it* and [site](https://example.com)"), [
    { kind: "text", text: "use " },
    { kind: "code", text: "x" },
    { kind: "text", text: " and " },
    { kind: "strong", text: "bold" },
    { kind: "text", text: " and " },
    { kind: "em", text: "it" },
    { kind: "text", text: " and " },
    { kind: "link", text: "site", href: "https://example.com" },
  ]);
});

test("inline markers inside code are not styled", () => {
  assert.deepEqual(parseInline("`**no**`"), [{ kind: "code", text: "**no**" }]);
});

test("CRLF line endings parse the same as LF", () => {
  assert.deepEqual(parseMarkdown("# A\r\n\r\nB"), parseMarkdown("# A\n\nB"));
});
