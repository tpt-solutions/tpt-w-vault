// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

import assert from "node:assert/strict";
import { test } from "node:test";

import { insertSnippet } from "../../src/editor";

test("a selection fills the placeholder and the cursor ends after the snippet", () => {
  const r = insertSnippet("hello world", 6, 11, "[{}](https://)");
  assert.equal(r.text, "hello [world](https://)");
  assert.equal(r.cursor, r.text.length);
});

test("with no selection the cursor lands on the placeholder", () => {
  const r = insertSnippet("ab", 1, 1, "- {}\n");
  assert.equal(r.text, "a- \nb");
  assert.equal(r.cursor, 3);
});
