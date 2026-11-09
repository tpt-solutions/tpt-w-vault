// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

import assert from "node:assert/strict";
import { test } from "node:test";

import { isNote, joinPath, validName, validPath } from "../../src/browser";
import { passphraseProblem } from "../../src/settings";

test("paths join with / and the root is empty", () => {
  assert.equal(joinPath("", "a.md"), "a.md");
  assert.equal(joinPath("work/deep", "a.md"), "work/deep/a.md");
});

test("entry names reject separators, dots and empty input", () => {
  assert.equal(validName(""), "Enter a name.");
  assert.equal(validName(".."), "That name is not allowed.");
  assert.notEqual(validName("a/b"), null);
  assert.notEqual(validName("a" + String.fromCharCode(92) + "b"), null);
  assert.equal(validName("ideas.md"), null);
});

test("note detection is by extension, case-insensitively", () => {
  assert.equal(isNote("Plan.MD"), true);
  assert.equal(isNote(".md"), false);
  assert.equal(isNote("photo.png"), false);
});

test("passphrase rules: length, then match", () => {
  assert.notEqual(passphraseProblem("short", "short"), null);
  assert.notEqual(passphraseProblem("eight-ch", "eight-cx"), null);
  assert.equal(passphraseProblem("eight-ch", "eight-ch"), null);
  // Length counts characters, not bytes.
  assert.equal(passphraseProblem("ééééééé日", "ééééééé日"), null);
});

test("full paths are checked part by part", () => {
  assert.equal(validPath("work/plan.md"), null);
  assert.notEqual(validPath("work//plan.md"), null);
  assert.notEqual(validPath("work/plan.md/"), null);
  assert.notEqual(validPath("../escape"), null);
  assert.notEqual(validPath(""), null);
});
