// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

import assert from "node:assert/strict";
import { test } from "node:test";

import { forgetRecentRoot, hasRememberedRoot } from "../../src/unlock";

// Minimal in-memory localStorage, so the per-viewer list can be exercised without a browser.
function installStorage(initial: Record<string, string>): Map<string, string> {
  const store = new Map(Object.entries(initial));
  (globalThis as { localStorage?: unknown }).localStorage = {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, String(v)),
    removeItem: (k: string) => void store.delete(k),
  };
  return store;
}

test("forgetting a recent vault removes only that entry from the list", () => {
  const store = installStorage({
    "tpt-vault.recentRoots": JSON.stringify(["/vaults/a", "/vaults/b"]),
    "tpt-vault.lastRoot": "/vaults/b",
  });
  const remaining = forgetRecentRoot("/vaults/a");
  assert.deepEqual(remaining, ["/vaults/b"]);
  assert.equal(store.get("tpt-vault.lastRoot"), "/vaults/b");
});

test("forgetting the remembered vault clears the first-run marker", () => {
  installStorage({
    "tpt-vault.recentRoots": JSON.stringify(["/vaults/a"]),
    "tpt-vault.lastRoot": "/vaults/a",
  });
  assert.equal(hasRememberedRoot(), true);
  assert.deepEqual(forgetRecentRoot("/vaults/a"), []);
  assert.equal(hasRememberedRoot(), false);
});

test("forgetting an unknown folder leaves the list as it was", () => {
  installStorage({ "tpt-vault.recentRoots": JSON.stringify(["/vaults/a"]) });
  assert.deepEqual(forgetRecentRoot("/nowhere"), ["/vaults/a"]);
});
