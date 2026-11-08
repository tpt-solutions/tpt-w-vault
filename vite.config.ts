// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

import { defineConfig } from "vite";

export default defineConfig({
  root: ".",
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { outDir: "dist", target: "es2022" },
});
