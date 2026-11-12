/// <reference types="vitest" />
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  // Only `TAURI_ENV_*` (set by the Tauri CLI) is safe to expose. A bare `TAURI_`
  // prefix would make `TAURI_SIGNING_PRIVATE_KEY` and its password eligible for
  // inlining into the shipped bundle.
  envPrefix: ["VITE_", "TAURI_ENV_"],
  build: {
    // Never inline assets as data: URIs. The Tauri CSP (`img-src 'self' asset:`)
    // does not allow `data:`, so an inlined app-logo.svg renders as a broken image
    // in the packaged app (it only works in `tauri dev`, where Vite serves the file).
    assetsInlineLimit: 0,
  },
  test: {
    environment: "node",
    globals: true,
    environmentMatchGlobs: [["src/**/*.test.tsx", "jsdom"]],
    setupFiles: ["./src/test/setup.ts"],
  },
});
