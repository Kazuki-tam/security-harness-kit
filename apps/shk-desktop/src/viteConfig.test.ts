import { describe, expect, it } from "vitest";
import config from "../vite.config";

describe("vite env exposure", () => {
  it("never exposes the updater signing variables to the bundle", () => {
    const prefixes = [(config as { envPrefix?: string | string[] }).envPrefix ?? "VITE_"].flat();

    expect(prefixes).toEqual(["VITE_", "TAURI_ENV_"]);
    for (const name of [
      "TAURI_SIGNING_PRIVATE_KEY",
      "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
      "TAURI_UPDATER_PUBKEY",
    ]) {
      expect(prefixes.some((prefix) => name.startsWith(prefix))).toBe(false);
    }
  });
});
