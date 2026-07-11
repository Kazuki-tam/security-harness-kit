import { describe, expect, it, vi } from "vitest";
import { detectBrowserLocale, resolveInitialLocale } from "./localeDetection";

describe("locale detection", () => {
  it("prefers Japanese when the browser locale starts with ja", () => {
    vi.stubGlobal("navigator", { language: "ja-JP", languages: ["ja-JP", "en-US"] });
    expect(detectBrowserLocale()).toBe("ja");
    vi.unstubAllGlobals();
  });

  it("falls back to English for other browser locales", () => {
    vi.stubGlobal("navigator", { language: "fr-FR", languages: ["fr-FR"] });
    expect(detectBrowserLocale()).toBe("en");
    vi.unstubAllGlobals();
  });

  it("prefers stored locale over browser detection", () => {
    vi.stubGlobal("navigator", { language: "ja-JP", languages: ["ja-JP"] });
    expect(resolveInitialLocale("en")).toBe("en");
    vi.unstubAllGlobals();
  });

  it("uses browser locale when storage is empty", () => {
    vi.stubGlobal("navigator", { language: "ja-JP", languages: ["ja-JP"] });
    expect(resolveInitialLocale(null)).toBe("ja");
    vi.unstubAllGlobals();
  });
});
