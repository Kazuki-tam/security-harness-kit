import { describe, expect, it } from "vitest";
import { isPreferredIde } from "./ide";

describe("ide preferences", () => {
  it("validates known IDE ids", () => {
    expect(isPreferredIde("cursor")).toBe(true);
    expect(isPreferredIde("vscode")).toBe(true);
    expect(isPreferredIde("antigravity")).toBe(true);
    expect(isPreferredIde("emacs")).toBe(false);
    expect(isPreferredIde(null)).toBe(false);
  });
});
