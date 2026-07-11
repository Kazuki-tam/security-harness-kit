import { describe, expect, it } from "vitest";
import { interpolate, operationErrorMessage } from "./interpolate";

describe("interpolate", () => {
  it("replaces named placeholders", () => {
    expect(interpolate("Version {{version}} failed", { version: "1.2.3" })).toBe(
      "Version 1.2.3 failed",
    );
  });
});

describe("operationErrorMessage", () => {
  it("includes the error detail", () => {
    expect(operationErrorMessage("Operation failed: {{message}}", new Error("disk full"))).toBe(
      "Operation failed: disk full",
    );
  });
});
