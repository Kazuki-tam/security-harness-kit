import { describe, expect, it } from "vitest";
import { actionFeedbackTone, localizeActionResult } from "./actionMessages";
import type { Messages } from "../i18n/types";

const actionMessages: Messages["setup"]["action"] = {
  failed: "Action failed",
  succeeded: "Action completed",
  partial: "Completed with warnings",
  resultTitles: {
    "Created shk.toml": "Policy created",
    "Installed pre-commit hook under": "Pre-commit hook installed",
  },
  resultDetails: {
    wrote_policy: "Wrote policy file",
  },
};

describe("localizeActionResult", () => {
  it("localizes exact and prefixed result titles", () => {
    expect(
      localizeActionResult(
        { success: true, message: "Created shk.toml", details: [] },
        actionMessages,
      ).title,
    ).toBe("Policy created");

    expect(
      localizeActionResult(
        {
          success: true,
          message: "Installed pre-commit hook under .git/hooks/pre-commit",
          details: [],
        },
        actionMessages,
      ).title,
    ).toBe("Pre-commit hook installed");
  });

  it("falls back to raw result text when no localization exists", () => {
    expect(
      localizeActionResult(
        {
          success: true,
          message: "Custom result",
          details: ["wrote_policy", "left untouched"],
        },
        actionMessages,
      ),
    ).toEqual({
      title: "Custom result",
      details: ["Wrote policy file", "left untouched"],
    });
  });
});

describe("actionFeedbackTone", () => {
  it("uses error for failed actions", () => {
    expect(actionFeedbackTone({ success: false, message: "Created shk.toml", details: [] })).toBe(
      "error",
    );
  });

  it("uses warning for successful actions that need review", () => {
    expect(
      actionFeedbackTone({
        success: true,
        message: "Applied partial npm hardening; review remaining items",
        details: [],
      }),
    ).toBe("warning");

    expect(
      actionFeedbackTone({
        success: true,
        message: "No changes were required for the selected fixes",
        details: [],
      }),
    ).toBe("warning");
  });

  it("uses success for completed actions without follow-up hints", () => {
    expect(actionFeedbackTone({ success: true, message: "Created shk.toml", details: [] })).toBe(
      "success",
    );
  });
});
