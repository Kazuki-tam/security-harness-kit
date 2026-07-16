// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { I18nProvider } from "./i18n";

const invokeMock = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

vi.mock("@tauri-apps/api/webview", () => ({
  getCurrentWebview: () => ({
    onDragDropEvent: vi.fn().mockResolvedValue(() => undefined),
  }),
}));

describe("App", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
    window.localStorage.clear();
    window.localStorage.setItem("shk.desktop.locale.v1", "en");
  });

  it("opens Mask for AI without a project", () => {
    render(
      <I18nProvider>
        <App />
      </I18nProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: "Mask for AI" }));

    expect(screen.getByRole("heading", { name: "Mask for AI" })).toBeInTheDocument();
  });

  it.each([
    ["medium", "1 item(s) masked — review the output before sharing"],
    ["high", "1 item(s) need review before sharing"],
  ])("describes a %s finding without marking masked output as safe", async (severity, expected) => {
    invokeMock.mockResolvedValue({
      masked_content: "contact=[REDACTED]",
      findings: [
        {
          rule_id: "pii.email",
          severity,
          kind: "pii",
          file: "<input>",
          line: 1,
          column: 9,
          message: "Possible email address detected",
          redacted_value: "[REDACTED]",
          confidence: 0.95,
        },
      ],
    });

    render(
      <I18nProvider>
        <App />
      </I18nProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: "Mask for AI" }));
    fireEvent.change(screen.getByPlaceholderText("Paste prompt text, logs, or notes here…"), {
      target: { value: "synthetic sensitive input" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Mask" }));

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent(expected);
    });
    expect(screen.getByRole("textbox", { name: "Masked output" })).toHaveValue(
      "contact=[REDACTED]",
    );
    expect(
      screen.queryByText("No high-risk items detected — safe to copy"),
    ).not.toBeInTheDocument();
  });

  it("reports clipboard failures to the user", async () => {
    invokeMock.mockResolvedValue({
      masked_content: "[REDACTED]",
      findings: [],
    });
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockRejectedValue(new Error("clipboard denied")) },
    });

    render(
      <I18nProvider>
        <App />
      </I18nProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: "Mask for AI" }));
    fireEvent.change(screen.getByPlaceholderText("Paste prompt text, logs, or notes here…"), {
      target: { value: "synthetic sensitive input" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Mask" }));
    await screen.findByRole("textbox", { name: "Masked output" });

    fireEvent.click(screen.getByRole("button", { name: "Copy masked text" }));

    expect(
      await screen.findByText("Could not copy to clipboard: clipboard denied"),
    ).toBeInTheDocument();
  });
});
