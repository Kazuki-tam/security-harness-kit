// @vitest-environment jsdom
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { I18nProvider } from "./i18n";

vi.mock("@tauri-apps/api/webview", () => ({
  getCurrentWebview: () => ({
    onDragDropEvent: vi.fn().mockResolvedValue(() => undefined),
  }),
}));

describe("App navigation", () => {
  beforeEach(() => {
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
});
