// @vitest-environment jsdom
import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import desktopCapability from "../../src-tauri/capabilities/default.json";
import { I18nProvider } from "../i18n";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

describe("window drag regions", () => {
  it("allows the native Tauri window dragging command", () => {
    expect(desktopCapability.permissions).toContain("core:window:allow-start-dragging");
  });

  it("marks the top bar as a Tauri drag region while excluding controls", () => {
    const { container } = render(
      <I18nProvider>
        <TopBar
          view="welcome"
          project={null}
          preferredApp="cursor"
          onOpenInApp={vi.fn()}
          onShowHelp={vi.fn()}
        />
      </I18nProvider>,
    );

    expect(container.querySelector(".shk-drag")).toHaveAttribute("data-tauri-drag-region");
    expect(container.querySelector(".shk-no-drag")).not.toHaveAttribute("data-tauri-drag-region");
  });

  it("provides draggable space above the sidebar controls", () => {
    const { container } = render(
      <I18nProvider>
        <Sidebar
          projects={[]}
          selectedId={null}
          onSelect={vi.fn()}
          onShowWelcome={vi.fn()}
          onShowMask={vi.fn()}
          onAdd={vi.fn()}
          onRemove={vi.fn()}
          onRename={vi.fn()}
          appVersion="0.5.0"
        />
      </I18nProvider>,
    );

    expect(container.querySelectorAll("[data-tauri-drag-region]")).toHaveLength(2);
  });
});
