// @vitest-environment jsdom
import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { Sidebar } from "./Sidebar";

afterEach(() => vi.useRealTimers());

it("keeps removal confirmation available without a time limit and resets it on reopening", () => {
  vi.useFakeTimers();
  localStorage.setItem("shk.desktop.locale.v1", "en");
  const onRemove = vi.fn();
  render(
    <I18nProvider>
      <Sidebar
        projects={[{ id: "demo", name: "Demo", path: "/tmp/demo", addedAt: "2026-01-01" }]}
        selectedId="demo"
        onSelect={vi.fn()}
        onShowWelcome={vi.fn()}
        onShowMask={vi.fn()}
        onAdd={vi.fn()}
        onRemove={onRemove}
        onRename={vi.fn()}
        appVersion="0.7.0"
      />
    </I18nProvider>,
  );
  const menu = screen.getByRole("button", { name: /Demo.*menu/i });
  fireEvent.click(menu);
  fireEvent.click(screen.getByRole("menuitem", { name: /keep files/i }));
  act(() => vi.advanceTimersByTime(60_000));
  expect(screen.getByRole("menuitem", { name: /confirm/i })).toBeVisible();
  expect(onRemove).not.toHaveBeenCalled();

  fireEvent.keyDown(window, { key: "Escape" });
  fireEvent.click(menu);
  fireEvent.click(screen.getByRole("menuitem", { name: /keep files/i }));
  expect(onRemove).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("menuitem", { name: /confirm/i }));
  expect(onRemove).toHaveBeenCalledExactlyOnceWith("demo");
});
