// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { UpdateButton } from "./UpdateButton";

const checkMock = vi.fn();
const relaunchMock = vi.fn();

vi.mock("@tauri-apps/plugin-updater", () => ({
  check: () => checkMock(),
}));

vi.mock("@tauri-apps/plugin-process", () => ({
  relaunch: () => relaunchMock(),
}));

function renderUpdateButton() {
  return render(
    <I18nProvider>
      <UpdateButton />
    </I18nProvider>,
  );
}

describe("UpdateButton", () => {
  beforeEach(() => {
    checkMock.mockReset();
    relaunchMock.mockReset();
  });

  it("shows an in-app dialog when no update is available", async () => {
    checkMock.mockResolvedValue(null);
    renderUpdateButton();

    fireEvent.click(screen.getByRole("button", { name: "Check updates" }));

    await waitFor(() => {
      expect(screen.getByRole("alertdialog")).toHaveTextContent("Up to date");
    });
  });

  it("confirms before installing an available update", async () => {
    const downloadAndInstall = vi.fn().mockResolvedValue(undefined);
    checkMock.mockResolvedValue({
      version: "0.6.0",
      downloadAndInstall,
    });
    renderUpdateButton();

    fireEvent.click(screen.getByRole("button", { name: "Check updates" }));
    await waitFor(() => {
      expect(screen.getByRole("alertdialog")).toHaveTextContent("0.6.0");
    });

    fireEvent.click(screen.getByRole("button", { name: "Download and restart" }));
    await waitFor(() => {
      expect(downloadAndInstall).toHaveBeenCalledOnce();
      expect(relaunchMock).toHaveBeenCalledOnce();
    });
  });

  it("shows a failure dialog when update check throws", async () => {
    checkMock.mockRejectedValue(new Error("network down"));
    renderUpdateButton();

    fireEvent.click(screen.getByRole("button", { name: "Check updates" }));

    await waitFor(() => {
      expect(screen.getByRole("alertdialog")).toHaveTextContent("network down");
    });
  });
});
