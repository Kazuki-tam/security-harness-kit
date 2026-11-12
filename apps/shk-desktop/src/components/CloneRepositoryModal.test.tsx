// @vitest-environment jsdom
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import { CloneRepositoryModal } from "./CloneRepositoryModal";

function renderModal(onClone: (remoteUrl: string) => Promise<boolean>) {
  const onClose = vi.fn();
  render(
    <I18nProvider>
      <CloneRepositoryModal open onClose={onClose} onClone={onClone} />
    </I18nProvider>,
  );
  fireEvent.change(screen.getByRole("textbox", { name: "Repository URL" }), {
    target: { value: "https://example.com/owner/repository.git" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Clone" }));
  return onClose;
}

describe("CloneRepositoryModal", () => {
  beforeEach(() => {
    window.localStorage.setItem("shk.desktop.locale.v1", "en");
  });

  it("shows why the clone failed and stays open", async () => {
    const onClose = renderModal(vi.fn().mockRejectedValue(new Error("authentication failed")));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Failed to clone repository");
    expect(alert).toHaveTextContent("authentication failed");
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Clone" })).toBeEnabled();
  });

  it("closes after a successful clone", async () => {
    const onClose = renderModal(vi.fn().mockResolvedValue(true));

    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
  });

  it("stays open without an error when the destination picker is cancelled", async () => {
    const onClose = renderModal(vi.fn().mockResolvedValue(false));

    await vi.waitFor(() => expect(screen.getByRole("button", { name: "Clone" })).toBeEnabled());
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
