// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import type { ProjectStatus } from "../types";
import { ScanWorkspace } from "./ScanWorkspace";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("../hooks/useAuditReport", () => ({
  useAuditReport: () => ({ auditState: { status: "idle" }, refreshAudit: vi.fn() }),
}));
vi.mock("./AuditPanel", () => ({
  AuditPanel: () => {
    throw new Error("audit panel failed");
  },
}));
vi.mock("../setup/plan", async (original) => ({
  ...(await original<typeof import("../setup/plan")>()),
  countPendingQuickSetup: () => 0,
}));
vi.mock("./DoctorPanel", () => ({
  DoctorPanel: () => <p>doctor panel</p>,
}));

describe("ScanWorkspace", () => {
  beforeEach(() => {
    window.localStorage.setItem("shk.desktop.locale.v1", "en");
  });

  it("keeps the rest of the project view when one panel fails to render", () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    render(
      <I18nProvider>
        <ScanWorkspace
          project={{
            id: "p1",
            name: "Demo",
            path: "/tmp/demo",
            addedAt: "2026-01-01T00:00:00.000Z",
          }}
          scanState={{ status: "idle" }}
          projectStatus={{
            status: "done",
            data: {
              policy: { exists: true },
              npmHardening: { hasProjects: false },
            } as ProjectStatus,
            loadedAt: "2026-01-01T00:00:00.000Z",
          }}
          actionState={{ status: "idle" }}
          onDismissActionFeedback={vi.fn()}
          onScan={vi.fn()}
        />
      </I18nProvider>,
    );

    expect(screen.getByRole("heading", { name: "Demo" })).toBeInTheDocument();
    expect(screen.getByText("doctor panel")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("This section could not be displayed");
    errorSpy.mockRestore();
  });
});
