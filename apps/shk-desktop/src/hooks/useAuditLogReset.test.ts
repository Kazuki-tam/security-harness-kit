import { beforeEach, describe, expect, it, vi } from "vitest";
import { performAuditLogReset } from "./useAuditLogReset";

vi.mock("../project", () => ({
  clearAuditLog: vi.fn(),
}));

import { clearAuditLog } from "../project";

const clearAuditLogMock = vi.mocked(clearAuditLog);

describe("performAuditLogReset", () => {
  beforeEach(() => {
    clearAuditLogMock.mockReset();
  });

  it("returns ok when the backend clears the log", async () => {
    clearAuditLogMock.mockResolvedValue({
      success: true,
      message: "Cleared 1 audit log file(s)",
      details: [],
    });

    await expect(performAuditLogReset("/tmp/project", "fallback")).resolves.toEqual({ ok: true });
    expect(clearAuditLogMock).toHaveBeenCalledWith("/tmp/project");
  });

  it("returns the backend failure message", async () => {
    clearAuditLogMock.mockResolvedValue({
      success: false,
      message: "refused",
      details: [],
    });

    await expect(performAuditLogReset("/tmp/project", "fallback")).resolves.toEqual({
      ok: false,
      message: "refused",
    });
  });

  it("returns thrown error messages", async () => {
    clearAuditLogMock.mockRejectedValue(new Error("network down"));

    await expect(performAuditLogReset("/tmp/project", "fallback")).resolves.toEqual({
      ok: false,
      message: "network down",
    });
  });
});
