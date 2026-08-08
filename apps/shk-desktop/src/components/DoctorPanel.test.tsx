// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { I18nProvider } from "../i18n";
import type { DoctorStatus, EnvFileReport } from "../types";
import { DoctorPanel } from "./DoctorPanel";

function doctor(overrides: Partial<DoctorStatus> = {}): DoctorStatus {
  return {
    gitPreCommit: true,
    aiManagedHooks: true,
    ignoreOk: true,
    missingIgnorePatterns: [],
    claudeDenyOk: true,
    claudeSandboxOk: true,
    codexConfigOk: true,
    envApplicable: true,
    envOk: false,
    npmOk: true,
    workflowsApplicable: false,
    workflowsOk: true,
    issues: [],
    ...overrides,
  };
}

function renderPanel(envFiles: EnvFileReport[], overrides: Partial<DoctorStatus> = {}) {
  return render(
    <I18nProvider>
      <DoctorPanel doctor={doctor(overrides)} npmApplicable={false} envFiles={envFiles} />
    </I18nProvider>,
  );
}

describe("DoctorPanel env files", () => {
  it("lists plaintext keys per env file without values", () => {
    renderPanel([
      {
        name: ".env",
        state: "plaintext",
        plaintextKeys: ["API_KEY", "DB_URL"],
        encryptedKeyCount: 0,
      },
      {
        name: ".env.production",
        state: "encrypted",
        plaintextKeys: [],
        encryptedKeyCount: 3,
      },
    ]);

    expect(screen.getByText(".env")).toBeInTheDocument();
    expect(screen.getByText("API_KEY")).toBeInTheDocument();
    expect(screen.getByText("DB_URL")).toBeInTheDocument();
    expect(screen.getByText("Plaintext")).toBeInTheDocument();
    expect(screen.getByText(".env.production")).toBeInTheDocument();
    expect(screen.getByText("Encrypted")).toBeInTheDocument();
    expect(screen.getByText("3 encrypted value(s)")).toBeInTheDocument();
  });

  it("collapses long plaintext key lists", () => {
    renderPanel([
      {
        name: ".env",
        state: "mixed",
        plaintextKeys: ["K1", "K2", "K3", "K4", "K5", "K6", "K7", "K8"],
        encryptedKeyCount: 1,
      },
    ]);

    expect(screen.getByText("K6")).toBeInTheDocument();
    expect(screen.queryByText("K7")).not.toBeInTheDocument();
    expect(screen.getByText("+2 more")).toBeInTheDocument();
    expect(screen.getByText("Partially encrypted")).toBeInTheDocument();
  });

  it("renders duplicate dotenv keys without collapsing either entry", () => {
    renderPanel([
      {
        name: ".env",
        state: "plaintext",
        plaintextKeys: ["DUPLICATE", "DUPLICATE"],
        encryptedKeyCount: 0,
      },
    ]);

    expect(screen.getAllByText("DUPLICATE")).toHaveLength(2);
  });

  it("hides the env section when no env files exist", () => {
    renderPanel([], { envApplicable: false, envOk: true });
    expect(screen.queryByText("Env files")).not.toBeInTheDocument();
  });
});
