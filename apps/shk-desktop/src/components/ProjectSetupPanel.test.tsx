// @vitest-environment jsdom
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import type { ActionState, ProjectStatus, SetupHandlers } from "../types";
import { ProjectSetupPanel } from "./ProjectSetupPanel";

function status(overrides: Partial<ProjectStatus> = {}): ProjectStatus {
  return {
    path: "/workspace/demo",
    policy: { exists: true, path: "/workspace/demo/shk.toml" },
    git: { isRepo: false },
    hooks: {
      preCommit: { installed: false, isGitRepo: false },
      aiTools: [],
    },
    doctor: {
      gitPreCommit: false,
      aiManagedHooks: false,
      ignoreOk: true,
      missingIgnorePatterns: [],
      claudeDenyOk: false,
      claudeSandboxOk: false,
      codexConfigOk: false,
      envApplicable: true,
      envOk: false,
      npmOk: true,
      workflowsApplicable: false,
      workflowsOk: true,
      issues: [],
    },
    aiSafetyApplied: {
      scanHooksClaudeCode: false,
      scanHooksCursor: false,
      scanHooksCodex: false,
      scanHooksCopilot: false,
      scanHooksAntigravity: false,
      scanHooksWindsurf: false,
      claudeDeny: false,
      claudeSandbox: false,
      codexSandbox: false,
    },
    npmHardening: {
      hasProjects: false,
      ok: true,
      settingsOk: true,
      packageCount: 0,
      missingLockfiles: [],
      ignoreScriptsOk: true,
      ageGatesOk: true,
      dependencyBotCooldownOk: true,
      recommendations: [],
    },
    skills: [],
    envFiles: [
      {
        name: ".env",
        state: "plaintext",
        plaintextKeys: ["API_KEY"],
        encryptedKeyCount: 0,
      },
      {
        name: ".env.production",
        state: "mixed",
        plaintextKeys: ["PLAIN_VALUE"],
        encryptedKeyCount: 1,
      },
      {
        name: ".env.staging",
        state: "encrypted",
        plaintextKeys: [],
        encryptedKeyCount: 3,
      },
    ],
    ignoreFixTargets: [{ name: ".gitignore", exists: true }],
    recommendedFixes: [],
    cliInstalled: false,
    ...overrides,
  };
}

function handlers(overrides: Partial<SetupHandlers> = {}): SetupHandlers {
  return {
    onQuickSetup: vi.fn(),
    onInitPolicy: vi.fn(),
    onFixDoctorIgnore: vi.fn(),
    onInstallPreCommit: vi.fn(),
    onInstallAiHooks: vi.fn(),
    onEncryptEnv: vi.fn(),
    onApplyNpmHardening: vi.fn(),
    onInstallSkills: vi.fn(),
    ...overrides,
  };
}

const idle: ActionState = { status: "idle" };

function renderPanel(projectStatus = status(), setupHandlers = handlers()) {
  render(
    <I18nProvider>
      <ProjectSetupPanel
        status={projectStatus}
        actionState={idle}
        onDismissActionFeedback={vi.fn()}
        {...setupHandlers}
      />
    </I18nProvider>,
  );
  return setupHandlers;
}

function openAdvanced() {
  fireEvent.click(screen.getByRole("button", { name: "Open advanced settings" }));
}

describe("ProjectSetupPanel env encryption card", () => {
  beforeEach(() => {
    window.localStorage.setItem("shk.desktop.locale.v1", "en");
  });

  it("encrypts only the env files the user left selected", () => {
    const setupHandlers = renderPanel();
    openAdvanced();

    fireEvent.click(screen.getByRole("checkbox", { name: /\.env\.production/ }));
    fireEvent.click(screen.getByRole("button", { name: "Encrypt selected env files" }));

    expect(setupHandlers.onEncryptEnv).toHaveBeenCalledWith([".env"]);
  });

  it("shows already-encrypted files without a checkbox", () => {
    renderPanel();
    openAdvanced();

    expect(screen.getByText(".env.staging")).toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: /\.env\.staging/ })).not.toBeInTheDocument();
  });

  it("disables encryption and explains when no policy exists", () => {
    const setupHandlers = renderPanel(status({ policy: { exists: false } }));
    openAdvanced();

    const encrypt = screen.getByRole("button", { name: "Encrypt selected env files" });
    expect(encrypt).toBeDisabled();
    fireEvent.click(encrypt);
    expect(setupHandlers.onEncryptEnv).not.toHaveBeenCalled();
  });

  it("blocks an explicit empty selection", () => {
    const setupHandlers = renderPanel();
    openAdvanced();

    fireEvent.click(screen.getByRole("checkbox", { name: /^\.envPlaintext$/ }));
    fireEvent.click(screen.getByRole("checkbox", { name: /\.env\.production/ }));

    const encrypt = screen.getByRole("button", { name: "Encrypt selected env files" });
    expect(encrypt).toBeDisabled();
    expect(screen.getByText("Select at least one env file to encrypt.")).toBeInTheDocument();
    expect(setupHandlers.onEncryptEnv).not.toHaveBeenCalled();
  });

  it("hides the card when the project has no env files", () => {
    renderPanel(status({ envFiles: [] }));
    openAdvanced();

    expect(
      screen.queryByRole("button", { name: "Encrypt selected env files" }),
    ).not.toBeInTheDocument();
  });
});
