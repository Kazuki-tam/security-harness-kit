// @vitest-environment jsdom
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import type { ProjectStatus } from "../types";
import { QuickSetupCard } from "./QuickSetupCard";

function status(): ProjectStatus {
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
    ],
    ignoreFixTargets: [{ name: ".gitignore", exists: true }],
    recommendedFixes: [
      {
        id: "env_encrypt",
        severity: "warning",
        message: "Encrypt env files",
        requiresPolicy: true,
        defaultSelected: false,
      },
    ],
    cliInstalled: false,
  };
}

function renderCard(onQuickSetup = vi.fn()) {
  render(
    <I18nProvider>
      <QuickSetupCard status={status()} running={false} onQuickSetup={onQuickSetup} />
    </I18nProvider>,
  );
  fireEvent.click(screen.getByRole("button", { name: "Review and adjust items" }));
  fireEvent.click(screen.getByRole("checkbox", { name: /Encrypt plaintext \.env files/ }));
  return onQuickSetup;
}

describe("QuickSetupCard env target selection", () => {
  beforeEach(() => {
    window.localStorage.setItem("shk.desktop.locale.v1", "en");
  });

  it("submits only the env files selected by the user", () => {
    const onQuickSetup = renderCard();
    fireEvent.click(screen.getByRole("checkbox", { name: /\.env\.production/ }));
    fireEvent.click(screen.getByRole("button", { name: "Apply recommended setup" }));

    expect(onQuickSetup).toHaveBeenCalledWith(["env_encrypt"], [".gitignore"], [".env"]);
  });

  it("does not allow an explicit empty env selection", () => {
    const onQuickSetup = renderCard();
    fireEvent.click(screen.getByRole("checkbox", { name: /^\.envPlaintext$/ }));
    fireEvent.click(screen.getByRole("checkbox", { name: /\.env\.production/ }));

    const apply = screen.getByRole("button", { name: "Apply recommended setup" });
    expect(apply).toBeDisabled();
    expect(screen.getByText("Select at least one env file to encrypt.")).toBeInTheDocument();
    fireEvent.click(apply);
    expect(onQuickSetup).not.toHaveBeenCalled();
  });
});
