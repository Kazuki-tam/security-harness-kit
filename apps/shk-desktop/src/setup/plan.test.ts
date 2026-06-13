import { describe, expect, it } from "vitest";
import {
  aiHookSelectionHasAdditions,
  aiHookSelectionHasRemovals,
  aiHookSelectionIsFullyDisabled,
  aiHookSelectionMatches,
  aiSafetyReady,
  buildQuickSetupSteps,
  defaultQuickSetupIgnoreTargets,
  defaultRecommendedFixIds,
  npmSettingsReady,
  projectSkillsInstalled,
  quickSetupCanApply,
} from "./plan";
import type { ProjectStatus, RecommendedFix } from "../types";

function fix(
  id: string,
  options: Partial<Pick<RecommendedFix, "defaultSelected" | "requiresPolicy">> = {},
): RecommendedFix {
  return {
    id,
    severity: "warning",
    message: id,
    requiresPolicy: options.requiresPolicy ?? false,
    defaultSelected: options.defaultSelected ?? true,
  };
}

function status(overrides: Partial<ProjectStatus> = {}): ProjectStatus {
  return {
    path: "/workspace/demo",
    policy: { exists: true },
    git: { isRepo: true, root: "/workspace/demo" },
    hooks: {
      preCommit: { installed: false, isGitRepo: true },
      aiTools: [
        {
          tool: "cursor",
          configPath: "/workspace/demo/.cursor/hooks.json",
          installed: false,
        },
      ],
    },
    doctor: {
      gitPreCommit: false,
      aiManagedHooks: false,
      ignoreOk: false,
      missingIgnorePatterns: [".env"],
      claudeDenyOk: false,
      claudeSandboxOk: false,
      codexConfigOk: false,
      envApplicable: false,
      envOk: true,
      npmOk: false,
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
      hasProjects: true,
      ok: false,
      settingsOk: false,
      packageCount: 1,
      missingLockfiles: [],
      ignoreScriptsOk: false,
      ageGatesOk: false,
      dependencyBotCooldownOk: false,
      recommendations: [],
    },
    skills: [],
    ignoreFixTargets: [{ name: ".gitignore", exists: true }],
    cliInstalled: false,
    recommendedFixes: [
      fix("ignore", { requiresPolicy: true }),
      fix("git_pre_commit", { requiresPolicy: true }),
      fix("ai_hooks", { requiresPolicy: true }),
      fix("ai_claude_deny", { requiresPolicy: true }),
      fix("npm_hardening"),
    ],
    ...overrides,
  };
}

describe("defaultRecommendedFixIds", () => {
  it("keeps default fixes and waits for policy-gated fixes until a policy exists", () => {
    const current = status({
      recommendedFixes: [
        fix("policy_optional"),
        fix("policy_required", { requiresPolicy: true }),
        fix("manual_choice", { defaultSelected: false }),
      ],
    });

    expect(defaultRecommendedFixIds(current, false)).toEqual(["policy_optional"]);
    expect(defaultRecommendedFixIds(current, true)).toEqual(["policy_optional", "policy_required"]);
  });
});

describe("buildQuickSetupSteps", () => {
  it("marks missing recommended protections as pending", () => {
    const steps = buildQuickSetupSteps(status({ policy: { exists: false } }));

    expect(steps).toEqual([
      { id: "policy", done: false, pending: true },
      { id: "ignore", done: false, pending: true },
      { id: "git", done: false, pending: true },
      { id: "ai", done: false, pending: true },
      { id: "npm", done: false, pending: true },
      { id: "skills", done: false, pending: false },
    ]);
  });

  it("recognizes completed optional setup areas", () => {
    const current = status({
      hooks: {
        preCommit: { installed: true, isGitRepo: true },
        aiTools: [
          {
            tool: "cursor",
            configPath: "/workspace/demo/.cursor/hooks.json",
            installed: true,
          },
        ],
      },
      doctor: {
        ...status().doctor,
        ignoreOk: true,
        claudeDenyOk: true,
        claudeSandboxOk: true,
        codexConfigOk: true,
      },
      npmHardening: {
        ...status().npmHardening,
        ignoreScriptsOk: true,
        ageGatesOk: true,
      },
      skills: [
        { label: "claude-code (global)", installed: true },
        { label: "claude-code (project)", installed: true },
        { label: "codex/cursor (project)", installed: true },
      ],
      recommendedFixes: [],
    });

    expect(aiSafetyReady(current)).toBe(true);
    expect(npmSettingsReady(current)).toBe(true);
    expect(projectSkillsInstalled(current)).toBe(true);
    expect(buildQuickSetupSteps(current).every((step) => step.done || step.id === "skills")).toBe(
      true,
    );
  });

  it("does not treat partial project skill installation as complete", () => {
    const current = status({
      skills: [
        { label: "claude-code (project)", installed: true },
        { label: "codex/cursor (project)", installed: false },
      ],
    });

    expect(projectSkillsInstalled(current)).toBe(false);
    expect(buildQuickSetupSteps(current).find((step) => step.id === "skills")).toEqual({
      id: "skills",
      done: false,
      pending: false,
    });
  });

  it("does not treat partial AI hook installation as fully ready", () => {
    const current = status({
      hooks: {
        preCommit: { installed: true, isGitRepo: true },
        aiTools: [
          {
            tool: "claude-code",
            configPath: "/workspace/demo/.claude/settings.json",
            installed: true,
          },
          {
            tool: "cursor",
            configPath: "/workspace/demo/.cursor/hooks.json",
            installed: false,
          },
        ],
      },
      doctor: {
        ...status().doctor,
        claudeDenyOk: true,
        claudeSandboxOk: true,
        codexConfigOk: true,
      },
      recommendedFixes: [fix("ai_hooks", { requiresPolicy: true })],
    });

    expect(aiSafetyReady(current)).toBe(false);
    expect(buildQuickSetupSteps(current).find((step) => step.id === "ai")).toEqual({
      id: "ai",
      done: false,
      pending: true,
    });
  });

  it("treats npm setup as done when no package projects are present", () => {
    const npmStep = buildQuickSetupSteps(
      status({
        npmHardening: {
          ...status().npmHardening,
          hasProjects: false,
        },
      }),
    ).find((step) => step.id === "npm");

    expect(npmStep).toEqual({ id: "npm", done: true, pending: false });
  });
});

describe("AI hook selection helpers", () => {
  it("include Windsurf in matching, additions, removals, and fully-disabled checks", () => {
    const applied = {
      ...status().aiSafetyApplied,
      cursorFailClosed: true,
      scanHooksWindsurf: false,
    };
    const withWindsurf = { ...applied, scanHooksWindsurf: true };

    expect(aiHookSelectionMatches(applied, withWindsurf)).toBe(false);
    expect(aiHookSelectionHasAdditions(applied, withWindsurf)).toBe(true);
    expect(aiHookSelectionHasRemovals(withWindsurf, applied)).toBe(true);
    expect(aiHookSelectionIsFullyDisabled(applied)).toBe(true);
    expect(aiHookSelectionIsFullyDisabled(withWindsurf)).toBe(false);
  });
});

describe("quickSetupCanApply", () => {
  it("allows first-run setup even before policy-gated fixes can be selected", () => {
    expect(
      quickSetupCanApply(
        status({
          policy: { exists: false },
          recommendedFixes: [fix("ignore", { requiresPolicy: true })],
        }),
      ),
    ).toBe(true);
  });

  it("requires at least one default recommended fix once a policy exists", () => {
    expect(
      quickSetupCanApply(
        status({
          recommendedFixes: [fix("manual_choice", { defaultSelected: false })],
        }),
      ),
    ).toBe(false);
  });
});

describe("defaultQuickSetupIgnoreTargets", () => {
  it("returns a fresh copy of the default ignore targets", () => {
    const first = defaultQuickSetupIgnoreTargets();
    first.push(".cursorignore");

    expect(defaultQuickSetupIgnoreTargets()).toEqual([".gitignore"]);
  });
});
