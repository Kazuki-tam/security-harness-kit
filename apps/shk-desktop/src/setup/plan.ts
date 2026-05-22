import { DEFAULT_IGNORE_TARGETS } from "../components/IgnoreTargetsPicker";
import type { AiHookSetupSelection, ProjectStatus } from "../types";

const AI_HOOK_BOOLEAN_FIELDS = [
  "scanHooksClaudeCode",
  "scanHooksCursor",
  "scanHooksCodex",
  "claudeDeny",
  "claudeSandbox",
  "codexSandbox",
] as const satisfies readonly (keyof AiHookSetupSelection)[];

export function defaultRecommendedFixIds(status: ProjectStatus, policyExists: boolean): string[] {
  return status.recommendedFixes
    .filter((fix) => fix.defaultSelected && (!fix.requiresPolicy || policyExists))
    .map((fix) => fix.id);
}

export type QuickSetupStepId = "policy" | "ignore" | "git" | "ai" | "npm" | "skills";

export type QuickSetupStep = {
  id: QuickSetupStepId;
  done: boolean;
  pending: boolean;
};

export function hasManagedAiHooks(status: ProjectStatus): boolean {
  return status.hooks.aiTools.length > 0 && status.hooks.aiTools.every((tool) => tool.installed);
}

export function aiSafetyReady(status: ProjectStatus): boolean {
  return (
    hasManagedAiHooks(status) &&
    status.doctor.claudeDenyOk &&
    status.doctor.claudeSandboxOk &&
    status.doctor.codexConfigOk
  );
}

export function aiHookSelectionFromStatus(status: ProjectStatus): AiHookSetupSelection {
  return { ...status.aiSafetyApplied };
}

export function aiHookSelectionMatches(
  applied: AiHookSetupSelection,
  selection: AiHookSetupSelection,
): boolean {
  return (
    applied.scanHooksClaudeCode === selection.scanHooksClaudeCode &&
    applied.scanHooksCursor === selection.scanHooksCursor &&
    applied.scanHooksCodex === selection.scanHooksCodex &&
    applied.claudeDeny === selection.claudeDeny &&
    applied.claudeSandbox === selection.claudeSandbox &&
    applied.codexSandbox === selection.codexSandbox
  );
}

export function aiHookSelectionHasRemovals(
  applied: AiHookSetupSelection,
  selection: AiHookSetupSelection,
): boolean {
  return AI_HOOK_BOOLEAN_FIELDS.some((key) => applied[key] && !selection[key]);
}

export function aiHookSelectionHasAdditions(
  applied: AiHookSetupSelection,
  selection: AiHookSetupSelection,
): boolean {
  return AI_HOOK_BOOLEAN_FIELDS.some((key) => !applied[key] && selection[key]);
}

export function aiHookSelectionIsFullyDisabled(selection: AiHookSetupSelection): boolean {
  return AI_HOOK_BOOLEAN_FIELDS.every((key) => !selection[key]);
}

export function npmSettingsReady(status: ProjectStatus): boolean {
  return status.npmHardening.ignoreScriptsOk && status.npmHardening.ageGatesOk;
}

export function projectSkillStatuses(status: ProjectStatus) {
  return status.skills.filter((skill) => skill.label.includes("(project)"));
}

export function projectSkillsInstalled(status: ProjectStatus): boolean {
  return projectSkillStatuses(status).some((skill) => skill.installed);
}

export function buildQuickSetupSteps(status: ProjectStatus): QuickSetupStep[] {
  const policyExists = status.policy.exists;
  const fixes = new Set(status.recommendedFixes.map((fix) => fix.id));
  const skillsOk = projectSkillsInstalled(status);

  return [
    {
      id: "policy",
      done: policyExists,
      pending: !policyExists,
    },
    {
      id: "ignore",
      done: policyExists && status.doctor.ignoreOk,
      pending: fixes.has("ignore"),
    },
    {
      id: "git",
      done: status.hooks.preCommit.installed && status.hooks.preCommit.isGitRepo,
      pending: fixes.has("git_pre_commit"),
    },
    {
      id: "ai",
      done: aiSafetyReady(status),
      pending:
        fixes.has("ai_hooks") ||
        fixes.has("ai_claude_deny") ||
        fixes.has("ai_claude_sandbox") ||
        fixes.has("ai_codex_sandbox"),
    },
    {
      id: "npm",
      done: !status.npmHardening.hasProjects || npmSettingsReady(status),
      pending: status.npmHardening.hasProjects && fixes.has("npm_hardening"),
    },
    {
      id: "skills",
      done: skillsOk,
      pending: false,
    },
  ];
}

export function countPendingQuickSetup(status: ProjectStatus): number {
  return buildQuickSetupSteps(status).filter((step) => step.pending).length;
}

export function quickSetupCanApply(status: ProjectStatus): boolean {
  if (!status.policy.exists) return true;
  return defaultRecommendedFixIds(status, true).length > 0;
}

export function defaultQuickSetupIgnoreTargets(): string[] {
  return [...DEFAULT_IGNORE_TARGETS];
}
