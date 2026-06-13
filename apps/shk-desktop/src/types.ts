import type { Severity } from "./scan";

export type ProjectSummary = {
  total: number;
  bySeverity: Partial<Record<Severity, number>>;
  scannedAt: string;
};

export type Project = {
  id: string;
  name: string;
  path: string;
  addedAt: string;
  lastScannedAt?: string;
  summary?: ProjectSummary;
};

export type PolicyStatus = {
  exists: boolean;
  path?: string;
};

export type GitStatus = {
  isRepo: boolean;
  root?: string;
};

export type PreCommitStatus = {
  installed: boolean;
  hookPath?: string;
  isGitRepo: boolean;
};

export type AiHookToolStatus = {
  tool: string;
  configPath: string;
  installed: boolean;
};

export type HooksStatus = {
  preCommit: PreCommitStatus;
  aiTools: AiHookToolStatus[];
};

export type DoctorIssue = {
  id: string;
  severity: string;
  message: string;
};

export type DoctorStatus = {
  gitPreCommit: boolean;
  aiManagedHooks: boolean;
  ignoreOk: boolean;
  missingIgnorePatterns: string[];
  claudeDenyOk: boolean;
  claudeSandboxOk: boolean;
  codexConfigOk: boolean;
  envApplicable: boolean;
  envOk: boolean;
  npmOk: boolean;
  workflowsApplicable: boolean;
  workflowsOk: boolean;
  issues: DoctorIssue[];
};

export type RecommendedFix = {
  id: string;
  severity: string;
  message: string;
  requiresPolicy: boolean;
  defaultSelected: boolean;
};

export type NpmHardeningStatus = {
  hasProjects: boolean;
  ok: boolean;
  settingsOk: boolean;
  packageCount: number;
  missingLockfiles: string[];
  ignoreScriptsOk: boolean;
  ageGatesOk: boolean;
  dependencyBotCooldownOk: boolean;
  recommendations: string[];
};

export type AiSafetyAppliedStatus = {
  scanHooksClaudeCode: boolean;
  scanHooksCursor: boolean;
  scanHooksCodex: boolean;
  scanHooksCopilot: boolean;
  scanHooksAntigravity: boolean;
  claudeDeny: boolean;
  claudeSandbox: boolean;
  codexSandbox: boolean;
};

export type SkillStatus = {
  label: string;
  path?: string;
  installed: boolean;
};

export type IgnoreFixTarget = {
  name: string;
  exists: boolean;
};

export type ProjectStatus = {
  path: string;
  policy: PolicyStatus;
  git: GitStatus;
  hooks: HooksStatus;
  doctor: DoctorStatus;
  aiSafetyApplied: AiSafetyAppliedStatus;
  npmHardening: NpmHardeningStatus;
  skills: SkillStatus[];
  ignoreFixTargets: IgnoreFixTarget[];
  recommendedFixes: RecommendedFix[];
  cliInstalled: boolean;
};

export type ActionResult = {
  success: boolean;
  message: string;
  details: string[];
};

export type InitPolicyOptions = {
  strict: boolean;
  force: boolean;
};

export type FixDoctorIgnoreOptions = {
  targets: string[];
};

export type ApplyRecommendedFixesOptions = {
  fixIds: string[];
  ignoreTargets: string[];
};

export type ApplyNpmHardeningOptions = {
  enabled: boolean;
};

export type ApplyAiHookSettingsOptions = {
  scanHooksClaudeCode: boolean;
  scanHooksCursor: boolean;
  scanHooksCodex: boolean;
  scanHooksCopilot: boolean;
  scanHooksAntigravity: boolean;
  cursorFailClosed: boolean;
  claudeDeny: boolean;
  claudeSandbox: boolean;
  codexSandbox: boolean;
};

export type AiHookSetupSelection = ApplyAiHookSettingsOptions;

export type SetupHandlers = {
  onQuickSetup: (fixIds: string[], ignoreTargets: string[]) => void;
  onInitPolicy: (request: InitPolicyOptions) => void;
  onFixDoctorIgnore: (targets: string[]) => void;
  onInstallPreCommit: () => void;
  onInstallAiHooks: (selection: AiHookSetupSelection) => void;
  onApplyNpmHardening: (enabled: boolean) => void;
  onInstallSkills: () => void;
};

export type InstallAiHooksOptions = {
  audit: boolean;
  logBlocked?: boolean;
  dryRun: boolean;
  global: boolean;
  tool?: string;
  failClosed: boolean;
  applyDeny: boolean;
  applySandbox: boolean;
};

export type AuditReportOptions = {
  limit?: number;
  since?: string;
  tool?: string;
  reason?: string;
  hidePaths?: boolean;
};

export type AuditCountRow = {
  label: string;
  count: number;
};

export type AuditRecentRow = {
  ts: string;
  tool?: string;
  hook?: string;
  reason?: string;
  max_severity?: string;
  action_category?: string;
  display_path?: string;
  finding_count?: number;
};

export type AuditReport = {
  version: number;
  log_path: string;
  log_exists: boolean;
  parse_errors: number;
  filters: {
    since?: string;
    tool?: string;
    reason?: string;
    limit: number;
  };
  summary: {
    total_entries: number;
    blocked_events: number;
    hook_audit_events: number;
    secrets_push_events: number;
    max_severity?: string;
  };
  by_rule: AuditCountRow[];
  by_tool: AuditCountRow[];
  by_reason: AuditCountRow[];
  by_action_category: AuditCountRow[];
  recent: AuditRecentRow[];
};

export type AuditState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "done"; data: AuditReport; loadedAt: string }
  | { status: "error"; message: string };

export type InstallSkillsOptions = {
  tool?: string;
  global: boolean;
  dryRun: boolean;
  force: boolean;
};

export type ProjectStatusState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "done"; data: ProjectStatus; loadedAt: string }
  | { status: "error"; message: string };

export type ActionState =
  | { status: "idle" }
  | { status: "running" }
  | { status: "done"; result: ActionResult }
  | { status: "error"; message: string };
