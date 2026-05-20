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
  codexConfigOk: boolean;
  envOk: boolean;
  npmOk: boolean;
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
  packageCount: number;
  missingLockfiles: string[];
  ignoreScriptsOk: boolean;
  ageGatesOk: boolean;
  dependencyBotCooldownOk: boolean;
  recommendations: string[];
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
  npmHardening: NpmHardeningStatus;
  skills: SkillStatus[];
  ignoreFixTargets: IgnoreFixTarget[];
  recommendedFixes: RecommendedFix[];
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

export type InstallAiHooksOptions = {
  audit: boolean;
  dryRun: boolean;
  global: boolean;
  tool?: string;
  failClosed: boolean;
  applyDeny: boolean;
  applySandbox: boolean;
};

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
