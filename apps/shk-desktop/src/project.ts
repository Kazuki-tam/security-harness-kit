import { invoke } from "@tauri-apps/api/core";
import type {
  ActionResult,
  ApplyAiHookSettingsOptions,
  ApplyNpmHardeningOptions,
  ApplyRecommendedFixesOptions,
  AuditReport,
  AuditReportOptions,
  FixDoctorIgnoreOptions,
  InstallAiHooksOptions,
  InstallSkillsOptions,
  InitPolicyOptions,
  ProjectStatus,
} from "./types";

export function fetchProjectStatus(path: string): Promise<ProjectStatus> {
  return invoke<ProjectStatus>("project_status", { path });
}

export function initPolicy(path: string, options: InitPolicyOptions): Promise<ActionResult> {
  return invoke<ActionResult>("init_policy", { path, options });
}

export function installPreCommitHook(path: string): Promise<ActionResult> {
  return invoke<ActionResult>("install_pre_commit_hook", { path });
}

export function installAiHooks(
  path: string,
  options: InstallAiHooksOptions,
): Promise<ActionResult> {
  return invoke<ActionResult>("install_ai_hooks", { path, options });
}

export function applyAiHookSettings(
  path: string,
  options: ApplyAiHookSettingsOptions,
): Promise<ActionResult> {
  return invoke<ActionResult>("apply_ai_hook_settings", { path, options });
}

export function fixDoctorIgnore(
  path: string,
  options: FixDoctorIgnoreOptions,
): Promise<ActionResult> {
  return invoke<ActionResult>("fix_doctor_ignore", { path, options });
}

export function applyRecommendedFixes(
  path: string,
  options: ApplyRecommendedFixesOptions,
): Promise<ActionResult> {
  return invoke<ActionResult>("apply_recommended_fixes", { path, options });
}

export function applyNpmHardening(
  path: string,
  options: ApplyNpmHardeningOptions,
): Promise<ActionResult> {
  return invoke<ActionResult>("apply_npm_hardening", { path, options });
}

export function installSkills(path: string, options: InstallSkillsOptions): Promise<ActionResult> {
  return invoke<ActionResult>("install_skills", { path, options });
}

export function fetchAuditReport(
  path: string,
  options: AuditReportOptions = {},
): Promise<AuditReport> {
  return invoke<AuditReport>("audit_report", { path, options });
}
