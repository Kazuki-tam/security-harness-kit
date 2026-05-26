import { asSeverity, type Severity } from "./scan";
import type { AuditRecentRow, AuditReport, AuditReportOptions, AuditState } from "./types";
import { fetchAuditReport } from "./project";

export const DEFAULT_AUDIT_REPORT_LIMIT = 10;

export const BLOCKED_AUDIT_REASONS = new Set(["finding_threshold", "action_guard"]);

export type BlockedReason = "finding_threshold" | "action_guard";

export function isBlockedAuditReason(reason: string | undefined): reason is BlockedReason {
  return reason !== undefined && BLOCKED_AUDIT_REASONS.has(reason);
}

export function blockedRecentRows(report: AuditReport): AuditRecentRow[] {
  return report.recent.filter((row) => isBlockedAuditReason(row.reason));
}

export function formatAuditTimestamp(ts: string, locale = "en-US"): string {
  const parsed = Date.parse(ts);
  if (Number.isNaN(parsed)) {
    return ts.slice(0, 16);
  }
  return new Intl.DateTimeFormat(locale, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(parsed);
}

export function auditEventDetail(row: AuditRecentRow): string {
  if (row.reason === "finding_threshold" && row.max_severity) {
    return row.max_severity;
  }
  if (row.reason === "action_guard" && row.action_category) {
    return row.action_category;
  }
  if (row.display_path) {
    return row.display_path;
  }
  return "—";
}

export function auditHasBlockedEvents(report: AuditReport): boolean {
  return report.summary.blocked_events > 0;
}

/** Localize tool identifiers used by the audit log (e.g. `cursor` → `Cursor`). */
export function formatToolName(toolId: string | undefined, names: Record<string, string>): string {
  if (!toolId) return "—";
  return names[toolId] ?? toolId;
}

/** Localize action-guard categories such as `environment_dump`. Falls back to the raw id. */
export function formatActionCategory(
  category: string | undefined,
  labels: Record<string, string>,
): string {
  if (!category) return "—";
  return labels[category] ?? category;
}

/** Return the most actionable severity in the recent blocked rows. */
export function highestBlockedSeverity(report: AuditReport): Severity | undefined {
  let highest: Severity | undefined;
  let highestRank = Infinity;
  for (const row of blockedRecentRows(report)) {
    if (!row.max_severity) continue;
    const sev = asSeverity(row.max_severity);
    const rank = severityRank(sev);
    if (rank < highestRank) {
      highest = sev;
      highestRank = rank;
    }
  }
  if (highest) return highest;
  if (report.summary.max_severity) {
    return asSeverity(report.summary.max_severity);
  }
  return undefined;
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function severityRank(sev: Severity): number {
  return SEVERITY_RANK[sev];
}

/** Whether a row should offer a “open findings tab” link. */
export function rowLinksToFindings(row: AuditRecentRow): boolean {
  return row.reason === "finding_threshold";
}

/** Count of recent rows hidden by the limit. */
export function hiddenBlockedCount(report: AuditReport): number {
  const visible = blockedRecentRows(report).length;
  return Math.max(0, report.summary.blocked_events - visible);
}

export async function loadAuditReport(
  projectPath: string,
  options: AuditReportOptions = {},
  fetcher: (path: string, options: AuditReportOptions) => Promise<AuditReport> = fetchAuditReport,
): Promise<Extract<AuditState, { status: "done" }> | Extract<AuditState, { status: "error" }>> {
  try {
    const data = await fetcher(projectPath, { limit: DEFAULT_AUDIT_REPORT_LIMIT, ...options });
    return { status: "done", data, loadedAt: new Date().toISOString() };
  } catch (error) {
    return {
      status: "error",
      message: error instanceof Error ? error.message : String(error),
    };
  }
}
