import { asSeverity, type Severity } from "./scan";
import type {
  AuditCountRow,
  AuditRecentRow,
  AuditReport,
  AuditReportOptions,
  AuditState,
} from "./types";
import { fetchAuditReport } from "./project";
import { ownLabel } from "./utils";

export const DEFAULT_AUDIT_REPORT_LIMIT = 10;

/** Every reason the CLI writes on a `blocked` event (`hook_audit_log.rs`). */
export const BLOCKED_AUDIT_REASONS = new Set([
  "finding_threshold",
  "action_guard",
  "policy_error",
  "payload_too_large",
]);

export type BlockedReason =
  | "finding_threshold"
  | "action_guard"
  | "policy_error"
  | "payload_too_large";

export function isBlockedAuditReason(reason: string | undefined): reason is BlockedReason {
  return reason !== undefined && BLOCKED_AUDIT_REASONS.has(reason);
}

/**
 * Whether a recent row is a block. The event type decides, so a reason this
 * build has no label for is still listed; the reason is only consulted for
 * rows that carry no event type.
 */
export function isBlockedAuditRow(row: AuditRecentRow): boolean {
  if (row.event != null) return row.event === "blocked";
  return isBlockedAuditReason(row.reason);
}

export type BlockedBreakdowns = {
  reasons: AuditCountRow[];
  actionCategories: AuditCountRow[];
  rules: AuditCountRow[];
};

export type AuditDetailField = {
  label: string;
  value: string;
};

export type AuditDetailLabels = {
  detailWhen: string;
  detailTool: string;
  detailReason: string;
  detailOperation: string;
  detailHook: string;
  detailRuleIds: string;
  detailKinds: string;
  detailSuppressed: string;
  detailDeduplicated: string;
  hookLabels: Record<string, string>;
  kindLabels: Record<string, string>;
  reasonLabels: Record<string, string>;
  toolNames: Record<string, string>;
  actionCategories: Record<string, string>;
};

export function blockedRecentRows(report: AuditReport): AuditRecentRow[] {
  return report.recent.filter(isBlockedAuditRow);
}

export function blockedBreakdowns(report: AuditReport): BlockedBreakdowns {
  return {
    reasons: report.by_reason.filter((row) => isBlockedAuditReason(row.label)),
    actionCategories: report.by_action_category,
    rules: report.by_rule,
  };
}

export function blockedRowDetailFields(
  row: AuditRecentRow,
  labels: AuditDetailLabels,
  locale = "en-US",
): AuditDetailField[] {
  const fields: AuditDetailField[] = [
    { label: labels.detailWhen, value: formatAuditTimestamp(row.ts, locale) },
    { label: labels.detailTool, value: formatToolName(row.tool, labels.toolNames) },
  ];

  if (row.reason) {
    fields.push({
      label: labels.detailReason,
      value: ownLabel(labels.reasonLabels, row.reason) ?? row.reason,
    });
  }

  const operation = formatBlockedRowSummary(row, labels.actionCategories);
  if (operation !== "—") {
    fields.push({ label: labels.detailOperation, value: operation });
  }

  if (row.hook) {
    fields.push({
      label: labels.detailHook,
      value: ownLabel(labels.hookLabels, row.hook) ?? row.hook,
    });
  }
  if (row.rule_ids?.length) {
    fields.push({
      label: labels.detailRuleIds,
      value: row.rule_ids.join(", "),
    });
  }
  if (row.kinds?.length) {
    fields.push({
      label: labels.detailKinds,
      value: row.kinds.map((kind) => ownLabel(labels.kindLabels, kind) ?? kind).join(", "),
    });
  }
  if (row.suppressed_total != null) {
    fields.push({
      label: labels.detailSuppressed,
      value: String(row.suppressed_total),
    });
  }
  if (row.deduplicated_total != null) {
    fields.push({
      label: labels.detailDeduplicated,
      value: String(row.deduplicated_total),
    });
  }

  return fields;
}

export function formatBlockedRowSummary(
  row: AuditRecentRow,
  actionCategories: Record<string, string>,
): string {
  if (row.reason === "action_guard") {
    return formatActionCategory(row.action_category, actionCategories);
  }
  return row.display_path ?? "—";
}

export function formatAuditTimestamp(ts: string, locale = "en-US"): string {
  const parsed = Date.parse(ts);
  if (Number.isNaN(parsed)) {
    return ts.slice(0, 19) || ts;
  }
  return new Intl.DateTimeFormat(locale, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
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
  return ownLabel(names, toolId) ?? toolId;
}

/** Localize action-guard categories such as `environment_dump`. Falls back to the raw id. */
export function formatActionCategory(
  category: string | undefined,
  labels: Record<string, string>,
): string {
  if (!category) return "—";
  return ownLabel(labels, category) ?? category;
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
    const requestOptions = { limit: DEFAULT_AUDIT_REPORT_LIMIT, ...options };
    let data = await fetcher(projectPath, requestOptions);

    // The general audit report truncates all event types before the desktop
    // filters to blocked rows. Fetch a blocked-only page when newer hook audit
    // events displaced blocks, so the details affordance remains available.
    // This re-reads the whole log, so it must only happen on displacement.
    const expectedBlockedRows = Math.min(
      data.summary.blocked_events,
      requestOptions.limit ?? DEFAULT_AUDIT_REPORT_LIMIT,
    );
    if (!options.reason && blockedRecentRows(data).length < expectedBlockedRows) {
      const blockedData = await fetcher(projectPath, {
        ...requestOptions,
        reason: "blocked",
      });
      // The backend filtered on the event type; every row of this page is a block.
      data = { ...data, recent: blockedData.recent };
    }

    return { status: "done", data, loadedAt: new Date().toISOString() };
  } catch (error) {
    return {
      status: "error",
      message: error instanceof Error ? error.message : String(error),
    };
  }
}
