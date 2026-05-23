import { AlertTriangle, ArrowRight, RefreshCcw, ShieldAlert, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import {
  auditHasBlockedEvents,
  blockedRecentRows,
  formatActionCategory,
  formatAuditTimestamp,
  formatToolName,
  hiddenBlockedCount,
  rowLinksToFindings,
} from "../audit";
import { useI18n } from "../i18n";
import { asSeverity, severityBadge, severityDot, type Severity } from "../scan";
import type { AuditRecentRow, AuditState } from "../types";
import { formatRelativeTime } from "../utils";
import { Button } from "./Button";

type Props = {
  auditState: AuditState;
  onRefresh: () => void;
  onOpenSetup?: () => void;
  onOpenFindings?: () => void;
};

export function AuditPanel({ auditState, onRefresh, onOpenSetup, onOpenFindings }: Props) {
  const { locale, messages, t } = useI18n();
  const m = messages.audit;
  const loading = auditState.status === "loading";

  if (auditState.status === "idle" || auditState.status === "loading") {
    return (
      <PanelShell
        title={m.title}
        subtitle={m.subtitle}
        loading={loading}
        onRefresh={onRefresh}
        refreshLabel={m.refresh}
      >
        {loading && <p className="mt-3 text-[12px] text-muted">{m.loading}</p>}
      </PanelShell>
    );
  }

  if (auditState.status === "error") {
    return (
      <section
        className="rounded-xl border border-red-500/30 bg-red-500/10 p-4"
        aria-label={m.title}
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-red-100">{m.title}</h3>
            <p className="mt-1 text-[12px] text-red-200/90">{auditState.message}</p>
          </div>
          <Button variant="secondary" size="sm" onClick={onRefresh}>
            {m.refresh}
          </Button>
        </div>
      </section>
    );
  }

  const { data: report } = auditState;
  const blockedRecent = blockedRecentRows(report);
  const hasBlocked = auditHasBlockedEvents(report);
  const hidden = hiddenBlockedCount(report);
  const maxSeverity = report.summary.max_severity
    ? asSeverity(report.summary.max_severity)
    : undefined;

  return (
    <PanelShell
      title={m.title}
      subtitle={m.subtitle}
      tone={hasBlocked ? "warn" : "calm"}
      onRefresh={onRefresh}
      refreshLabel={m.refresh}
    >
      {!report.log_exists ? (
        <div className="rounded-lg border border-amber-500/25 bg-amber-500/10 px-3 py-3 text-[12px] text-amber-100">
          <p>{m.noLog}</p>
          {onOpenSetup && (
            <Button variant="primary" size="sm" className="mt-3" onClick={onOpenSetup}>
              {m.openSetup}
            </Button>
          )}
        </div>
      ) : (
        <>
          {report.parse_errors > 0 && (
            <div className="mb-3 flex items-start gap-2 rounded-lg border border-amber-500/25 bg-amber-500/10 px-3 py-2 text-[12px] text-amber-100">
              <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
              <span>{t(m.parseErrors, { count: report.parse_errors })}</span>
            </div>
          )}

          <div className="grid gap-2 sm:grid-cols-3">
            <SummaryStat
              label={m.blockedEvents}
              value={report.summary.blocked_events}
              tone="warn"
            />
            <SummaryStat label={m.hookAuditEvents} value={report.summary.hook_audit_events} />
            <SummaryStat
              label={m.maxSeverity}
              value={maxSeverity ? (m.severityLabels[maxSeverity] ?? maxSeverity) : "—"}
              text
            />
          </div>

          {!hasBlocked ? (
            <div className="mt-3 flex items-start gap-2 rounded-lg border border-emerald-500/25 bg-emerald-500/10 px-3 py-3 text-[12px] text-emerald-100">
              <ShieldCheck
                size={14}
                className="mt-0.5 shrink-0 text-emerald-300"
                aria-hidden="true"
              />
              <span>{m.noBlockedYet}</span>
            </div>
          ) : (
            <div className="mt-4">
              <h4 className="text-[11px] font-semibold tracking-[0.14em] text-faint uppercase">
                {m.recentBlocked}
              </h4>
              {blockedRecent.length > 0 && (
                <ul className="mt-2 grid gap-2" aria-label={m.recentBlocked}>
                  {blockedRecent.map((row, index) => (
                    <BlockedRowCard
                      key={`${row.ts}:${row.tool ?? ""}:${row.reason ?? ""}:${index}`}
                      row={row}
                      locale={locale}
                      onOpenFindings={onOpenFindings}
                    />
                  ))}
                </ul>
              )}
              {hidden > 0 && blockedRecent.length > 0 && (
                <p className="mt-3 text-[11px] text-muted">
                  {t(m.moreEvents, { count: hidden })} · {m.moreEventsHint}
                </p>
              )}
              {blockedRecent.length === 0 && (
                <p className="mt-2 rounded-lg border border-border bg-surface-3/40 px-3 py-2 text-[11px] text-muted">
                  {t(m.moreEvents, { count: report.summary.blocked_events })} · {m.moreEventsHint}
                </p>
              )}
              <p className="mt-2 text-[11px] text-faint">
                {m.updated} {formatRelativeTime(auditState.loadedAt, messages.time)}
              </p>
            </div>
          )}
        </>
      )}
    </PanelShell>
  );
}

function PanelShell({
  title,
  subtitle,
  tone = "calm",
  loading,
  onRefresh,
  refreshLabel,
  children,
}: {
  title: string;
  subtitle: string;
  tone?: "warn" | "calm";
  loading?: boolean;
  onRefresh: () => void;
  refreshLabel: string;
  children: ReactNode;
}) {
  return (
    <section className="rounded-xl border border-border bg-surface-2 p-4" aria-label={title}>
      <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h3 className="inline-flex items-center gap-2 text-sm font-semibold text-white">
            {tone === "warn" ? (
              <ShieldAlert size={16} className="text-orange-300" aria-hidden="true" />
            ) : (
              <ShieldCheck size={16} className="text-emerald-300" aria-hidden="true" />
            )}
            {title}
          </h3>
          <p className="mt-1 text-[12px] text-muted">{subtitle}</p>
        </div>
        <Button
          variant="secondary"
          size="sm"
          className="shrink-0 self-start"
          onClick={onRefresh}
          disabled={loading}
          loading={loading}
          icon={!loading ? <RefreshCcw size={14} aria-hidden="true" /> : undefined}
        >
          {refreshLabel}
        </Button>
      </div>
      {children}
    </section>
  );
}

function BlockedRowCard({
  row,
  locale,
  onOpenFindings,
}: {
  row: AuditRecentRow;
  locale: string;
  onOpenFindings?: () => void;
}) {
  const { messages, t } = useI18n();
  const m = messages.audit;
  const severity: Severity | undefined =
    row.reason === "finding_threshold" && row.max_severity
      ? asSeverity(row.max_severity)
      : undefined;
  const reasonLabel = row.reason ? (m.reasonLabels[row.reason] ?? row.reason) : "—";
  const toolLabel = formatToolName(row.tool, m.toolNames);
  const isFindingThreshold = rowLinksToFindings(row);
  const showOpenFindings = isFindingThreshold && Boolean(onOpenFindings);
  const detail =
    row.reason === "action_guard"
      ? formatActionCategory(row.action_category, m.actionCategories)
      : (row.display_path ?? "—");

  return (
    <li className="flex flex-col gap-2 rounded-lg border border-border bg-surface-3/40 px-3 py-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          {severity && (
            <span
              className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${severityBadge[severity]}`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${severityDot[severity]}`}
                aria-hidden="true"
              />
              {m.severityLabels[severity] ?? severity}
            </span>
          )}
          <span className="text-[12px] font-medium text-white">{reasonLabel}</span>
          <span className="text-[11px] text-faint">·</span>
          <span className="text-[11px] text-muted">{toolLabel}</span>
        </div>
        <p className="mt-1 truncate text-[12px] text-muted" title={detail}>
          {detail}
          {row.finding_count != null && row.finding_count > 0 && (
            <>
              {" "}
              <span className="text-faint">·</span>{" "}
              {t(m.findingsCount, { count: row.finding_count })}
            </>
          )}
        </p>
        <p className="mt-0.5 text-[11px] text-faint" title={row.ts}>
          {formatAuditTimestamp(row.ts, locale)}
        </p>
      </div>
      {showOpenFindings && (
        <Button
          variant="secondary"
          size="sm"
          className="shrink-0 self-start"
          onClick={onOpenFindings}
          icon={<ArrowRight size={12} aria-hidden="true" />}
        >
          {m.openFindings}
        </Button>
      )}
    </li>
  );
}

function SummaryStat({
  label,
  value,
  tone,
  text = false,
}: {
  label: string;
  value: number | string;
  tone?: "warn";
  text?: boolean;
}) {
  const isWarning = tone === "warn" && !text && typeof value === "number" && value > 0;
  const valueClass = isWarning ? "text-orange-200" : "text-white";

  return (
    <div className="rounded-lg border border-border bg-surface-3/50 px-3 py-2">
      <p className="text-[11px] text-muted">{label}</p>
      <p className={`mt-0.5 text-lg font-semibold ${valueClass}`}>{value}</p>
    </div>
  );
}
