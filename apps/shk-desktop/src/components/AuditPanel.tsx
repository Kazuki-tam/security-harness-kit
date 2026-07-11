import {
  AlertTriangle,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  RefreshCcw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useId, useState, type ReactNode } from "react";
import {
  auditHasBlockedEvents,
  blockedBreakdowns,
  blockedRecentRows,
  blockedRowDetailFields,
  formatBlockedRowSummary,
  formatAuditTimestamp,
  formatToolName,
  hiddenBlockedCount,
  rowLinksToFindings,
} from "../audit";
import { useAuditLogReset } from "../hooks/useAuditLogReset";
import { useI18n } from "../i18n";
import { asSeverity, severityBadge, severityDot, type Severity } from "../scan";
import type { AuditCountRow, AuditRecentRow, AuditState } from "../types";
import { formatRelativeTime } from "../utils";
import { Button } from "./Button";
import { ConfirmDialog } from "./ConfirmDialog";

type Props = {
  projectPath: string;
  auditState: AuditState;
  onRefresh: (options?: { silent?: boolean }) => void;
  onOpenSetup?: () => void;
  onOpenFindings?: () => void;
};

export function AuditPanel({
  projectPath,
  auditState,
  onRefresh,
  onOpenSetup,
  onOpenFindings,
}: Props) {
  const { messages } = useI18n();
  const m = messages.audit;
  const reset = useAuditLogReset(projectPath, m.resetFailed);

  async function handleResetConfirm() {
    const ok = await reset.confirmAndReset();
    if (ok) {
      onRefresh({ silent: true });
    }
  }

  return (
    <>
      <AuditPanelBody
        auditState={auditState}
        onRefresh={onRefresh}
        onOpenSetup={onOpenSetup}
        onOpenFindings={onOpenFindings}
        reset={reset}
      />
      <ConfirmDialog
        open={reset.confirming}
        title={m.resetConfirmTitle}
        description={m.resetConfirmBody}
        confirmLabel={m.resetConfirm}
        variant="danger"
        onCancel={reset.cancelConfirm}
        onConfirm={() => void handleResetConfirm()}
      />
    </>
  );
}

function AuditPanelBody({
  auditState,
  onRefresh,
  onOpenSetup,
  onOpenFindings,
  reset,
}: {
  auditState: AuditState;
  onRefresh: (options?: { silent?: boolean }) => void;
  onOpenSetup?: () => void;
  onOpenFindings?: () => void;
  reset: ReturnType<typeof useAuditLogReset>;
}) {
  const { locale, messages, t } = useI18n();
  const m = messages.audit;
  const loading = auditState.status === "loading";

  if (auditState.status === "idle" || auditState.status === "loading") {
    return (
      <PanelShell
        title={m.title}
        subtitle={m.subtitle}
        busy={loading}
        onRefresh={() => onRefresh()}
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
          <Button variant="secondary" size="sm" onClick={() => onRefresh()}>
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
  const breakdowns = blockedBreakdowns(report);
  const maxSeverity = report.summary.max_severity
    ? asSeverity(report.summary.max_severity)
    : undefined;

  return (
    <PanelShell
      title={m.title}
      subtitle={m.subtitle}
      tone={hasBlocked ? "warn" : "calm"}
      busy={loading || reset.busy}
      onRefresh={() => onRefresh()}
      refreshLabel={m.refresh}
      onReset={report.log_exists ? reset.requestConfirm : undefined}
      resetLabel={m.resetLog}
      resetBusy={reset.busy}
    >
      {reset.error && (
        <div className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[12px] text-red-100">
          {reset.error}
        </div>
      )}
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
            <div className="mt-4 grid gap-4">
              <BlockedBreakdownSections breakdowns={breakdowns} />
              <RecentBlockedSection
                blockedRecent={blockedRecent}
                hidden={hidden}
                loadedAt={auditState.loadedAt}
                blockedEvents={report.summary.blocked_events}
                locale={locale}
                onOpenFindings={onOpenFindings}
              />
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
  busy,
  onRefresh,
  refreshLabel,
  onReset,
  resetLabel,
  resetBusy,
  children,
}: {
  title: string;
  subtitle: string;
  tone?: "warn" | "calm";
  busy?: boolean;
  onRefresh: () => void;
  refreshLabel: string;
  onReset?: () => void;
  resetLabel?: string;
  resetBusy?: boolean;
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
        <div className="flex shrink-0 flex-wrap items-center gap-2 self-start">
          {onReset && resetLabel && (
            <Button
              variant="secondary"
              size="sm"
              onClick={onReset}
              disabled={busy}
              loading={resetBusy}
              icon={!resetBusy ? <RotateCcw size={14} aria-hidden="true" /> : undefined}
            >
              {resetLabel}
            </Button>
          )}
          <Button
            variant="secondary"
            size="sm"
            onClick={onRefresh}
            disabled={busy}
            loading={busy && !resetBusy}
            icon={!(busy && !resetBusy) ? <RefreshCcw size={14} aria-hidden="true" /> : undefined}
          >
            {refreshLabel}
          </Button>
        </div>
      </div>
      {children}
    </section>
  );
}

function BlockedBreakdownSections({
  breakdowns,
}: {
  breakdowns: ReturnType<typeof blockedBreakdowns>;
}) {
  const { messages } = useI18n();
  const m = messages.audit;
  const sections = [
    {
      key: "reasons",
      title: m.reasonBreakdown,
      rows: breakdowns.reasons,
      formatLabel: (label: string) => m.reasonLabels[label] ?? label,
    },
    {
      key: "actionCategories",
      title: m.actionCategoryBreakdown,
      rows: breakdowns.actionCategories,
      formatLabel: (label: string) => m.actionCategories[label] ?? label,
    },
    {
      key: "rules",
      title: m.ruleBreakdown,
      rows: breakdowns.rules,
      hint: m.ruleBreakdownHint,
    },
  ].filter((section) => section.rows.length > 0);

  if (sections.length === 0) {
    return null;
  }

  return (
    <>
      {sections.map((section) => (
        <BreakdownSection
          key={section.key}
          title={section.title}
          rows={section.rows}
          hint={section.hint}
          formatLabel={section.formatLabel}
        />
      ))}
    </>
  );
}

function RecentBlockedSection({
  blockedRecent,
  hidden,
  loadedAt,
  blockedEvents,
  locale,
  onOpenFindings,
}: {
  blockedRecent: AuditRecentRow[];
  hidden: number;
  loadedAt: string;
  blockedEvents: number;
  locale: string;
  onOpenFindings?: () => void;
}) {
  const { messages, t } = useI18n();
  const m = messages.audit;

  return (
    <div>
      <SectionHeading title={m.recentBlocked} />
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
          {t(m.moreEvents, { count: blockedEvents })} · {m.moreEventsHint}
        </p>
      )}
      <p className="mt-2 text-[11px] text-faint">
        {m.updated} {formatRelativeTime(loadedAt, messages.time)}
      </p>
    </div>
  );
}

function SectionHeading({ title }: { title: string }) {
  return (
    <h4 className="text-[11px] font-semibold tracking-[0.14em] text-white/90 uppercase">{title}</h4>
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
  const [expanded, setExpanded] = useState(false);
  const detailsId = useId();
  const severity: Severity | undefined =
    row.reason === "finding_threshold" && row.max_severity
      ? asSeverity(row.max_severity)
      : undefined;
  const reasonLabel = row.reason ? (m.reasonLabels[row.reason] ?? row.reason) : "—";
  const toolLabel = formatToolName(row.tool, m.toolNames);
  const showOpenFindings = rowLinksToFindings(row) && Boolean(onOpenFindings);
  const whenLabel = formatAuditTimestamp(row.ts, locale);
  const detail = formatBlockedRowSummary(row, m.actionCategories);

  return (
    <li className="rounded-lg border border-border bg-surface-3/40 px-3 py-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 flex-1">
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
            <span className="text-[11px] text-white/40">·</span>
            <span className="text-[11px] text-white/75">{toolLabel}</span>
          </div>
          <p className="mt-1 truncate text-[12px] text-white/80" title={detail}>
            {detail}
            {row.finding_count != null && row.finding_count > 0 && (
              <>
                {" "}
                <span className="text-white/40">·</span>{" "}
                {t(m.findingsCount, { count: row.finding_count })}
              </>
            )}
          </p>
          <p className="mt-1 text-[12px] tabular-nums text-white/90" title={row.ts}>
            {whenLabel}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2 self-start">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => setExpanded((open) => !open)}
            aria-expanded={expanded}
            aria-controls={detailsId}
            icon={
              expanded ? (
                <ChevronUp size={12} aria-hidden="true" />
              ) : (
                <ChevronDown size={12} aria-hidden="true" />
              )
            }
          >
            {expanded ? m.hideDetails : m.showDetails}
          </Button>
          {showOpenFindings && (
            <Button
              variant="secondary"
              size="sm"
              onClick={onOpenFindings}
              icon={<ArrowRight size={12} aria-hidden="true" />}
            >
              {m.openFindings}
            </Button>
          )}
        </div>
      </div>
      {expanded && (
        <dl
          id={detailsId}
          className="mt-3 grid gap-2 rounded-lg border border-border/70 bg-surface-2/60 px-3 py-2 text-[11px]"
        >
          {blockedRowDetailFields(row, m, locale).map((field) => (
            <DetailRow
              key={`${field.label}:${field.value}`}
              label={field.label}
              value={field.value}
            />
          ))}
        </dl>
      )}
    </li>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-0.5 sm:grid-cols-[minmax(8rem,30%)_1fr] sm:gap-2">
      <dt className="text-white/50">{label}</dt>
      <dd className="break-all text-white/90">{value}</dd>
    </div>
  );
}

function BreakdownSection({
  title,
  rows,
  hint,
  formatLabel = (label) => label,
}: {
  title: string;
  rows: AuditCountRow[];
  hint?: string;
  formatLabel?: (label: string) => string;
}) {
  return (
    <section aria-label={title}>
      <h4 className="text-[11px] font-semibold tracking-[0.14em] text-white/90 uppercase">
        {title}
      </h4>
      {hint && <p className="mt-1 text-[11px] text-white/55">{hint}</p>}
      <ul className="mt-2 grid gap-1.5">
        {rows.map((row) => (
          <li
            key={row.label}
            className="flex items-center justify-between gap-3 rounded-lg border border-border bg-surface-3/40 px-3 py-2 text-[12px]"
          >
            <span className="min-w-0 truncate text-white/90" title={formatLabel(row.label)}>
              {formatLabel(row.label)}
            </span>
            <span className="shrink-0 tabular-nums font-semibold text-white">{row.count}</span>
          </li>
        ))}
      </ul>
    </section>
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
