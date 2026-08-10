import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  RefreshCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { auditHasBlockedEvents } from "../audit";
import { useAuditReport } from "../hooks/useAuditReport";
import { useI18n } from "../i18n";
import { actionableCount, type ScanState, type Severity, visibleScanResult } from "../scan";
import { countPendingQuickSetup } from "../setup/plan";
import type { ActionState, Project, ProjectStatusState, SetupHandlers } from "../types";
import { formatRelativeTime } from "../utils";
import { AuditPanel } from "./AuditPanel";
import { Button } from "./Button";
import { DoctorPanel } from "./DoctorPanel";
import { FindingList } from "./FindingList";
import { ProjectSetupPanel } from "./ProjectSetupPanel";
import { ScanProgressCard } from "./ScanProgressCard";
import { SetupLoadingCard } from "./SetupActionCard";
import { SeveritySummary } from "./SeveritySummary";

type WorkspaceTab = "overview" | "findings" | "setup";

type Props = {
  project: Project;
  scanState: ScanState;
  projectStatus: ProjectStatusState;
  actionState: ActionState;
  onDismissActionFeedback: () => void;
  onScan: () => void;
  setupHandlers?: SetupHandlers;
};

export function ScanWorkspace({
  project,
  scanState,
  projectStatus,
  actionState,
  onDismissActionFeedback,
  onScan,
  setupHandlers,
}: Props) {
  const { messages, t } = useI18n();
  const m = messages.scan;
  const w = messages.workspace;
  const [tab, setTab] = useState<WorkspaceTab>("overview");
  const [filter, setFilter] = useState<Severity | "all">("all");
  const autoOpenedSetupRef = useRef(false);
  const previousScanStatusRef = useRef(scanState.status);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const projectStatusLoadedAt = projectStatus.status === "done" ? projectStatus.loadedAt : null;
  const { auditState, refreshAudit } = useAuditReport(project.path, projectStatusLoadedAt);
  const isScanning = scanState.status === "running";
  const visibleResult = visibleScanResult(scanState);
  const report = visibleResult?.report;
  const finishedAt = visibleResult?.finishedAt ?? project.lastScannedAt;
  const actionable = report
    ? actionableCount(report.summary.by_severity)
    : actionableCount(project.summary?.bySeverity);
  const setupPendingCount =
    projectStatus.status === "done" ? countPendingQuickSetup(projectStatus.data) : 0;
  const showSetupBadge = setupPendingCount > 0;
  const blockedCount = auditState.status === "done" ? auditState.data.summary.blocked_events : 0;
  const hasBlocked = auditState.status === "done" && auditHasBlockedEvents(auditState.data);

  useEffect(() => {
    if (autoOpenedSetupRef.current) return;
    if (projectStatus.status !== "done") return;
    if (setupPendingCount === 0) return;
    if (scanState.status === "running") return;
    if (scanState.status === "done") return;
    setTab("setup");
    autoOpenedSetupRef.current = true;
  }, [projectStatus.status, setupPendingCount, scanState.status]);

  useEffect(() => {
    const previousStatus = previousScanStatusRef.current;
    previousScanStatusRef.current = scanState.status;

    if (scanState.status === "running" && previousStatus !== "running") {
      scrollContainerRef.current?.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }

    if (previousStatus === "running" && scanState.status === "done") {
      setTab("findings");
      const frame = requestAnimationFrame(() => {
        scrollContainerRef.current?.scrollTo({ top: 0, behavior: "smooth" });
      });
      return () => cancelAnimationFrame(frame);
    }

    if (previousStatus === "running" && scanState.status === "error") {
      scrollContainerRef.current?.scrollTo({ top: 0, behavior: "smooth" });
    }
  }, [scanState.status]);

  return (
    <div ref={scrollContainerRef} className="shk-scroll shk-fade-in min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto flex max-w-5xl flex-col gap-5 px-8 pt-6 pb-10">
        <header className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <p className="text-[11px] font-semibold tracking-[0.18em] text-faint uppercase">
              {m.project}
            </p>
            <h2 className="mt-1 truncate text-[22px] font-semibold tracking-tight text-white">
              {project.name}
            </h2>
            <p className="mt-0.5 truncate font-mono text-[12px] text-muted" title={project.path}>
              {project.path}
            </p>
          </div>

          <Button
            variant="primary"
            className="self-start"
            onClick={onScan}
            disabled={isScanning}
            loading={isScanning}
            icon={
              !isScanning ? (
                report ? (
                  <RefreshCcw size={14} aria-hidden="true" className="shrink-0" />
                ) : (
                  <Search size={14} aria-hidden="true" className="shrink-0" />
                )
              ) : undefined
            }
          >
            {isScanning ? m.scanning : report ? m.rescan : m.runScan}
          </Button>
        </header>

        <nav
          className="flex flex-wrap gap-2 border-b border-border pb-3"
          role="tablist"
          aria-label={w.tabsLabel}
        >
          {(["overview", "findings", "setup"] as const).map((key) => (
            <button
              key={key}
              type="button"
              role="tab"
              id={`scan-tab-${key}`}
              aria-controls={`scan-panel-${key}`}
              aria-selected={tab === key}
              tabIndex={tab === key ? 0 : -1}
              onClick={() => setTab(key)}
              className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[12px] font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70 ${
                tab === key
                  ? "bg-sky-500/12 text-sky-100 ring-1 ring-inset ring-sky-400/35"
                  : "text-muted hover:bg-surface-2 hover:text-white"
              }`}
            >
              {w.tabs[key]}
              {key === "overview" && hasBlocked && (
                <span className="rounded-full bg-orange-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-orange-100 ring-1 ring-inset ring-orange-400/35">
                  {t(messages.audit.overviewTabBadge, { count: blockedCount })}
                </span>
              )}
              {key === "findings" && report && (
                <span
                  className={`rounded-full px-1.5 py-0.5 text-[10px] font-semibold ring-1 ring-inset ${
                    report.summary.total > 0
                      ? "bg-red-500/20 text-red-100 ring-red-400/35"
                      : "bg-emerald-500/15 text-emerald-100 ring-emerald-400/30"
                  }`}
                >
                  {report.summary.total}
                </span>
              )}
              {key === "setup" && showSetupBadge && (
                <span className="rounded-full bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-amber-100 ring-1 ring-inset ring-amber-400/35">
                  {w.setupTabBadge}
                </span>
              )}
            </button>
          ))}
        </nav>

        <MetaBar finishedAt={finishedAt} report={report} />

        {scanState.status === "running" && (
          <ScanProgressCard startedAt={scanState.startedAt} hasPreviousResults={Boolean(report)} />
        )}

        {scanState.status === "error" && (
          <div
            role="alert"
            className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200"
          >
            <AlertTriangle size={18} aria-hidden="true" className="mt-0.5 shrink-0 text-red-300" />
            <div>
              <strong className="block text-red-100">{m.scanFailed}</strong>
              <p className="mt-0.5 text-red-200/90">{scanState.message}</p>
            </div>
          </div>
        )}

        <TabPanel tab="overview" activeTab={tab}>
          {report && (
            <>
              <StatusBanner actionable={actionable} report={report} />
              <SeveritySummary
                report={report}
                filter={filter}
                onFilterChange={(next) => {
                  setFilter(next);
                  setTab("findings");
                }}
              />
            </>
          )}
          {projectStatus.status === "loading" && <SetupLoadingCard label={w.loadingStatus} />}
          {projectStatus.status === "error" && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-[12px] text-red-100">
              {projectStatus.message}
            </div>
          )}
          {projectStatus.status === "done" && (
            <>
              {hasBlocked && (
                <BlockedBanner
                  count={blockedCount}
                  onViewDetails={() => {
                    if (typeof document !== "undefined") {
                      document
                        .getElementById("audit-panel")
                        ?.scrollIntoView({ behavior: "smooth", block: "start" });
                    }
                  }}
                />
              )}
              <DoctorPanel
                doctor={projectStatus.data.doctor}
                npmApplicable={projectStatus.data.npmHardening.hasProjects}
                envFiles={projectStatus.data.envFiles}
                onOpenSetup={() => setTab("setup")}
              />
              <div id="audit-panel">
                <AuditPanel
                  projectPath={project.path}
                  auditState={auditState}
                  onRefresh={(options) => void refreshAudit(options)}
                  onOpenSetup={() => setTab("setup")}
                  onOpenFindings={report ? () => setTab("findings") : undefined}
                />
              </div>
              {!projectStatus.data.policy.exists && (
                <div className="flex flex-col gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-[12px] text-amber-100 sm:flex-row sm:items-center sm:justify-between">
                  <p>{w.policyRequired}</p>
                  <Button variant="primary" size="sm" onClick={() => setTab("setup")}>
                    {w.openSetup}
                  </Button>
                </div>
              )}
            </>
          )}
        </TabPanel>

        <TabPanel tab="findings" activeTab={tab}>
          {report ? (
            <>
              <StatusBanner actionable={actionable} report={report} />
              <SeveritySummary report={report} filter={filter} onFilterChange={setFilter} />
              <FindingList findings={report.findings} filter={filter} />
            </>
          ) : scanState.status !== "error" ? (
            <EmptyHero isScanning={isScanning} onScan={onScan} />
          ) : null}
        </TabPanel>

        <TabPanel tab="setup" activeTab={tab}>
          {setupHandlers ? (
            <>
              {projectStatus.status === "loading" && <SetupLoadingCard label={w.loadingStatus} />}
              {projectStatus.status === "error" && (
                <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-[12px] text-red-100">
                  {projectStatus.message}
                </div>
              )}
              {projectStatus.status === "done" && (
                <ProjectSetupPanel
                  status={projectStatus.data}
                  actionState={actionState}
                  onDismissActionFeedback={onDismissActionFeedback}
                  onQuickSetup={setupHandlers.onQuickSetup}
                  onInitPolicy={setupHandlers.onInitPolicy}
                  onFixDoctorIgnore={setupHandlers.onFixDoctorIgnore}
                  onInstallPreCommit={setupHandlers.onInstallPreCommit}
                  onInstallAiHooks={setupHandlers.onInstallAiHooks}
                  onEncryptEnv={setupHandlers.onEncryptEnv}
                  onApplyNpmHardening={setupHandlers.onApplyNpmHardening}
                  onInstallSkills={setupHandlers.onInstallSkills}
                />
              )}
            </>
          ) : null}
        </TabPanel>
      </div>
    </div>
  );
}

function TabPanel({
  tab,
  activeTab,
  children,
}: {
  tab: WorkspaceTab;
  activeTab: WorkspaceTab;
  children: ReactNode;
}) {
  return (
    <div
      role="tabpanel"
      id={`scan-panel-${tab}`}
      aria-labelledby={`scan-tab-${tab}`}
      hidden={activeTab !== tab}
      // space-y (margins) instead of flex/grid gap: a display utility would
      // override the `hidden` attribute's display:none.
      className="space-y-4"
    >
      {children}
    </div>
  );
}

function MetaBar({
  finishedAt,
  report,
}: {
  finishedAt?: string;
  report?: { suppressed: number; deduplicated: number; summary: { total: number } };
}) {
  const { messages, t } = useI18n();
  const m = messages.scan;

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] text-muted">
      <span className="inline-flex items-center gap-1.5">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
        {m.lastScan} {formatRelativeTime(finishedAt, messages.time)}
      </span>
      {report && (
        <>
          <span className="text-faint">·</span>
          <span>{t(m.detected, { count: report.summary.total })}</span>
          <span className="text-faint">·</span>
          <span>{t(m.suppressed, { count: report.suppressed })}</span>
          <span className="text-faint">·</span>
          <span>{t(m.deduplicated, { count: report.deduplicated })}</span>
        </>
      )}
    </div>
  );
}

function StatusBanner({
  actionable,
  report,
}: {
  actionable: number;
  report: { summary: { total: number }; suppressed: number; deduplicated: number };
}) {
  const { messages, t } = useI18n();
  const m = messages.scan;

  if (actionable > 0) {
    return (
      <section className="flex items-start gap-3 rounded-xl border border-orange-500/30 bg-orange-500/10 px-4 py-3.5 text-sm text-orange-100">
        <AlertTriangle size={18} className="mt-0.5 shrink-0 text-orange-300" aria-hidden="true" />
        <div>
          <strong className="block text-orange-50">
            {t(m.actionableBanner, { count: actionable })}
          </strong>
          <p className="mt-0.5 text-orange-100/90">{m.actionableHint}</p>
        </div>
      </section>
    );
  }
  if (report.summary.total === 0) {
    return (
      <section className="flex items-start gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3.5 text-sm text-emerald-100">
        <CheckCircle2 size={18} className="mt-0.5 shrink-0 text-emerald-300" aria-hidden="true" />
        <div>
          <strong className="block text-emerald-50">{m.cleanResult}</strong>
          <p className="mt-0.5 text-emerald-100/90">{m.cleanHint}</p>
        </div>
      </section>
    );
  }
  return (
    <section className="flex items-start gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3.5 text-sm text-emerald-100">
      <CheckCircle2 size={18} className="mt-0.5 shrink-0 text-emerald-300" aria-hidden="true" />
      <div>
        <strong className="block text-emerald-50">{m.noActionable}</strong>
        <p className="mt-0.5 text-emerald-100/90">
          {t(m.lowSeverityHint, { count: report.summary.total })}
        </p>
      </div>
    </section>
  );
}

function BlockedBanner({ count, onViewDetails }: { count: number; onViewDetails: () => void }) {
  const { messages, t } = useI18n();
  const m = messages.audit;
  return (
    <section
      role="alert"
      className="flex flex-col gap-3 rounded-xl border border-orange-500/30 bg-orange-500/10 px-4 py-3.5 text-sm text-orange-100 sm:flex-row sm:items-start sm:justify-between"
    >
      <div className="flex items-start gap-3">
        <ShieldAlert size={18} className="mt-0.5 shrink-0 text-orange-300" aria-hidden="true" />
        <div>
          <strong className="block text-orange-50">{t(m.bannerTitle, { count })}</strong>
          <p className="mt-0.5 text-orange-100/90">{m.bannerHint}</p>
        </div>
      </div>
      <Button
        variant="secondary"
        size="sm"
        className="shrink-0 self-start"
        onClick={onViewDetails}
        icon={<ArrowRight size={12} aria-hidden="true" />}
      >
        {m.recentBlocked}
      </Button>
    </section>
  );
}

function EmptyHero({ isScanning, onScan }: { isScanning: boolean; onScan: () => void }) {
  const { messages } = useI18n();
  const m = messages.scan;

  return (
    <section className="grid place-items-center gap-4 rounded-xl border border-dashed border-border bg-surface-2/40 px-6 py-14 text-center">
      <div className="grid h-12 w-12 place-items-center rounded-2xl bg-sky-500/15 text-sky-200 ring-1 ring-inset ring-sky-400/25">
        <ShieldCheck size={24} aria-hidden="true" />
      </div>
      <div className="grid gap-1.5">
        <h3 className="text-base font-semibold text-white">{m.readyTitle}</h3>
        <p className="max-w-md text-[13px] leading-relaxed text-muted">{m.readyHint}</p>
      </div>
      <Button
        variant="primary"
        onClick={onScan}
        disabled={isScanning}
        loading={isScanning}
        icon={
          !isScanning ? <Search size={14} aria-hidden="true" className="shrink-0" /> : undefined
        }
      >
        {m.runScan}
      </Button>
    </section>
  );
}
