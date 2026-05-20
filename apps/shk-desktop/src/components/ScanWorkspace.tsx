import { AlertTriangle, CheckCircle2, RefreshCcw, Search, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useI18n } from "../i18n";
import { actionableCount, type ScanState, type Severity } from "../scan";
import type { ActionState, Project, ProjectStatusState } from "../types";
import { formatRelativeTime } from "../utils";
import { Button } from "./Button";
import { DoctorPanel } from "./DoctorPanel";
import { FindingList } from "./FindingList";
import { ProjectSetupPanel } from "./ProjectSetupPanel";
import { SetupLoadingCard } from "./SetupActionCard";
import { SeveritySummary } from "./SeveritySummary";

type WorkspaceTab = "overview" | "findings" | "setup";

type SetupHandlers = {
  onInitPolicy: (strict: boolean) => void;
  onApplyRecommendedFixes: (fixIds: string[], ignoreTargets: string[]) => void;
  onFixDoctorIgnore: (targets: string[]) => void;
  onInstallPreCommit: () => void;
  onInstallAiHooks: () => void;
  onInstallClaudeDeny: () => void;
  onInstallCodexSandbox: () => void;
  onApplyNpmHardening: () => void;
  onInstallSkills: () => void;
};

type Props = {
  project: Project;
  scanState: ScanState;
  projectStatus: ProjectStatusState;
  actionState: ActionState;
  onScan: () => void;
  setupHandlers?: SetupHandlers;
};

export function ScanWorkspace({
  project,
  scanState,
  projectStatus,
  actionState,
  onScan,
  setupHandlers,
}: Props) {
  const { messages } = useI18n();
  const m = messages.scan;
  const w = messages.workspace;
  const [tab, setTab] = useState<WorkspaceTab>("overview");
  const [filter, setFilter] = useState<Severity | "all">("all");
  const isScanning = scanState.status === "running";
  const report = scanState.status === "done" ? scanState.report : undefined;
  const finishedAt = scanState.status === "done" ? scanState.finishedAt : project.lastScannedAt;
  const actionable = report
    ? actionableCount(report.summary.by_severity)
    : actionableCount(project.summary?.bySeverity);

  return (
    <div className="shk-scroll shk-fade-in min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto flex max-w-5xl flex-col gap-5 px-8 pt-6 pb-10">
        <header className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <p className="text-[11px] font-semibold tracking-[0.18em] text-[var(--color-faint)] uppercase">
              {m.project}
            </p>
            <h2 className="mt-1 truncate text-[22px] font-semibold tracking-tight text-white">
              {project.name}
            </h2>
            <p
              className="mt-0.5 truncate font-mono text-[12px] text-[var(--color-muted)]"
              title={project.path}
            >
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

        <nav className="flex flex-wrap gap-2 border-b border-[var(--color-border)] pb-3">
          {(["overview", "findings", "setup"] as const).map((key) => (
            <button
              key={key}
              type="button"
              onClick={() => setTab(key)}
              aria-current={tab === key ? "page" : undefined}
              className={`rounded-lg px-3 py-1.5 text-[12px] font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/60 ${
                tab === key
                  ? "bg-sky-500/12 text-sky-100 ring-1 ring-inset ring-sky-400/35"
                  : "text-[var(--color-muted)] hover:bg-[var(--color-surface-2)] hover:text-white"
              }`}
            >
              {w.tabs[key]}
            </button>
          ))}
        </nav>

        <MetaBar finishedAt={finishedAt} report={report} />

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

        {tab === "overview" && (
          <>
            {projectStatus.status === "loading" && <SetupLoadingCard label={w.loadingStatus} />}
            {projectStatus.status === "error" && (
              <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-[12px] text-red-100">
                {projectStatus.message}
              </div>
            )}
            {projectStatus.status === "done" && (
              <>
                <DoctorPanel doctor={projectStatus.data.doctor} />
                {!projectStatus.data.policy.exists && (
                  <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-[12px] text-amber-100">
                    {w.policyRequired}
                  </div>
                )}
              </>
            )}
            {report && (
              <>
                <StatusBanner actionable={actionable} report={report} />
                <SeveritySummary report={report} filter={filter} onFilterChange={setFilter} />
              </>
            )}
          </>
        )}

        {tab === "findings" && report && (
          <>
            <StatusBanner actionable={actionable} report={report} />
            <SeveritySummary report={report} filter={filter} onFilterChange={setFilter} />
            <FindingList findings={report.findings} filter={filter} />
          </>
        )}

        {tab === "findings" && !report && scanState.status !== "error" && (
          <EmptyHero isScanning={isScanning} onScan={onScan} />
        )}

        {tab === "setup" && setupHandlers && (
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
                onInitPolicy={setupHandlers.onInitPolicy}
                onApplyRecommendedFixes={setupHandlers.onApplyRecommendedFixes}
                onFixDoctorIgnore={setupHandlers.onFixDoctorIgnore}
                onInstallPreCommit={setupHandlers.onInstallPreCommit}
                onInstallAiHooks={setupHandlers.onInstallAiHooks}
                onInstallClaudeDeny={setupHandlers.onInstallClaudeDeny}
                onInstallCodexSandbox={setupHandlers.onInstallCodexSandbox}
                onApplyNpmHardening={setupHandlers.onApplyNpmHardening}
                onInstallSkills={setupHandlers.onInstallSkills}
              />
            )}
          </>
        )}
      </div>
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
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] text-[var(--color-muted)]">
      <span className="inline-flex items-center gap-1.5">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
        {m.lastScan} {formatRelativeTime(finishedAt, messages.time)}
      </span>
      {report && (
        <>
          <span className="text-[var(--color-faint)]">·</span>
          <span>{t(m.detected, { count: report.summary.total })}</span>
          <span className="text-[var(--color-faint)]">·</span>
          <span>{t(m.suppressed, { count: report.suppressed })}</span>
          <span className="text-[var(--color-faint)]">·</span>
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

function EmptyHero({ isScanning, onScan }: { isScanning: boolean; onScan: () => void }) {
  const { messages } = useI18n();
  const m = messages.scan;

  return (
    <section className="grid place-items-center gap-4 rounded-xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface-2)]/40 px-6 py-14 text-center">
      <div className="grid h-12 w-12 place-items-center rounded-2xl bg-gradient-to-br from-sky-400/25 via-violet-400/10 to-emerald-400/10 text-sky-200 ring-1 ring-inset ring-sky-400/25">
        <ShieldCheck size={24} aria-hidden="true" />
      </div>
      <div className="grid gap-1.5">
        <h3 className="text-base font-semibold text-white">{m.readyTitle}</h3>
        <p className="max-w-md text-[13px] leading-relaxed text-[var(--color-muted)]">
          {m.readyHint}
        </p>
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
