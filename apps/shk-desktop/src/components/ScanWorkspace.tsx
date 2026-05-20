import {
  AlertTriangle,
  CheckCircle2,
  Loader2,
  RefreshCcw,
  Search,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";
import { actionableCount, type ScanState, type Severity } from "../scan";
import type { Project } from "../types";
import { formatRelativeTime } from "../utils";
import { FindingList } from "./FindingList";
import { SeveritySummary } from "./SeveritySummary";

type Props = {
  project: Project;
  scanState: ScanState;
  onScan: () => void;
};

export function ScanWorkspace({ project, scanState, onScan }: Props) {
  const [filter, setFilter] = useState<Severity | "all">("all");
  const isScanning = scanState.status === "running";
  const report = scanState.status === "done" ? scanState.report : undefined;
  const finishedAt = scanState.status === "done" ? scanState.finishedAt : project.lastScannedAt;
  const actionable = report
    ? actionableCount(report.summary.by_severity)
    : actionableCount(project.summary?.bySeverity as Record<string, number>);

  return (
    <div className="shk-scroll shk-fade-in min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto flex max-w-5xl flex-col gap-5 px-8 pt-6 pb-10">
        <header className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <p className="text-[11px] font-semibold tracking-[0.18em] text-[var(--color-faint)] uppercase">
              プロジェクト
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

          <button
            type="button"
            onClick={onScan}
            disabled={isScanning}
            className="inline-flex items-center gap-2 self-start rounded-lg bg-sky-500 px-4 py-2.5 text-sm font-semibold text-slate-950 shadow-lg shadow-sky-500/20 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70"
          >
            {isScanning ? (
              <>
                <Loader2 size={16} aria-hidden="true" className="animate-spin" />
                スキャン中…
              </>
            ) : report ? (
              <>
                <RefreshCcw size={16} aria-hidden="true" />
                再スキャン
              </>
            ) : (
              <>
                <Search size={16} aria-hidden="true" />
                スキャンを実行
              </>
            )}
          </button>
        </header>

        <MetaBar finishedAt={finishedAt} report={report} />

        {scanState.status === "error" && (
          <div
            role="alert"
            className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200"
          >
            <AlertTriangle size={18} aria-hidden="true" className="mt-0.5 shrink-0 text-red-300" />
            <div>
              <strong className="block text-red-100">スキャンに失敗しました</strong>
              <p className="mt-0.5 text-red-200/90">{scanState.message}</p>
            </div>
          </div>
        )}

        {report ? (
          <>
            <StatusBanner actionable={actionable} report={report} />
            <SeveritySummary report={report} filter={filter} onFilterChange={setFilter} />
            <FindingList findings={report.findings} filter={filter} />
          </>
        ) : scanState.status !== "error" ? (
          <EmptyHero isScanning={isScanning} onScan={onScan} />
        ) : null}
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
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] text-[var(--color-muted)]">
      <span className="inline-flex items-center gap-1.5">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden="true" />
        最終スキャン: {formatRelativeTime(finishedAt)}
      </span>
      {report && (
        <>
          <span className="text-[var(--color-faint)]">·</span>
          <span>検出 {report.summary.total} 件</span>
          <span className="text-[var(--color-faint)]">·</span>
          <span>抑制 {report.suppressed} 件</span>
          <span className="text-[var(--color-faint)]">·</span>
          <span>重複除外 {report.deduplicated} 件</span>
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
  if (actionable > 0) {
    return (
      <section className="flex items-start gap-3 rounded-xl border border-orange-500/30 bg-orange-500/10 px-4 py-3.5 text-sm text-orange-100">
        <AlertTriangle size={18} className="mt-0.5 shrink-0 text-orange-300" aria-hidden="true" />
        <div>
          <strong className="block text-orange-50">{actionable} 件の要対応な検出があります</strong>
          <p className="mt-0.5 text-orange-100/90">
            critical / high の検出を優先的に確認してください。
          </p>
        </div>
      </section>
    );
  }
  if (report.summary.total === 0) {
    return (
      <section className="flex items-start gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3.5 text-sm text-emerald-100">
        <CheckCircle2 size={18} className="mt-0.5 shrink-0 text-emerald-300" aria-hidden="true" />
        <div>
          <strong className="block text-emerald-50">クリーンな結果です</strong>
          <p className="mt-0.5 text-emerald-100/90">対象パスから検出はありませんでした。</p>
        </div>
      </section>
    );
  }
  return (
    <section className="flex items-start gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3.5 text-sm text-emerald-100">
      <CheckCircle2 size={18} className="mt-0.5 shrink-0 text-emerald-300" aria-hidden="true" />
      <div>
        <strong className="block text-emerald-50">要対応の検出はありません</strong>
        <p className="mt-0.5 text-emerald-100/90">
          medium 以下の検出が {report.summary.total} 件あります。必要に応じて確認してください。
        </p>
      </div>
    </section>
  );
}

function EmptyHero({ isScanning, onScan }: { isScanning: boolean; onScan: () => void }) {
  return (
    <section className="grid place-items-center gap-3 rounded-xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface-2)]/50 px-6 py-16 text-center">
      <ShieldCheck size={36} className="text-sky-300" aria-hidden="true" />
      <h3 className="text-lg font-semibold text-white">スキャンの準備が整いました</h3>
      <p className="max-w-md text-sm text-[var(--color-muted)]">
        結果には機密値そのものは表示されず、検出場所と対応に必要な情報のみが残ります。
      </p>
      <button
        type="button"
        onClick={onScan}
        disabled={isScanning}
        className="mt-2 inline-flex items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:opacity-60"
      >
        {isScanning ? (
          <Loader2 size={14} aria-hidden="true" className="animate-spin" />
        ) : (
          <Search size={14} aria-hidden="true" />
        )}
        スキャンを実行
      </button>
    </section>
  );
}
