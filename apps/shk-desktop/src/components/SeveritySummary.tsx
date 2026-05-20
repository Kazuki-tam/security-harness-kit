import type { ScanReport, Severity } from "../scan";
import { severityDot, severityLabels, severityOrder, severityText } from "../scan";

type Props = {
  report: ScanReport;
  filter: Severity | "all";
  onFilterChange: (next: Severity | "all") => void;
};

export function SeveritySummary({ report, filter, onFilterChange }: Props) {
  return (
    <section className="grid grid-cols-2 gap-3 sm:grid-cols-5" aria-label="重大度別の検出件数">
      {severityOrder.map((severity) => {
        const count = report.summary.by_severity[severity] ?? 0;
        const active = filter === severity;
        return (
          <button
            key={severity}
            type="button"
            onClick={() => onFilterChange(active ? "all" : severity)}
            aria-pressed={active}
            className={`group relative overflow-hidden rounded-xl border bg-[var(--color-surface-2)] px-4 py-4 text-left transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/60 ${
              active
                ? "border-sky-400/50 bg-sky-500/10 shadow-lg shadow-sky-500/10"
                : "border-[var(--color-border)] hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-3)]"
            }`}
          >
            <div className="flex items-center gap-2">
              <span
                className={`inline-block h-2 w-2 rounded-full ${severityDot[severity]}`}
                aria-hidden="true"
              />
              <span className="text-[11px] font-medium tracking-wide text-[var(--color-muted)]">
                {severityLabels[severity]}
              </span>
            </div>
            <div className="mt-2 flex items-baseline gap-1">
              <span className={`text-3xl font-semibold tabular-nums ${severityText[severity]}`}>
                {count}
              </span>
              <span className="text-[11px] text-[var(--color-faint)]">件</span>
            </div>
          </button>
        );
      })}
    </section>
  );
}
