import { CheckCircle2, FileCode2, Hash } from "lucide-react";
import { useMemo } from "react";
import { useI18n } from "../i18n";
import {
  asSeverity,
  type Finding,
  severityBadge,
  severityDot,
  severityOrder,
  type Severity,
} from "../scan";
import { basenameOf, dirnameOf } from "../utils";

type Props = {
  findings: Finding[];
  filter: Severity | "all";
};

export function FindingList({ findings, filter }: Props) {
  const { messages, t } = useI18n();
  const m = messages.findings;
  const severityLabels = messages.severity;

  const visible = useMemo(() => {
    const sorted = [...findings].sort((a, b) => {
      return (
        severityOrder.indexOf(asSeverity(a.severity)) -
        severityOrder.indexOf(asSeverity(b.severity))
      );
    });
    if (filter === "all") return sorted;
    return sorted.filter((f) => asSeverity(f.severity) === filter);
  }, [findings, filter]);

  return (
    <section
      className="overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-2)]"
      aria-label={m.listAria}
    >
      <header className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-3">
        <div>
          <h3 className="text-sm font-semibold text-white">{m.title}</h3>
          <p className="mt-0.5 text-[11px] text-[var(--color-muted)]">
            {filter === "all"
              ? t(m.allFindings, { count: visible.length })
              : t(m.filteredCount, {
                  severity: severityLabels[filter],
                  count: visible.length,
                })}
          </p>
        </div>
      </header>

      {visible.length === 0 ? (
        <div className="grid place-items-center gap-2 px-6 py-14 text-center">
          <CheckCircle2 size={28} className="text-emerald-400" aria-hidden="true" />
          <p className="text-sm text-[var(--color-muted)]">{m.noMatch}</p>
        </div>
      ) : (
        <ul className="divide-y divide-[var(--color-border)]">
          {visible.map((finding, index) => (
            <li
              key={`${finding.file}:${finding.line}:${finding.column}:${finding.rule_id}:${index}`}
            >
              <FindingRow finding={finding} />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const { messages, t } = useI18n();
  const m = messages.findings;
  const severityLabels = messages.severity;
  const severity = asSeverity(finding.severity);
  const fileName = basenameOf(finding.file);
  const folder = dirnameOf(finding.file);

  return (
    <article className="grid grid-cols-[12px_minmax(0,1fr)] gap-3 px-5 py-4 transition hover:bg-[var(--color-surface-3)]/60">
      <div
        className={`mt-1.5 h-2.5 w-2.5 rounded-full ${severityDot[severity]}`}
        aria-hidden="true"
      />
      <div className="min-w-0">
        <div className="flex items-start justify-between gap-3">
          <strong className="text-sm font-semibold text-white">{finding.message}</strong>
          <span
            className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-bold tracking-wide ${severityBadge[severity]}`}
          >
            {severityLabels[severity]}
          </span>
        </div>

        <div className="mt-1.5 flex min-w-0 items-center gap-2 text-[12px] text-[var(--color-muted)]">
          <FileCode2 size={12} aria-hidden="true" className="shrink-0 text-[var(--color-faint)]" />
          <span className="truncate" title={finding.file}>
            {folder && <span className="text-[var(--color-faint)]">{folder}/</span>}
            <span className="text-[var(--color-text)]">{fileName}</span>
          </span>
        </div>

        <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
          <Tag icon={<Hash size={10} aria-hidden="true" />}>
            {t(m.lineTag, { line: finding.line, column: finding.column })}
          </Tag>
          <Tag>{finding.kind}</Tag>
          <Tag muted>{finding.rule_id}</Tag>
          {finding.confidence > 0 && (
            <Tag muted>{t(m.confidence, { percent: (finding.confidence * 100).toFixed(0) })}</Tag>
          )}
        </div>
      </div>
    </article>
  );
}

function Tag({
  children,
  icon,
  muted,
}: {
  children: React.ReactNode;
  icon?: React.ReactNode;
  muted?: boolean;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset ${
        muted
          ? "bg-[var(--color-surface-3)] text-[var(--color-faint)] ring-[var(--color-border)]"
          : "bg-[var(--color-surface-3)] text-[var(--color-text)] ring-[var(--color-border)]"
      }`}
    >
      {icon}
      {children}
    </span>
  );
}
