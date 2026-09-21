import { Check, CheckCircle2, Copy, FileText, Lock, RotateCcw } from "lucide-react";
import { useEffect, useRef } from "react";
import type { Messages } from "../../i18n/types";
import { kindDisplayLabel, type PseudonymizeRunResult } from "../../pseudonymize";
import { Button } from "../Button";

type Props = {
  result: PseudonymizeRunResult;
  copiedPath: string | null;
  onCopyPath: (path: string) => void;
  onStartOver: () => void;
  messages: Messages["mask"]["pseudonymize"];
  t: (template: string, vars?: Record<string, string | number>) => string;
};

/** What happened, in plain words, plus the files that were written. */
export function PseudonymizeSummary({
  result,
  copiedPath,
  onCopyPath,
  onStartOver,
  messages: m,
  t,
}: Props) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const replaced = Object.entries(result.replaced).filter(([, count]) => count > 0);
  const unparsedTotal = Object.values(result.unparsed).reduce((sum, count) => sum + count, 0);
  const files: { label: string; path: string; secret?: boolean }[] = [];
  if (result.outputPath) files.push({ label: m.fileOutput, path: result.outputPath });
  if (result.metaPath) files.push({ label: m.fileMeta, path: result.metaPath });
  if (result.mapPath) files.push({ label: m.fileMap, path: result.mapPath, secret: true });

  return (
    <section className="grid gap-4 rounded-xl border border-emerald-400/40 bg-emerald-500/8 p-4 ring-1 ring-inset ring-emerald-400/20">
      <div className="flex items-start gap-3">
        <CheckCircle2 size={20} className="mt-0.5 shrink-0 text-emerald-300" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <h2
            ref={headingRef}
            tabIndex={-1}
            className="text-sm font-semibold text-white outline-none focus-visible:ring-2 focus-visible:ring-emerald-300/70"
          >
            {m.summaryTitle}
          </h2>
          {result.mode === "table" && (
            <p className="mt-1 text-[12px] text-emerald-100/85">
              {t(m.summaryRows, { count: result.rowsProcessed })}
            </p>
          )}
        </div>
      </div>

      <div className="grid gap-2">
        <h3 className="text-[10px] font-semibold tracking-[0.12em] text-white/70 uppercase">
          {m.summaryReplaced}
        </h3>
        {replaced.length === 0 ? (
          <p className="text-[12px] text-muted">{m.summaryNoneReplaced}</p>
        ) : (
          <ul className="flex flex-wrap gap-2">
            {replaced.map(([kind, count]) => (
              <li
                key={kind}
                className="rounded-md bg-emerald-500/15 px-2 py-1 text-[11px] font-medium text-emerald-100 ring-1 ring-inset ring-emerald-400/30"
              >
                {t(m.summaryReplacedItem, { kind: kindDisplayLabel(kind, m), count })}
              </li>
            ))}
          </ul>
        )}
        {unparsedTotal > 0 && (
          <p className="text-[11px] leading-relaxed text-amber-100">
            {t(m.summaryUnparsed, { count: unparsedTotal })}
          </p>
        )}
        {result.remainingRuleIds.length > 0 && (
          <p className="text-[11px] leading-relaxed text-amber-100">
            {t(m.summaryLeftovers, { rules: result.remainingRuleIds.join(", ") })}
          </p>
        )}
      </div>

      {files.length > 0 && (
        <div className="grid gap-2">
          <h3 className="text-[10px] font-semibold tracking-[0.12em] text-white/70 uppercase">
            {m.summaryFiles}
          </h3>
          <ul className="grid gap-1.5">
            {files.map((file) => (
              <li
                key={file.path}
                className={`flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-2 ${
                  file.secret ? "border-red-400/35 bg-red-500/10" : "border-border/70 bg-canvas/40"
                }`}
              >
                <div className="flex min-w-0 items-start gap-2">
                  {file.secret ? (
                    <Lock size={14} className="mt-0.5 shrink-0 text-red-200" aria-hidden="true" />
                  ) : (
                    <FileText size={14} className="mt-0.5 shrink-0 text-muted" aria-hidden="true" />
                  )}
                  <div className="min-w-0">
                    <p
                      className={`text-[12px] font-medium ${file.secret ? "text-red-100" : "text-white"}`}
                    >
                      {file.label}
                    </p>
                    <p className="break-all font-mono text-[11px] text-muted" title={file.path}>
                      {file.path}
                    </p>
                  </div>
                </div>
                <Button
                  variant="secondary"
                  size="sm"
                  icon={
                    copiedPath === file.path ? (
                      <Check size={12} aria-hidden="true" />
                    ) : (
                      <Copy size={12} aria-hidden="true" />
                    )
                  }
                  onClick={() => onCopyPath(file.path)}
                >
                  {copiedPath === file.path ? m.pathCopied : m.copyPath}
                </Button>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div>
        <Button
          variant="secondary"
          size="sm"
          icon={<RotateCcw size={12} aria-hidden="true" />}
          onClick={onStartOver}
        >
          {m.startOver}
        </Button>
      </div>
    </section>
  );
}
