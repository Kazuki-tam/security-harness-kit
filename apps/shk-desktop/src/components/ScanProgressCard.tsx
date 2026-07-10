import { Loader2, Timer } from "lucide-react";
import { useEffect, useState } from "react";
import { useI18n } from "../i18n";

type Props = {
  startedAt: string;
  hasPreviousResults: boolean;
};

export function ScanProgressCard({ startedAt, hasPreviousResults }: Props) {
  const { messages, t } = useI18n();
  const m = messages.scan;
  const [elapsedSeconds, setElapsedSeconds] = useState(() => elapsedSince(startedAt));
  const isTakingLonger = elapsedSeconds >= 8;

  useEffect(() => {
    setElapsedSeconds(elapsedSince(startedAt));
    const interval = window.setInterval(() => {
      setElapsedSeconds(elapsedSince(startedAt));
    }, 1000);
    return () => window.clearInterval(interval);
  }, [startedAt]);

  return (
    <section className="overflow-hidden rounded-xl border border-sky-400/30 bg-sky-500/10 text-sky-100 shadow-[0_18px_70px_rgba(44,202,251,0.08)]">
      <div role="status" aria-live="polite" className="sr-only">
        {m.progressTitle}
      </div>
      <div className="flex flex-col gap-4 px-4 py-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-start gap-3">
          <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-sky-400/15 ring-1 ring-inset ring-sky-300/30">
            <Loader2 size={20} className="animate-spin text-sky-200" aria-hidden="true" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-sky-50">{m.progressTitle}</h3>
            <p className="mt-1 max-w-xl text-[12px] leading-relaxed text-sky-100/85">
              {hasPreviousResults ? m.previousResultsVisible : m.progressHint}
            </p>
            {isTakingLonger && (
              <p className="mt-1 text-[12px] leading-relaxed text-sky-100/70">
                {m.progressSlowHint}
              </p>
            )}
          </div>
        </div>
        <span
          aria-hidden="true"
          className="inline-flex shrink-0 items-center gap-1.5 rounded-full bg-sky-400/10 px-2.5 py-1 text-[11px] font-medium text-sky-100 ring-1 ring-inset ring-sky-300/25"
        >
          <Timer size={12} aria-hidden="true" />
          {t(m.elapsed, { seconds: elapsedSeconds })}
        </span>
      </div>
      <div className="border-t border-sky-300/15 px-4 py-3">
        <div className="mb-2 flex items-center justify-between text-[11px] text-sky-100/75">
          <span>{m.scanningFiles}</span>
          <span>{m.scanning}</span>
        </div>
        <div className="h-1.5 overflow-hidden rounded-full bg-sky-950/70">
          <div className="shk-indeterminate-progress h-full w-1/2 rounded-full bg-linear-to-r from-sky-300 via-cyan-200 to-emerald-200" />
        </div>
      </div>
    </section>
  );
}

function elapsedSince(startedAt: string): number {
  const started = Date.parse(startedAt);
  if (Number.isNaN(started)) return 0;
  return Math.max(0, Math.floor((Date.now() - started) / 1000));
}
