import { Check, Copy, Eraser, Loader2, TriangleAlert } from "lucide-react";
import type { Messages } from "../../i18n/types";
import type { MaskState } from "../../mask";
import { Button } from "../Button";

type Props = {
  maskedOutput: string;
  maskState: MaskState;
  isLoading: boolean;
  canCopy: boolean;
  copied: boolean;
  actionableFindings: number;
  findingsCount: number;
  onCopy: () => void;
  messages: Messages["mask"];
  t: (template: string, vars?: Record<string, string | number>) => string;
};

export function MaskOutputPanel({
  maskedOutput,
  maskState,
  isLoading,
  canCopy,
  copied,
  actionableFindings,
  findingsCount,
  onCopy,
  messages: m,
  t,
}: Props) {
  const statusTone =
    maskState.status === "done"
      ? findingsCount > 0
        ? "amber"
        : "emerald"
      : isLoading
        ? "sky"
        : "neutral";

  return (
    <section
      className={`grid gap-3 rounded-xl border p-4 ring-1 ring-inset ${
        statusTone === "emerald"
          ? "border-emerald-400/45 bg-emerald-500/12 shadow-[0_16px_50px_rgba(16,185,129,0.12)] ring-emerald-400/20"
          : statusTone === "amber"
            ? "border-amber-400/45 bg-amber-500/12 shadow-[0_16px_50px_rgba(245,158,11,0.12)] ring-amber-400/20"
            : statusTone === "sky"
              ? "border-sky-400/30 bg-sky-500/5 ring-sky-400/15"
              : "border-border bg-surface-2/70 ring-white/5"
      }`}
    >
      <div className="flex min-h-[52px] items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-white">{m.outputTitle}</h2>
          <p role="status" className="mt-1 text-[12px] text-muted">
            {canCopy
              ? actionableFindings > 0
                ? t(m.outputNeedsReview, { count: actionableFindings })
                : findingsCount > 0
                  ? t(m.outputMaskedReview, { count: findingsCount })
                  : m.outputSafe
              : m.outputHint}
          </p>
        </div>
      </div>

      {isLoading ? (
        <div className="grid min-h-[300px] place-items-center gap-3 rounded-lg border border-dashed border-sky-400/25 bg-canvas/50 px-6 py-10 text-center">
          <Loader2 size={28} className="animate-spin text-sky-200" aria-hidden="true" />
          <p className="text-sm text-sky-100">{m.masking}</p>
          <div className="h-1.5 w-full max-w-xs overflow-hidden rounded-full bg-sky-950/70">
            <div className="shk-indeterminate-progress h-full w-1/2 rounded-full bg-sky-400" />
          </div>
        </div>
      ) : canCopy ? (
        <textarea
          readOnly
          aria-label={m.outputTitle}
          value={maskedOutput}
          className={`bg-canvas min-h-[300px] w-full resize-y rounded-lg border px-3 py-3 font-mono text-[12px] leading-relaxed text-white outline-none ${
            findingsCount > 0
              ? "border-amber-400/35 ring-1 ring-inset ring-amber-400/10"
              : "border-emerald-400/35 ring-1 ring-inset ring-emerald-400/10"
          }`}
        />
      ) : (
        <div className="grid min-h-[300px] place-items-center gap-3 rounded-lg border border-dashed border-border bg-canvas/40 px-6 py-10 text-center">
          {maskState.status === "idle" ? (
            <>
              <Eraser size={28} className="text-muted" aria-hidden="true" />
              <p className="max-w-xs text-[13px] leading-relaxed text-muted">
                {m.outputPlaceholder}
              </p>
            </>
          ) : (
            <>
              <TriangleAlert size={28} className="text-amber-300" aria-hidden="true" />
              <p className="max-w-xs text-[13px] leading-relaxed text-muted">
                {m.outputPlaceholder}
              </p>
            </>
          )}
        </div>
      )}

      {canCopy && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border/70 pt-3">
          <p className="text-[11px] text-muted">{t(m.findingsCount, { count: findingsCount })}</p>
          <Button
            variant="secondary"
            icon={
              copied ? (
                <Check size={14} aria-hidden="true" />
              ) : (
                <Copy size={14} aria-hidden="true" />
              )
            }
            onClick={onCopy}
          >
            {copied ? m.copied : m.copyMasked}
          </Button>
          <span aria-live="polite" className="sr-only">
            {copied ? m.copied : ""}
          </span>
        </div>
      )}
    </section>
  );
}
