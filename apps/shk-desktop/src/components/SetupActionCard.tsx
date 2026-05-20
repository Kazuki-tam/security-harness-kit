import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import { Button } from "./Button";

type Props = {
  title: string;
  description: string;
  statusLabel: string;
  statusTone: "ok" | "warn" | "neutral";
  children?: ReactNode;
  primaryLabel?: string;
  secondaryLabel?: string;
  onPrimary?: () => void;
  onSecondary?: () => void;
  primaryLoading?: boolean;
  primaryDisabled?: boolean;
  secondaryDisabled?: boolean;
};

export function SetupActionCard({
  title,
  description,
  statusLabel,
  statusTone,
  children,
  primaryLabel,
  secondaryLabel,
  onPrimary,
  onSecondary,
  primaryLoading,
  primaryDisabled,
  secondaryDisabled,
}: Props) {
  const StatusIcon = statusTone === "ok" ? CheckCircle2 : statusTone === "warn" ? XCircle : Circle;

  const statusClass =
    statusTone === "ok"
      ? "text-emerald-300"
      : statusTone === "warn"
        ? "text-amber-300"
        : "text-[var(--color-muted)]";

  return (
    <section className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-2)] p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          <p className="mt-1 text-[12px] leading-relaxed text-[var(--color-muted)]">
            {description}
          </p>
        </div>
        <span className={`inline-flex shrink-0 items-center gap-1 text-[11px] ${statusClass}`}>
          <StatusIcon size={12} aria-hidden="true" />
          {statusLabel}
        </span>
      </div>

      {children && <div className="mt-3">{children}</div>}

      {(primaryLabel || secondaryLabel) && (
        <div className="mt-4 flex flex-wrap gap-2">
          {secondaryLabel && onSecondary && (
            <Button
              variant="secondary"
              size="sm"
              onClick={onSecondary}
              disabled={secondaryDisabled || primaryLoading}
            >
              {secondaryLabel}
            </Button>
          )}
          {primaryLabel && onPrimary && (
            <Button
              variant="primary"
              size="sm"
              onClick={onPrimary}
              loading={primaryLoading}
              disabled={primaryDisabled}
            >
              {primaryLabel}
            </Button>
          )}
        </div>
      )}
    </section>
  );
}

export function SetupLoadingCard({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-2 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-2)] px-4 py-6 text-[12px] text-[var(--color-muted)]">
      <Loader2 size={14} className="animate-spin" aria-hidden="true" />
      {label}
    </div>
  );
}
