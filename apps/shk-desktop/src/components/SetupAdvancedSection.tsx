import { ChevronDown, ChevronUp } from "lucide-react";
import type { ReactNode } from "react";
import { useI18n } from "../i18n";

type Props = {
  open: boolean;
  onToggle: () => void;
  pendingHint?: string;
  children: ReactNode;
};

export function SetupAdvancedSection({ open, onToggle, pendingHint, children }: Props) {
  const { messages } = useI18n();
  const m = messages.setup.advanced;

  return (
    <section className="grid gap-3">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-2)] px-4 py-3 text-left transition hover:bg-[var(--color-surface-3)]/50 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/60"
      >
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">{m.title}</h3>
          <p className="mt-0.5 text-[11px] text-[var(--color-muted)]">{m.description}</p>
          {pendingHint && !open && (
            <p className="mt-1 text-[11px] text-amber-200/90">{pendingHint}</p>
          )}
        </div>
        {open ? (
          <ChevronUp size={18} className="shrink-0 text-[var(--color-muted)]" aria-hidden="true" />
        ) : (
          <ChevronDown
            size={18}
            className="shrink-0 text-[var(--color-muted)]"
            aria-hidden="true"
          />
        )}
      </button>
      {open && <div className="grid gap-4">{children}</div>}
    </section>
  );
}
