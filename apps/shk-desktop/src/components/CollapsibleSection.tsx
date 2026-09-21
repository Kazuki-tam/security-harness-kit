import { ChevronDown, ChevronUp } from "lucide-react";
import { useId, type ReactNode } from "react";

type Props = {
  title: string;
  description?: string;
  open: boolean;
  onToggle: () => void;
  children: ReactNode;
};

/** A titled section that starts collapsed; the header button toggles the body. */
export function CollapsibleSection({ title, description, open, onToggle, children }: Props) {
  const bodyId = useId();
  return (
    <section className="grid gap-3">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={bodyId}
        className="flex w-full items-center justify-between gap-3 rounded-xl border border-border bg-surface-2/70 px-4 py-3 text-left transition hover:bg-surface-3/50 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70"
      >
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          {description && <p className="mt-0.5 text-[11px] text-muted">{description}</p>}
        </div>
        {open ? (
          <ChevronUp size={18} className="shrink-0 text-muted" aria-hidden="true" />
        ) : (
          <ChevronDown size={18} className="shrink-0 text-muted" aria-hidden="true" />
        )}
      </button>
      {open && (
        <div id={bodyId} className="grid gap-4">
          {children}
        </div>
      )}
    </section>
  );
}
