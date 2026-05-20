import { X } from "lucide-react";
import { useEffect } from "react";
import { useI18n } from "../i18n";

type Props = {
  open: boolean;
  onClose: () => void;
};

export function HelpModal({ open, onClose }: Props) {
  const { messages } = useI18n();
  const m = messages.help;

  useEffect(() => {
    if (!open) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, open]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="shk-help-title"
      className="fixed inset-0 z-50 grid place-items-center bg-black/60 px-6 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="shk-fade-in w-full max-w-md overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-2xl shadow-black/60"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-4">
          <h2 id="shk-help-title" className="text-sm font-semibold text-white">
            {m.title}
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label={messages.common.close}
            className="grid h-7 w-7 place-items-center rounded-md text-[var(--color-muted)] transition hover:bg-[var(--color-surface-3)] hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/60"
          >
            <X size={14} aria-hidden="true" />
          </button>
        </header>

        <section className="px-5 py-4">
          <h3 className="text-[11px] font-semibold tracking-[0.16em] text-[var(--color-faint)] uppercase">
            {m.quickStart}
          </h3>
          <ol className="mt-3 grid gap-2 text-[13px] text-[var(--color-text)]">
            <Step number={1}>{m.step1}</Step>
            <Step number={2}>{m.step2}</Step>
            <Step number={3}>{m.step3}</Step>
          </ol>
        </section>

        <section className="border-t border-[var(--color-border)] px-5 py-4">
          <h3 className="text-[11px] font-semibold tracking-[0.16em] text-[var(--color-faint)] uppercase">
            {m.shortcuts}
          </h3>
          <dl className="mt-3 grid gap-1.5">
            <Shortcut label={m.shortcutOpen} keys={["⌘", "O"]} />
            <Shortcut label={m.shortcutRescan} keys={["⌘", "R"]} />
            <Shortcut label={m.shortcutClose} keys={["Esc"]} />
          </dl>
        </section>

        <footer className="border-t border-[var(--color-border)] bg-[var(--color-surface-2)]/60 px-5 py-3">
          <p className="text-[11px] text-[var(--color-muted)]">{m.footer}</p>
        </footer>
      </div>
    </div>
  );
}

function Step({ number, children }: { number: number; children: React.ReactNode }) {
  return (
    <li className="flex items-start gap-2.5">
      <span className="mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full bg-sky-500/15 text-[11px] font-semibold text-sky-300 ring-1 ring-inset ring-sky-400/30">
        {number}
      </span>
      <span className="leading-relaxed">{children}</span>
    </li>
  );
}

function Shortcut({ label, keys }: { label: string; keys: string[] }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-[13px] text-[var(--color-text)]">{label}</dt>
      <dd className="flex items-center gap-1">
        {keys.map((key) => (
          <kbd
            key={key}
            className="min-w-[24px] rounded-md border border-[var(--color-border)] bg-[var(--color-canvas)] px-1.5 py-0.5 text-center font-mono text-[11px] text-[var(--color-text)]"
          >
            {key}
          </kbd>
        ))}
      </dd>
    </div>
  );
}
