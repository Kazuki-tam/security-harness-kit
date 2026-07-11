import { X } from "lucide-react";
import { useEffect } from "react";
import { useI18n } from "../i18n";
import { Button } from "./Button";

type Props = {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  cancelLabel?: string;
  variant?: "danger" | "default";
  onConfirm: () => void;
  onCancel: () => void;
};

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  cancelLabel,
  variant = "default",
  onConfirm,
  onCancel,
}: Props) {
  const { messages } = useI18n();

  useEffect(() => {
    if (!open) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onCancel();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel, open]);

  if (!open) return null;

  const confirmClass =
    variant === "danger"
      ? "border-red-400/35 bg-red-500/12 text-red-100 hover:border-red-400/55 hover:bg-red-500/20"
      : undefined;

  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="shk-confirm-title"
      aria-describedby="shk-confirm-desc"
      className="fixed inset-0 z-[60] grid place-items-center bg-black/60 px-6 backdrop-blur-sm"
      onClick={onCancel}
    >
      <div
        className="shk-fade-in w-full max-w-md overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-2xl shadow-black/60"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-4">
          <h2 id="shk-confirm-title" className="text-sm font-semibold text-white">
            {title}
          </h2>
          <button
            type="button"
            onClick={onCancel}
            aria-label={messages.common.close}
            className="grid h-7 w-7 place-items-center rounded-md text-[var(--color-muted)] transition hover:bg-[var(--color-surface-3)] hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70"
          >
            <X size={14} aria-hidden="true" />
          </button>
        </header>
        <p
          id="shk-confirm-desc"
          className="px-5 py-4 text-[13px] leading-relaxed text-[var(--color-muted)]"
        >
          {description}
        </p>
        <footer className="flex flex-wrap justify-end gap-2 border-t border-[var(--color-border)] bg-[var(--color-surface-2)]/60 px-5 py-3">
          <Button variant="secondary" size="sm" onClick={onCancel}>
            {cancelLabel ?? messages.common.cancel}
          </Button>
          <Button variant="primary" size="sm" className={confirmClass} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </footer>
      </div>
    </div>
  );
}
