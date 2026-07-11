import { X } from "lucide-react";
import { useEffect, useId, useRef } from "react";
import { createPortal } from "react-dom";
import { useI18n } from "../i18n";
import { Button } from "./Button";
import { queryModalFocusables } from "./modalFocus";

type Props = {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  cancelLabel?: string;
  variant?: "danger" | "default";
  hideCancel?: boolean;
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
  hideCancel = false,
  onConfirm,
  onCancel,
}: Props) {
  const { messages } = useI18n();
  const titleId = useId();
  const descriptionId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;

    previousFocusRef.current = document.activeElement as HTMLElement | null;
    const frame = requestAnimationFrame(() => {
      queryModalFocusables(panelRef.current)[0]?.focus();
    });

    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onCancel();
        return;
      }
      if (event.key === "Tab") {
        const focusable = queryModalFocusables(panelRef.current);
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    }
    window.addEventListener("keydown", onKey);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("keydown", onKey);
      previousFocusRef.current?.focus();
    };
  }, [onCancel, open]);

  if (!open) return null;

  const confirmClass =
    variant === "danger"
      ? "border-red-400/35 bg-red-500/12 text-red-100 hover:border-red-400/55 hover:bg-red-500/20"
      : undefined;

  return createPortal(
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby={titleId}
      aria-describedby={descriptionId}
      className="fixed inset-0 z-60 grid place-items-center bg-black/60 px-6 backdrop-blur-sm"
      onClick={onCancel}
    >
      <div
        ref={panelRef}
        className="shk-fade-in w-full max-w-md overflow-hidden rounded-2xl border border-border bg-surface shadow-2xl shadow-black/60"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 id={titleId} className="text-sm font-semibold text-white">
            {title}
          </h2>
          {!hideCancel && (
            <button
              type="button"
              onClick={onCancel}
              aria-label={messages.common.close}
              className="grid h-7 w-7 place-items-center rounded-md text-muted transition hover:bg-surface-3 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70"
            >
              <X size={14} aria-hidden="true" />
            </button>
          )}
        </header>
        <p id={descriptionId} className="px-5 py-4 text-[13px] leading-relaxed text-muted">
          {description}
        </p>
        <footer className="flex flex-wrap justify-end gap-2 border-t border-border bg-surface-2/60 px-5 py-3">
          {!hideCancel && (
            <Button variant="secondary" size="sm" onClick={onCancel}>
              {cancelLabel ?? messages.common.cancel}
            </Button>
          )}
          <Button variant="primary" size="sm" className={confirmClass} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </footer>
      </div>
    </div>,
    document.body,
  );
}
