import { AlertTriangle, CheckCircle2, X } from "lucide-react";
import { useI18n } from "../i18n";
import { actionFeedbackTone, localizeActionResult } from "../setup/actionMessages";
import type { ActionState } from "../types";

type Props = {
  state: ActionState;
  onDismiss: () => void;
};

function DismissButton({ onDismiss, label }: { onDismiss: () => void; label: string }) {
  return (
    <button
      type="button"
      onClick={onDismiss}
      aria-label={label}
      className="grid h-6 w-6 shrink-0 place-items-center rounded-md opacity-70 transition hover:bg-white/10 hover:opacity-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70"
    >
      <X size={14} aria-hidden="true" />
    </button>
  );
}

export function SetupFeedback({ state, onDismiss }: Props) {
  const { messages } = useI18n();
  const m = messages.setup.action;

  if (state.status === "error") {
    return (
      <div
        role="alert"
        className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-[12px] text-red-100"
      >
        <AlertTriangle size={16} className="mt-0.5 shrink-0 text-red-300" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <strong className="block">{m.failed}</strong>
          <p className="mt-1 text-red-200/90">{state.message}</p>
        </div>
        <DismissButton onDismiss={onDismiss} label={messages.common.close} />
      </div>
    );
  }

  if (state.status === "done") {
    const tone = actionFeedbackTone(state.result);
    const { title, details } = localizeActionResult(state.result, m);
    const toneClass =
      tone === "success"
        ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
        : tone === "warning"
          ? "border-amber-500/30 bg-amber-500/10 text-amber-100"
          : "border-red-500/30 bg-red-500/10 text-red-100";
    const iconClass =
      tone === "success"
        ? "text-emerald-300"
        : tone === "warning"
          ? "text-amber-300"
          : "text-red-300";
    const heading = tone === "success" ? m.succeeded : tone === "warning" ? m.partial : m.failed;

    return (
      <div
        role="status"
        className={`flex items-start gap-3 rounded-xl border px-4 py-3 text-[12px] ${toneClass}`}
      >
        {tone === "success" ? (
          <CheckCircle2 size={16} className={`mt-0.5 shrink-0 ${iconClass}`} aria-hidden="true" />
        ) : (
          <AlertTriangle size={16} className={`mt-0.5 shrink-0 ${iconClass}`} aria-hidden="true" />
        )}
        <div className="min-w-0 flex-1">
          <strong className="block">{heading}</strong>
          <p className="mt-0.5 opacity-90">{title}</p>
          {details.length > 0 && (
            <ul className="mt-2 grid gap-1 opacity-80">
              {details.map((detail) => (
                <li key={detail} className="text-[11px]">
                  {detail}
                </li>
              ))}
            </ul>
          )}
        </div>
        <DismissButton onDismiss={onDismiss} label={messages.common.close} />
      </div>
    );
  }

  return null;
}
