import { AlertTriangle, X } from "lucide-react";
import { useI18n } from "../i18n";

type Props = {
  message: string;
  onDismiss: () => void;
};

export function AppNotice({ message, onDismiss }: Props) {
  const { messages } = useI18n();

  return (
    <div
      role="alert"
      className="mx-4 mt-3 flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-100"
    >
      <AlertTriangle size={16} aria-hidden="true" className="mt-0.5 shrink-0 text-red-300" />
      <p className="min-w-0 flex-1 leading-relaxed">{message}</p>
      <button
        type="button"
        onClick={onDismiss}
        aria-label={messages.common.dismiss}
        className="grid h-6 w-6 shrink-0 place-items-center rounded-md text-red-200/80 transition hover:bg-red-500/15 hover:text-red-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-300/70"
      >
        <X size={14} aria-hidden="true" />
      </button>
    </div>
  );
}
