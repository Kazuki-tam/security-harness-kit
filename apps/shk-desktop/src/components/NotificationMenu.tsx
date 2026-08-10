import { Bell, BellOff, ChevronDown } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useI18n } from "../i18n";
import type { NotificationControls } from "../notifications";

/**
 * Blocked-activity notification preferences.
 *
 * Lives in the top bar rather than the audit panel because it is an app-wide
 * setting: the panel only renders for a selected project on one tab, so a user
 * who turned notifications off there could be left with no way back.
 */
export function NotificationMenu({ settings, onChange }: NotificationControls) {
  const { messages } = useI18n();
  const m = messages.notifications;
  const [open, setOpen] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function handleDown(event: MouseEvent) {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    function handleKey(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    window.addEventListener("mousedown", handleDown);
    window.addEventListener("keydown", handleKey);
    return () => {
      window.removeEventListener("mousedown", handleDown);
      window.removeEventListener("keydown", handleKey);
    };
  }, [open]);

  const Icon = settings.enabled ? Bell : BellOff;

  return (
    <div ref={wrapperRef} className="relative inline-flex">
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-label={m.title}
        title={m.title}
        className="inline-flex h-7 items-center gap-1 rounded-md border border-border bg-surface-2 px-2 text-[11px] font-medium text-text transition hover:border-sky-300/60 hover:bg-surface-3 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70"
      >
        <Icon
          size={12}
          aria-hidden="true"
          className={`shrink-0 ${settings.enabled ? "text-sky-300" : "text-muted"}`}
        />
        <ChevronDown
          size={12}
          aria-hidden="true"
          className={`shrink-0 text-muted transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>

      {open && (
        <div
          role="dialog"
          aria-label={m.title}
          className="shk-fade-in absolute right-0 top-[calc(100%+4px)] z-30 w-72 rounded-lg border border-border bg-surface-3 p-3 shadow-xl shadow-black/40"
        >
          <label className="flex cursor-pointer items-start gap-2 text-[12px]">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={settings.enabled}
              onChange={(event) => onChange({ enabled: event.target.checked })}
            />
            <span className="min-w-0 flex-1">
              <span className="font-medium text-white">{m.enabled}</span>
              <span className="mt-0.5 block text-[11px] text-muted">{m.description}</span>
            </span>
          </label>

          <fieldset
            disabled={!settings.enabled}
            className="mt-2.5 border-0 p-0 pl-6 transition-opacity disabled:opacity-40"
          >
            <legend className="pb-1 text-[10px] font-semibold tracking-[0.14em] text-muted uppercase">
              {m.reasonsLegend}
            </legend>
            <ReasonToggle
              label={messages.audit.reasonLabels.action_guard}
              checked={settings.actionGuard}
              onChange={(actionGuard) => onChange({ actionGuard })}
            />
            <ReasonToggle
              label={messages.audit.reasonLabels.finding_threshold}
              checked={settings.findingThreshold}
              onChange={(findingThreshold) => onChange({ findingThreshold })}
            />
          </fieldset>
        </div>
      )}
    </div>
  );
}

function ReasonToggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="flex cursor-pointer items-center gap-1.5 py-0.5 text-[11px] text-white/80">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />
      {label}
    </label>
  );
}
