import { Check, ChevronDown, FolderOpen } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useI18n } from "../i18n";
import { PROJECT_APP_SECTIONS, type ProjectApp } from "../projectApp";

type Props = {
  preferredApp: ProjectApp;
  onSelect: (app: ProjectApp) => void;
  disabled?: boolean;
};

export function OpenInAppMenu({ preferredApp, onSelect, disabled = false }: Props) {
  const { messages, t } = useI18n();
  const m = messages.topBar;
  const triggerLabel = t(m.openInAppWith, { app: m.appNames[preferredApp] });
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

  function handleSelect(app: ProjectApp) {
    setOpen(false);
    onSelect(app);
  }

  return (
    <div ref={wrapperRef} className="relative inline-flex">
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        disabled={disabled}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={triggerLabel}
        className="inline-flex h-7 items-center gap-1.5 rounded-md border border-border bg-surface-2 px-2.5 text-[11px] font-medium text-text transition hover:border-sky-300/60 hover:bg-surface-3 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70 disabled:cursor-not-allowed disabled:opacity-50"
      >
        <FolderOpen size={12} aria-hidden="true" className="shrink-0" />
        <span className="truncate">{triggerLabel}</span>
        <ChevronDown
          size={12}
          aria-hidden="true"
          className={`shrink-0 text-muted transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>

      {open && (
        <div
          role="menu"
          className="shk-fade-in absolute right-0 top-[calc(100%+4px)] z-30 w-52 overflow-hidden rounded-lg border border-border bg-surface-3 py-1 shadow-xl shadow-black/40"
        >
          <div className="px-3 pt-1.5 pb-1 text-[10px] font-semibold tracking-[0.14em] text-muted uppercase">
            {m.preferredApp}
          </div>
          <div className="mx-2 mb-1 h-px bg-border" aria-hidden="true" />
          {PROJECT_APP_SECTIONS.map((section, index) => (
            <div key={section.labelKey}>
              {index > 0 ? <div className="mx-2 my-1 h-px bg-border" aria-hidden="true" /> : null}
              <div className="px-3 pt-1 pb-0.5 text-[10px] font-medium tracking-[0.08em] text-faint uppercase">
                {m[section.labelKey]}
              </div>
              {section.options.map((app) => {
                const active = app === preferredApp;
                return (
                  <button
                    key={app}
                    type="button"
                    role="menuitemradio"
                    aria-checked={active}
                    onClick={() => handleSelect(app)}
                    className={`flex w-full items-center gap-2 px-3 py-2 text-left text-xs transition ${
                      active
                        ? "bg-sky-500/10 text-white"
                        : "text-text hover:bg-surface/60 hover:text-white"
                    }`}
                  >
                    <span className="grid h-4 w-4 shrink-0 place-items-center text-sky-300">
                      {active ? <Check size={12} aria-hidden="true" /> : null}
                    </span>
                    <span className="flex-1 truncate">{m.appNames[app]}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
