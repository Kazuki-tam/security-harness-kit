import { Check, ChevronDown, FolderOpen } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useI18n } from "../i18n";
import { IDE_OPTIONS, type PreferredIde } from "../ide";

type Props = {
  preferredIde: PreferredIde;
  onSelect: (ide: PreferredIde) => void;
  disabled?: boolean;
};

export function OpenInIdeMenu({ preferredIde, onSelect, disabled = false }: Props) {
  const { messages, t } = useI18n();
  const m = messages.topBar;
  const triggerLabel = t(m.openInIdeWith, { ide: m.ideNames[preferredIde] });
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

  function handleSelect(ide: PreferredIde) {
    setOpen(false);
    onSelect(ide);
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
        className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-2.5 py-1 text-[11px] font-medium text-text transition hover:border-sky-400/40 hover:bg-surface-3 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/60 disabled:cursor-not-allowed disabled:opacity-50"
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
          className="shk-fade-in absolute right-0 top-[calc(100%+4px)] z-30 w-48 overflow-hidden rounded-lg border border-border bg-surface-3 py-1 shadow-xl shadow-black/40"
        >
          <div className="px-3 pt-1.5 pb-1 text-[10px] font-semibold tracking-[0.14em] text-muted uppercase">
            {m.preferredIde}
          </div>
          <div className="mx-2 mb-1 h-px bg-border" aria-hidden="true" />
          {IDE_OPTIONS.map((id) => {
            const active = id === preferredIde;
            return (
              <button
                key={id}
                type="button"
                role="menuitemradio"
                aria-checked={active}
                onClick={() => handleSelect(id)}
                className={`flex w-full items-center gap-2 px-3 py-2 text-left text-xs transition ${
                  active
                    ? "bg-sky-500/10 text-white"
                    : "text-text hover:bg-surface/60 hover:text-white"
                }`}
              >
                <span className="grid h-4 w-4 shrink-0 place-items-center text-sky-300">
                  {active ? <Check size={12} aria-hidden="true" /> : null}
                </span>
                <span className="flex-1 truncate">{m.ideNames[id]}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
