import { useId } from "react";
import type { Messages } from "../../i18n/types";

export type MaskMode = "redact" | "pseudonymize";

type Props = {
  mode: MaskMode;
  onChange: (mode: MaskMode) => void;
  disabled?: boolean;
  messages: Messages["mask"]["mode"];
};

/** Segmented radio group: redact (`[REDACTED]`) or pseudonymize (consistent codes). */
export function MaskModeToggle({ mode, onChange, disabled = false, messages: m }: Props) {
  const name = useId();
  const options: { value: MaskMode; label: string; hint: string }[] = [
    { value: "redact", label: m.redact, hint: m.redactHint },
    { value: "pseudonymize", label: m.pseudonymize, hint: m.pseudonymizeHint },
  ];

  return (
    <fieldset className="grid gap-1.5" disabled={disabled}>
      <legend className="text-[10px] font-semibold tracking-[0.12em] text-white/70 uppercase">
        {m.label}
      </legend>
      <div className="grid grid-cols-2 gap-1 rounded-lg border border-border bg-canvas p-0.5">
        {options.map((option) => {
          const checked = mode === option.value;
          return (
            <label
              key={option.value}
              title={option.hint}
              className={`grid cursor-pointer gap-0.5 rounded-md px-2.5 py-1.5 text-left transition has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-sky-300/70 ${
                checked
                  ? "bg-sky-500/15 text-sky-100 ring-1 ring-inset ring-sky-400/30"
                  : "text-muted hover:text-text"
              } ${disabled ? "cursor-not-allowed opacity-60" : ""}`}
            >
              <input
                type="radio"
                name={name}
                value={option.value}
                checked={checked}
                onChange={() => onChange(option.value)}
                className="sr-only"
              />
              <span className="text-[12px] font-medium">{option.label}</span>
              <span className="text-[10px] leading-snug opacity-80">{option.hint}</span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}
