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
    <fieldset disabled={disabled}>
      <legend className="sr-only">{m.label}</legend>
      <div className="grid grid-cols-2 gap-1 rounded-lg border border-border bg-canvas p-0.5">
        {options.map((option) => {
          const checked = mode === option.value;
          return (
            <label
              key={option.value}
              title={option.hint}
              className={`flex min-h-9 cursor-pointer items-center justify-center rounded-md px-3 py-2 transition has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-sky-300/70 ${
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
                aria-labelledby={`${name}-${option.value}-label`}
                aria-describedby={`${name}-${option.value}-hint`}
                className="sr-only"
              />
              <span id={`${name}-${option.value}-label`} className="text-[12px] font-medium">
                {option.label}
              </span>
              <span id={`${name}-${option.value}-hint`} className="sr-only">
                {option.hint}
              </span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}
