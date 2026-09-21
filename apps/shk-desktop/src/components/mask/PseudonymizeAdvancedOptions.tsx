import type { Messages } from "../../i18n/types";

type Props = {
  restoreMap: boolean;
  onRestoreMapChange: (value: boolean) => void;
  noHeader: boolean;
  onNoHeaderChange: (value: boolean) => void;
  isFileInput: boolean;
  isTableInput: boolean;
  restoreMapName: string | null;
  disabled: boolean;
  messages: Messages["mask"]["pseudonymize"];
  t: (template: string, vars?: Record<string, string | number>) => string;
};

export function PseudonymizeAdvancedOptions({
  restoreMap,
  onRestoreMapChange,
  noHeader,
  onNoHeaderChange,
  isFileInput,
  isTableInput,
  restoreMapName,
  disabled,
  messages: m,
  t,
}: Props) {
  return (
    <div className="grid gap-4 rounded-xl border border-border bg-surface-2/50 p-4">
      {isFileInput ? (
        <label className="flex items-start gap-3">
          <input
            type="checkbox"
            checked={restoreMap}
            disabled={disabled}
            onChange={(event) => onRestoreMapChange(event.target.checked)}
            className="mt-0.5 h-4 w-4 accent-sky-400"
          />
          <span className="grid gap-1">
            <span className="text-[13px] font-medium text-white">{m.restoreMapLabel}</span>
            <span className="text-[11px] leading-relaxed text-muted">{m.restoreMapHint}</span>
            {restoreMap && restoreMapName && (
              <span className="font-mono text-[11px] text-sky-100/90">
                {t(m.restoreMapPath, { name: restoreMapName })}
              </span>
            )}
          </span>
        </label>
      ) : (
        <p className="text-[11px] text-muted">{m.restoreMapUnavailableText}</p>
      )}

      {isTableInput && (
        <label className="flex items-start gap-3">
          <input
            type="checkbox"
            checked={noHeader}
            disabled={disabled}
            onChange={(event) => onNoHeaderChange(event.target.checked)}
            className="mt-0.5 h-4 w-4 accent-sky-400"
          />
          <span className="grid gap-1">
            <span className="text-[13px] font-medium text-white">{m.noHeaderLabel}</span>
            <span className="text-[11px] text-muted">{m.noHeaderHint}</span>
          </span>
        </label>
      )}
    </div>
  );
}
