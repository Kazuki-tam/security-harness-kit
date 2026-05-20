import { useI18n } from "../i18n";
import type { IgnoreFixTarget } from "../types";

export const DEFAULT_IGNORE_TARGETS = [".gitignore"];

type Props = {
  targets: IgnoreFixTarget[];
  selectedTargets: string[];
  disabled?: boolean;
  compact?: boolean;
  onToggle: (name: string) => void;
};

export function IgnoreTargetsPicker({
  targets,
  selectedTargets,
  disabled = false,
  compact = false,
  onToggle,
}: Props) {
  const { messages } = useI18n();
  const m = messages.setup.ignore;

  return (
    <ul className="grid gap-1.5">
      {targets.map((target) => {
        const checked = selectedTargets.includes(target.name);
        return (
          <li key={target.name}>
            <label
              className={`flex cursor-pointer items-start gap-2 rounded-lg border text-[11px] text-muted ${
                compact
                  ? "border-border/70 bg-surface-3/30 px-3 py-1.5"
                  : "border-border bg-surface-3/50 px-3 py-2"
              }`}
            >
              <input
                type="checkbox"
                className="mt-0.5"
                checked={checked}
                disabled={disabled}
                onChange={() => onToggle(target.name)}
              />
              <span className="min-w-0 flex-1">
                <span className="block font-medium text-text">
                  {m.targetNames[target.name] ?? target.name}
                </span>
                <span className="text-[10px] text-faint">
                  {target.exists ? m.targetExists : m.targetNew}
                </span>
              </span>
            </label>
          </li>
        );
      })}
    </ul>
  );
}
