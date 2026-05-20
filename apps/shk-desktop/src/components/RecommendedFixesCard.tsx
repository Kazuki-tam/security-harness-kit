import { useEffect, useMemo, useState } from "react";
import { useI18n } from "../i18n";
import type { ProjectStatus } from "../types";
import { DEFAULT_IGNORE_TARGETS, IgnoreTargetsPicker } from "./IgnoreTargetsPicker";
import { SetupActionCard } from "./SetupActionCard";

type Props = {
  status: ProjectStatus;
  running: boolean;
  policyExists: boolean;
  onApply: (fixIds: string[], ignoreTargets: string[]) => void;
};

export function RecommendedFixesCard({ status, running, policyExists, onApply }: Props) {
  const { messages, t } = useI18n();
  const m = messages.setup.recommendedFixes;
  const fixes = status.recommendedFixes;

  const defaultSelected = useMemo(
    () =>
      fixes
        .filter((fix) => fix.defaultSelected && (!fix.requiresPolicy || policyExists))
        .map((fix) => fix.id),
    [fixes, policyExists],
  );

  const [selectedFixIds, setSelectedFixIds] = useState<string[]>(defaultSelected);
  const [selectedIgnoreTargets, setSelectedIgnoreTargets] =
    useState<string[]>(DEFAULT_IGNORE_TARGETS);

  useEffect(() => {
    setSelectedFixIds(defaultSelected);
    setSelectedIgnoreTargets(DEFAULT_IGNORE_TARGETS);
  }, [status.path, defaultSelected.join(",")]);

  const ignoreSelected = selectedFixIds.includes("ignore");

  const toggleFix = (id: string) => {
    setSelectedFixIds((prev) =>
      prev.includes(id) ? prev.filter((fixId) => fixId !== id) : [...prev, id],
    );
  };

  const toggleIgnoreTarget = (name: string) => {
    setSelectedIgnoreTargets((prev) =>
      prev.includes(name) ? prev.filter((target) => target !== name) : [...prev, name],
    );
  };

  const applyDisabled =
    running ||
    selectedFixIds.length === 0 ||
    (ignoreSelected && selectedIgnoreTargets.length === 0) ||
    selectedFixIds.some((id) => {
      const fix = fixes.find((entry) => entry.id === id);
      return fix?.requiresPolicy && !policyExists;
    });

  if (fixes.length === 0) {
    return null;
  }

  return (
    <SetupActionCard
      title={m.title}
      description={m.description}
      statusLabel={t(m.available, { count: fixes.length })}
      statusTone="warn"
      primaryLabel={m.applySelected}
      onPrimary={() => onApply(selectedFixIds, selectedIgnoreTargets)}
      primaryLoading={running}
      primaryDisabled={applyDisabled}
    >
      <ul className="grid gap-2">
        {fixes.map((fix) => {
          const checked = selectedFixIds.includes(fix.id);
          const disabled = running || (fix.requiresPolicy && !policyExists);
          return (
            <li key={fix.id}>
              <label className="flex cursor-pointer items-start gap-2 rounded-lg border border-border bg-surface-3/50 px-3 py-2 text-[11px] text-muted">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={checked}
                  disabled={disabled}
                  onChange={() => toggleFix(fix.id)}
                />
                <span className="min-w-0 flex-1">
                  <span className="block font-medium text-text">
                    {m.fixLabels[fix.id] ?? fix.id}
                  </span>
                  <span className="text-[10px] text-faint">{fix.message}</span>
                </span>
              </label>
            </li>
          );
        })}
      </ul>

      {ignoreSelected && policyExists && status.ignoreFixTargets.length > 0 && (
        <div className="mt-3 grid gap-2">
          <p className="text-[11px] font-medium text-text">{m.ignoreTargetsLabel}</p>
          <IgnoreTargetsPicker
            targets={status.ignoreFixTargets}
            selectedTargets={selectedIgnoreTargets}
            disabled={running}
            compact
            onToggle={toggleIgnoreTarget}
          />
        </div>
      )}
    </SetupActionCard>
  );
}
