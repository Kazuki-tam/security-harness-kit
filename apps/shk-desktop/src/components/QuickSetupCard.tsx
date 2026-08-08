import { CheckCircle2, ChevronDown, ChevronUp } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useI18n } from "../i18n";
import {
  buildQuickSetupSteps,
  defaultQuickSetupIgnoreTargets,
  defaultRecommendedFixIds,
  envEncryptTargets,
  quickSetupCanApply,
} from "../setup/plan";
import type { ProjectStatus } from "../types";
import { IgnoreTargetsPicker } from "./IgnoreTargetsPicker";
import { Button } from "./Button";

type Props = {
  status: ProjectStatus;
  running: boolean;
  onQuickSetup: (fixIds: string[], ignoreTargets: string[], envTargets: string[]) => void;
  onOpenAdvanced?: () => void;
};

export function QuickSetupCard({ status, running, onQuickSetup, onOpenAdvanced }: Props) {
  const { messages, t } = useI18n();
  const m = messages.setup.quickSetup;
  const fixLabels = messages.setup.recommendedFixes.fixLabels;
  const policyExists = status.policy.exists;
  const fixes = status.recommendedFixes;
  const steps = buildQuickSetupSteps(status);
  const pendingCount = steps.filter((step) => step.pending).length;
  const allDone = pendingCount === 0 && policyExists;

  const defaultSelected = useMemo(
    () => defaultRecommendedFixIds(status, policyExists),
    [status, policyExists],
  );

  const eligibleEnvTargets = useMemo(() => envEncryptTargets(status), [status]);

  const [customizeOpen, setCustomizeOpen] = useState(false);
  const [selectedFixIds, setSelectedFixIds] = useState<string[]>(defaultSelected);
  const [selectedIgnoreTargets, setSelectedIgnoreTargets] = useState<string[]>(
    defaultQuickSetupIgnoreTargets(),
  );
  const [selectedEnvTargets, setSelectedEnvTargets] = useState<string[]>(eligibleEnvTargets);
  const projectPathRef = useRef(status.path);

  useEffect(() => {
    if (projectPathRef.current !== status.path) {
      projectPathRef.current = status.path;
      setSelectedFixIds(defaultSelected);
      setSelectedIgnoreTargets(defaultQuickSetupIgnoreTargets());
      setSelectedEnvTargets(eligibleEnvTargets);
    }
  }, [status.path, defaultSelected, eligibleEnvTargets]);

  // Drop selections for files that were encrypted or removed since the last
  // status refresh; deliberately never re-add files the user unchecked.
  useEffect(() => {
    setSelectedEnvTargets((prev) => prev.filter((name) => eligibleEnvTargets.includes(name)));
  }, [eligibleEnvTargets]);

  useEffect(() => {
    setSelectedFixIds((prev) => {
      const available = new Set(fixes.map((fix) => fix.id));
      const next = prev.filter((id) => available.has(id));
      for (const id of defaultSelected) {
        if (!next.includes(id)) next.push(id);
      }
      return next;
    });
  }, [fixes, defaultSelected]);

  const ignoreSelected = selectedFixIds.includes("ignore");
  const envEncryptSelected = selectedFixIds.includes("env_encrypt");
  const applyDisabled =
    running ||
    allDone ||
    (policyExists &&
      (selectedFixIds.length === 0 ||
        (ignoreSelected && selectedIgnoreTargets.length === 0) ||
        (envEncryptSelected && selectedEnvTargets.length === 0) ||
        !quickSetupCanApply(status)));

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

  const toggleEnvTarget = (name: string) => {
    setSelectedEnvTargets((prev) =>
      prev.includes(name) ? prev.filter((target) => target !== name) : [...prev, name],
    );
  };

  const primaryLabel = !policyExists ? m.applyWithPolicy : allDone ? m.reapply : m.apply;

  return (
    <section className="overflow-hidden rounded-xl border border-sky-400/25 bg-sky-500/8 p-4 ring-1 ring-inset ring-sky-400/20">
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="text-base font-semibold text-white">{m.title}</h3>
          <p className="mt-1 text-[12px] leading-relaxed text-muted">{m.description}</p>
        </div>
        <span
          className={`shrink-0 rounded-full px-2.5 py-0.5 text-[10px] font-medium ring-1 ring-inset ${
            allDone
              ? "bg-emerald-500/15 text-emerald-200 ring-emerald-400/30"
              : "bg-amber-500/15 text-amber-100 ring-amber-400/30"
          }`}
        >
          {allDone ? m.badgeComplete : t(m.badgePending, { count: pendingCount })}
        </span>
      </div>

      <ol className="mt-4 grid gap-1.5 sm:grid-cols-2">
        {steps.map((step) => {
          const label = m.steps[step.id];
          return (
            <li
              key={step.id}
              className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-[11px] ${
                step.done
                  ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-100"
                  : step.pending
                    ? "border-amber-500/20 bg-amber-500/5 text-amber-50"
                    : "border-border bg-surface-3/40 text-muted"
              }`}
            >
              <CheckCircle2
                size={14}
                className={step.done ? "shrink-0 text-emerald-300" : "shrink-0 text-faint"}
                aria-hidden="true"
              />
              <span className="min-w-0 flex-1">{label}</span>
            </li>
          );
        })}
      </ol>

      {!policyExists && (
        <p className="mt-3 rounded-lg border border-sky-400/20 bg-sky-500/5 px-3 py-2 text-[11px] text-sky-100/90">
          {m.policyWillCreate}
        </p>
      )}

      {policyExists && fixes.length > 0 && (
        <div className="mt-4">
          <button
            type="button"
            onClick={() => setCustomizeOpen((open) => !open)}
            className="inline-flex items-center gap-1.5 text-[11px] font-medium text-sky-200 transition hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70"
          >
            {customizeOpen ? (
              <ChevronUp size={14} aria-hidden="true" />
            ) : (
              <ChevronDown size={14} aria-hidden="true" />
            )}
            {m.customizeToggle}
          </button>

          {customizeOpen && (
            <div className="mt-3 grid gap-2 rounded-lg border border-border bg-surface-3/30 p-3">
              <p className="text-[11px] text-faint">{m.customizeHint}</p>
              <ul className="grid gap-1.5">
                {fixes.map((fix) => {
                  const checked = selectedFixIds.includes(fix.id);
                  return (
                    <li key={fix.id}>
                      <label className="flex cursor-pointer items-start gap-2 rounded-lg border border-border bg-surface-3/50 px-3 py-2 text-[11px] text-muted">
                        <input
                          type="checkbox"
                          className="mt-0.5"
                          checked={checked}
                          disabled={running}
                          onChange={() => toggleFix(fix.id)}
                        />
                        <span className="min-w-0 flex-1">
                          <span className="block font-medium text-text">
                            {fixLabels[fix.id] ?? fix.id}
                          </span>
                        </span>
                      </label>
                    </li>
                  );
                })}
              </ul>
              {ignoreSelected && status.ignoreFixTargets.length > 0 && (
                <div className="grid gap-2">
                  <p className="text-[11px] font-medium text-text">
                    {messages.setup.recommendedFixes.ignoreTargetsLabel}
                  </p>
                  <IgnoreTargetsPicker
                    targets={status.ignoreFixTargets}
                    selectedTargets={selectedIgnoreTargets}
                    disabled={running}
                    compact
                    onToggle={toggleIgnoreTarget}
                  />
                </div>
              )}
              {envEncryptSelected && eligibleEnvTargets.length > 0 && (
                <div className="grid gap-2">
                  <p className="text-[11px] font-medium text-text">
                    {messages.setup.recommendedFixes.envTargetsLabel}
                  </p>
                  <ul className="grid gap-1.5">
                    {status.envFiles
                      .filter((file) => file.state !== "encrypted")
                      .map((file, index) => {
                        const checked = selectedEnvTargets.includes(file.name);
                        return (
                          <li key={`${file.name}:${index}`}>
                            <label className="flex cursor-pointer items-start gap-2 rounded-lg border border-border/70 bg-surface-3/30 px-3 py-1.5 text-[11px] text-muted">
                              <input
                                type="checkbox"
                                className="mt-0.5"
                                checked={checked}
                                disabled={running}
                                onChange={() => toggleEnvTarget(file.name)}
                              />
                              <span className="min-w-0 flex-1">
                                <code className="block font-medium text-text">{file.name}</code>
                                <span className="text-[10px] text-faint">
                                  {messages.setup.doctor.envFiles.states[file.state]}
                                </span>
                              </span>
                            </label>
                          </li>
                        );
                      })}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        {!allDone && (
          <Button
            variant="primary"
            size="sm"
            loading={running}
            disabled={applyDisabled}
            onClick={() => onQuickSetup(selectedFixIds, selectedIgnoreTargets, selectedEnvTargets)}
          >
            {primaryLabel}
          </Button>
        )}
        {onOpenAdvanced && (
          <Button
            variant={allDone ? "primary" : "secondary"}
            size="sm"
            disabled={running}
            onClick={onOpenAdvanced}
          >
            {m.openAdvanced}
          </Button>
        )}
      </div>

      {allDone && <p className="mt-2 text-[11px] text-emerald-200/90">{m.allCompleteHint}</p>}

      {applyDisabled && !running && !allDone && policyExists && (
        <>
          {selectedFixIds.length === 0 && (
            <p className="mt-2 text-[11px] text-amber-200/90">{m.nothingSelected}</p>
          )}
          {ignoreSelected && selectedIgnoreTargets.length === 0 && (
            <p className="mt-2 text-[11px] text-amber-200/90">
              {messages.setup.hints.selectIgnoreTarget}
            </p>
          )}
          {envEncryptSelected && selectedEnvTargets.length === 0 && (
            <p className="mt-2 text-[11px] text-amber-200/90">
              {messages.setup.hints.selectEnvTarget}
            </p>
          )}
        </>
      )}
    </section>
  );
}
