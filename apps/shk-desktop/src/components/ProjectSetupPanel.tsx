import { AlertTriangle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useI18n } from "../i18n";
import {
  aiHookSelectionFromStatus,
  aiHookSelectionHasAdditions,
  aiHookSelectionHasRemovals,
  aiHookSelectionIsFullyDisabled,
  aiHookSelectionMatches,
  countPendingQuickSetup,
  npmSettingsReady,
  projectSkillsInstalled,
  projectSkillStatuses,
} from "../setup/plan";
import type { ActionState, AiHookSetupSelection, ProjectStatus, SetupHandlers } from "../types";
import { DEFAULT_IGNORE_TARGETS, IgnoreTargetsPicker } from "./IgnoreTargetsPicker";
import { ConfirmDialog } from "./ConfirmDialog";
import { QuickSetupCard } from "./QuickSetupCard";
import { SetupActionCard } from "./SetupActionCard";
import { SetupAdvancedSection } from "./SetupAdvancedSection";
import { SetupFeedback } from "./SetupFeedback";

type Props = SetupHandlers & {
  status: ProjectStatus;
  actionState: ActionState;
  onDismissActionFeedback: () => void;
};

export function ProjectSetupPanel({
  status,
  actionState,
  onDismissActionFeedback,
  onQuickSetup,
  onInitPolicy,
  onFixDoctorIgnore,
  onInstallPreCommit,
  onInstallAiHooks,
  onApplyNpmHardening,
  onInstallSkills,
}: Props) {
  const { messages, t } = useI18n();
  const m = messages.setup;
  const running = actionState.status === "running";
  const policyExists = status.policy.exists;
  const ignoreMissingPatterns = status.doctor.missingIgnorePatterns;
  const ignoreReady = policyExists && status.doctor.ignoreOk;
  const hasNpmProjects = status.npmHardening.hasProjects;
  const npmSettingsOk = npmSettingsReady(status);
  const projectSkills = projectSkillStatuses(status);
  const skillsInstalled = projectSkillsInstalled(status);
  const pendingQuickSetup = countPendingQuickSetup(status);

  const [selectedIgnoreTargets, setSelectedIgnoreTargets] =
    useState<string[]>(DEFAULT_IGNORE_TARGETS);
  const [aiHookSelection, setAiHookSelection] = useState<AiHookSetupSelection>(() =>
    aiHookSelectionFromStatus(status),
  );
  const [npmHardeningEnabled, setNpmHardeningEnabled] = useState(true);
  const [advancedOpen, setAdvancedOpen] = useState(pendingQuickSetup > 0);
  const [confirmRecreatePolicy, setConfirmRecreatePolicy] = useState(false);
  const [confirmNpmRemove, setConfirmNpmRemove] = useState(false);
  const [confirmAiRemove, setConfirmAiRemove] = useState(false);
  const advancedRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setSelectedIgnoreTargets(DEFAULT_IGNORE_TARGETS);
  }, [status.path]);

  useEffect(() => {
    setAiHookSelection(aiHookSelectionFromStatus(status));
  }, [
    status.path,
    status.aiSafetyApplied.scanHooksClaudeCode,
    status.aiSafetyApplied.scanHooksCursor,
    status.aiSafetyApplied.scanHooksCodex,
    status.aiSafetyApplied.scanHooksCopilot,
    status.aiSafetyApplied.scanHooksAntigravity,
    status.aiSafetyApplied.scanHooksWindsurf,
    status.aiSafetyApplied.claudeDeny,
    status.aiSafetyApplied.claudeSandbox,
    status.aiSafetyApplied.codexSandbox,
  ]);

  useEffect(() => {
    setNpmHardeningEnabled(npmSettingsReady(status));
  }, [status.path, status.npmHardening.ignoreScriptsOk, status.npmHardening.ageGatesOk]);

  useEffect(() => {
    if (pendingQuickSetup > 0) return;
    setAdvancedOpen(false);
  }, [status.path, pendingQuickSetup]);

  const toggleIgnoreTarget = (name: string) => {
    setSelectedIgnoreTargets((prev) =>
      prev.includes(name) ? prev.filter((target) => target !== name) : [...prev, name],
    );
  };

  const toggleAiHookSelection = (key: keyof AiHookSetupSelection) => {
    setAiHookSelection((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const openAdvanced = () => {
    setAdvancedOpen(true);
    requestAnimationFrame(() => {
      advancedRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };

  const appliedAiHooks = aiHookSelectionFromStatus(status);
  const aiHookSelectionChanged = !aiHookSelectionMatches(appliedAiHooks, aiHookSelection);
  const aiHookHasRemovals = aiHookSelectionHasRemovals(appliedAiHooks, aiHookSelection);
  const aiHookHasAdditions = aiHookSelectionHasAdditions(appliedAiHooks, aiHookSelection);
  const aiHookSettingsRemoved = aiHookSelectionIsFullyDisabled(appliedAiHooks);
  const scanHooksSelected =
    aiHookSelection.scanHooksClaudeCode ||
    aiHookSelection.scanHooksCursor ||
    aiHookSelection.scanHooksCodex ||
    aiHookSelection.scanHooksCopilot ||
    aiHookSelection.scanHooksAntigravity ||
    aiHookSelection.scanHooksWindsurf;
  const showCliNotFoundWarning = !status.cliInstalled && scanHooksSelected;
  const aiHookStatusLabel = !policyExists
    ? m.statusMissing
    : aiHookSelectionChanged
      ? m.statusPending
      : aiHookSettingsRemoved
        ? m.statusRemoved
        : m.statusApplied;
  const aiHookStatusTone = !policyExists
    ? "neutral"
    : aiHookSelectionChanged
      ? "warn"
      : aiHookSettingsRemoved
        ? "neutral"
        : "ok";
  const aiHookPrimaryLabel =
    aiHookHasRemovals && !aiHookHasAdditions
      ? m.aiHooks.removeSelected
      : aiHookHasRemovals
        ? m.aiHooks.syncSelected
        : m.aiHooks.applySelected;
  const gitReady = status.hooks.preCommit.installed && status.hooks.preCommit.isGitRepo;
  const gitDisabled = running || !policyExists || !status.hooks.preCommit.isGitRepo || gitReady;
  const ignoreDisabled =
    running || !policyExists || ignoreReady || selectedIgnoreTargets.length === 0;
  const npmSelectionChanged = npmHardeningEnabled !== npmSettingsOk;
  const npmPrimaryDisabled = running || !npmSelectionChanged;
  const npmStatusLabel = npmSelectionChanged
    ? m.statusPending
    : npmSettingsOk
      ? m.statusApplied
      : m.statusRemoved;
  const npmStatusTone = npmSelectionChanged ? "warn" : npmSettingsOk ? "ok" : "neutral";

  const handleNpmPrimary = () => {
    if (!npmHardeningEnabled) {
      setConfirmNpmRemove(true);
      return;
    }
    onApplyNpmHardening(true);
  };

  const handleAiPrimary = () => {
    if (
      aiHookHasRemovals &&
      aiHookSelectionIsFullyDisabled(aiHookSelection) &&
      !aiHookHasAdditions
    ) {
      setConfirmAiRemove(true);
      return;
    }
    onInstallAiHooks(aiHookSelection);
  };

  return (
    <div className="grid gap-4">
      {actionState.status !== "idle" && actionState.status !== "running" && (
        <SetupFeedback state={actionState} onDismiss={onDismissActionFeedback} />
      )}

      <QuickSetupCard
        status={status}
        running={running}
        onQuickSetup={onQuickSetup}
        onOpenAdvanced={openAdvanced}
      />

      <div ref={advancedRef}>
        <SetupAdvancedSection
          open={advancedOpen}
          onToggle={() => setAdvancedOpen((value) => !value)}
          pendingHint={
            pendingQuickSetup > 0
              ? t(messages.setup.advanced.pendingHint, { count: pendingQuickSetup })
              : undefined
          }
        >
          <SetupActionCard
            title={m.policy.title}
            description={m.policy.description}
            statusLabel={policyExists ? m.statusReady : m.statusMissing}
            statusTone={policyExists ? "ok" : "warn"}
            primaryLabel={policyExists ? m.policy.recreate : m.policy.create}
            secondaryLabel={policyExists ? undefined : m.policy.createStrict}
            onPrimary={() =>
              policyExists
                ? setConfirmRecreatePolicy(true)
                : onInitPolicy({ strict: false, force: false })
            }
            onSecondary={
              policyExists ? undefined : () => onInitPolicy({ strict: true, force: false })
            }
            primaryLoading={running}
            primaryDisabled={running}
            secondaryDisabled={running}
          >
            {policyExists && <p className="text-[11px] text-faint">{m.policy.recreateHint}</p>}
            {!policyExists && <p className="text-[11px] text-faint">{m.policy.strictHint}</p>}
          </SetupActionCard>

          <SetupActionCard
            title={m.ignore.title}
            description={m.ignore.description}
            statusLabel={
              !policyExists
                ? m.ignore.policyRequired
                : ignoreReady
                  ? m.statusReady
                  : m.statusNeedsAttention
            }
            statusTone={!policyExists ? "neutral" : ignoreReady ? "ok" : "warn"}
            primaryLabel={m.ignore.applySelected}
            onPrimary={() => onFixDoctorIgnore(selectedIgnoreTargets)}
            primaryLoading={running}
            primaryDisabled={ignoreDisabled}
            primaryDisabledReason={
              !policyExists
                ? m.hints.policyFirst
                : ignoreReady
                  ? m.hints.ignoreAlreadyOk
                  : selectedIgnoreTargets.length === 0
                    ? m.hints.selectIgnoreTarget
                    : undefined
            }
          >
            {ignoreMissingPatterns.length > 0 && (
              <div className="grid gap-1 text-[11px] text-muted">
                <p className="font-medium text-text">{m.ignore.missingLabel}</p>
                <ul className="grid gap-1">
                  {ignoreMissingPatterns.map((pat) => (
                    <li key={pat}>
                      · {m.ignore.patternDescriptions[pat] ?? pat}
                      <span className="ml-1 font-mono text-[10px] text-faint">({pat})</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {policyExists && !ignoreReady && status.ignoreFixTargets.length > 0 && (
              <div className="mt-3 grid gap-2">
                <p className="text-[11px] font-medium text-text">{m.ignore.targetsLabel}</p>
                <IgnoreTargetsPicker
                  targets={status.ignoreFixTargets}
                  selectedTargets={selectedIgnoreTargets}
                  disabled={running}
                  onToggle={toggleIgnoreTarget}
                />
              </div>
            )}
          </SetupActionCard>

          <SetupActionCard
            title={m.gitHook.title}
            description={m.gitHook.description}
            statusLabel={
              !status.hooks.preCommit.isGitRepo
                ? m.gitHook.notRepo
                : status.hooks.preCommit.installed
                  ? m.statusReady
                  : m.statusMissing
            }
            statusTone={gitReady ? "ok" : "warn"}
            primaryLabel={m.gitHook.install}
            onPrimary={onInstallPreCommit}
            primaryLoading={running}
            primaryDisabled={gitDisabled}
            primaryDisabledReason={
              !policyExists
                ? m.hints.policyFirst
                : !status.hooks.preCommit.isGitRepo
                  ? m.hints.notGitRepo
                  : gitReady
                    ? m.hints.gitHookAlreadyOk
                    : undefined
            }
          />

          <SetupActionCard
            title={m.aiHooks.title}
            description={m.aiHooks.description}
            statusLabel={aiHookStatusLabel}
            statusTone={aiHookStatusTone}
            primaryLabel={aiHookPrimaryLabel}
            onPrimary={handleAiPrimary}
            primaryLoading={running}
            primaryDisabled={running || !policyExists || !aiHookSelectionChanged}
            primaryDisabledReason={
              !policyExists
                ? m.hints.policyFirst
                : !aiHookSelectionChanged
                  ? m.hints.aiNoChanges
                  : undefined
            }
          >
            <ul className="mb-3 grid gap-1.5">
              {status.hooks.aiTools.map((tool) => (
                <li
                  key={tool.tool}
                  className="flex items-center justify-between rounded-lg border border-border bg-surface-3/50 px-3 py-2 text-[11px]"
                >
                  <span className="font-medium text-text">
                    {m.aiHooks.toolNames[tool.tool] ?? tool.tool}
                  </span>
                  <span className={tool.installed ? "text-emerald-300" : "text-amber-200"}>
                    {tool.installed ? m.statusReady : m.statusMissing}
                  </span>
                </li>
              ))}
            </ul>
            <p className="mb-2 text-[11px] text-faint">{m.aiHooks.selectionHint}</p>
            <p className="mb-1 text-[11px] font-medium text-text">{m.aiHooks.scanHooksGroup}</p>
            <p className="mb-2 text-[11px] text-faint">{m.aiHooks.scanHooksHint}</p>
            <ul className="mb-3 grid gap-1.5">
              <AiHookOption
                checked={aiHookSelection.scanHooksClaudeCode}
                disabled={running}
                label={m.aiHooks.toolNames["claude-code"]}
                hint={m.aiHooks.scanHooksToolHint}
                onToggle={() => toggleAiHookSelection("scanHooksClaudeCode")}
              />
              <AiHookOption
                checked={aiHookSelection.scanHooksCursor}
                disabled={running}
                label={m.aiHooks.toolNames.cursor}
                hint={m.aiHooks.scanHooksToolHint}
                onToggle={() => toggleAiHookSelection("scanHooksCursor")}
              />
              <AiHookOption
                checked={aiHookSelection.scanHooksCodex}
                disabled={running}
                label={m.aiHooks.toolNames.codex}
                hint={m.aiHooks.scanHooksToolHint}
                onToggle={() => toggleAiHookSelection("scanHooksCodex")}
              />
              <AiHookOption
                checked={aiHookSelection.scanHooksCopilot}
                disabled={running}
                label={m.aiHooks.toolNames.copilot}
                hint={m.aiHooks.scanHooksToolHint}
                onToggle={() => toggleAiHookSelection("scanHooksCopilot")}
              />
              <AiHookOption
                checked={aiHookSelection.scanHooksAntigravity}
                disabled={running}
                label={m.aiHooks.toolNames.antigravity}
                hint={m.aiHooks.scanHooksToolHint}
                onToggle={() => toggleAiHookSelection("scanHooksAntigravity")}
              />
              <AiHookOption
                checked={aiHookSelection.scanHooksWindsurf}
                disabled={running}
                label={m.aiHooks.toolNames.windsurf}
                hint={m.aiHooks.scanHooksToolHint}
                onToggle={() => toggleAiHookSelection("scanHooksWindsurf")}
              />
            </ul>
            {showCliNotFoundWarning && (
              <div className="mb-3 flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2.5 text-[11px] text-amber-100">
                <AlertTriangle
                  size={14}
                  aria-hidden="true"
                  className="mt-0.5 shrink-0 text-amber-300"
                />
                <div>
                  <p className="font-semibold text-amber-50">{m.aiHooks.cliNotFoundTitle}</p>
                  <p className="mt-0.5 text-amber-100/90">{m.aiHooks.cliNotFoundBody}</p>
                </div>
              </div>
            )}
            <ul className="grid gap-1.5">
              <AiHookOption
                checked={aiHookSelection.claudeDeny}
                disabled={running}
                label={m.aiHooks.claudeDeny}
                hint={m.aiHooks.claudeDenyHint}
                onToggle={() => toggleAiHookSelection("claudeDeny")}
              />
              <AiHookOption
                checked={aiHookSelection.claudeSandbox}
                disabled={running}
                label={m.aiHooks.claudeSandbox}
                hint={m.aiHooks.claudeSandboxHint}
                onToggle={() => toggleAiHookSelection("claudeSandbox")}
              />
              <AiHookOption
                checked={aiHookSelection.codexSandbox}
                disabled={running}
                label={m.aiHooks.codexSandbox}
                hint={m.aiHooks.codexSandboxHint}
                onToggle={() => toggleAiHookSelection("codexSandbox")}
              />
            </ul>
          </SetupActionCard>

          {hasNpmProjects && (
            <SetupActionCard
              title={m.npm.title}
              description={m.npm.description}
              statusLabel={npmStatusLabel}
              statusTone={npmStatusTone}
              primaryLabel={npmHardeningEnabled ? m.npm.apply : m.npm.remove}
              onPrimary={handleNpmPrimary}
              primaryLoading={running}
              primaryDisabled={npmPrimaryDisabled}
              primaryDisabledReason={
                !npmSelectionChanged
                  ? npmHardeningEnabled
                    ? m.hints.npmAlreadyOk
                    : m.hints.npmNoChanges
                  : undefined
              }
            >
              <label className="mb-3 flex cursor-pointer items-start gap-2 rounded-lg border border-border bg-surface-3/50 px-3 py-2 text-[11px] text-muted">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={npmHardeningEnabled}
                  disabled={running}
                  onChange={() => setNpmHardeningEnabled((enabled) => !enabled)}
                />
                <span className="min-w-0 flex-1">
                  <span className="block font-medium text-text">{m.npm.enableLabel}</span>
                  <span className="text-[10px] text-faint">
                    {npmHardeningEnabled ? m.npm.enabledHint : m.npm.disabledHint}
                  </span>
                </span>
              </label>
              {status.npmHardening.recommendations.length > 0 && (
                <ul className="grid gap-1 text-[11px] text-muted">
                  {status.npmHardening.recommendations.map((rec) => (
                    <li key={rec}>· {rec}</li>
                  ))}
                </ul>
              )}
            </SetupActionCard>
          )}

          <SetupActionCard
            title={m.skills.title}
            description={m.skills.description}
            statusLabel={skillsInstalled ? m.statusReady : m.statusMissing}
            statusTone={skillsInstalled ? "ok" : "neutral"}
            primaryLabel={m.skills.install}
            onPrimary={onInstallSkills}
            primaryLoading={running}
            primaryDisabled={running}
          >
            <ul className="grid gap-1.5">
              {projectSkills.map((skill) => (
                <li key={skill.label} className="text-[11px] text-muted">
                  {skill.label}: {skill.installed ? m.statusReady : m.statusMissing}
                </li>
              ))}
            </ul>
          </SetupActionCard>
        </SetupAdvancedSection>
      </div>

      <ConfirmDialog
        open={confirmRecreatePolicy}
        title={m.policy.recreateConfirmTitle}
        description={m.policy.recreateConfirmBody}
        confirmLabel={m.policy.recreate}
        variant="danger"
        onCancel={() => setConfirmRecreatePolicy(false)}
        onConfirm={() => {
          setConfirmRecreatePolicy(false);
          onInitPolicy({ strict: false, force: true });
        }}
      />

      <ConfirmDialog
        open={confirmNpmRemove}
        title={m.npm.removeConfirmTitle}
        description={m.npm.removeConfirmBody}
        confirmLabel={m.npm.remove}
        variant="danger"
        onCancel={() => setConfirmNpmRemove(false)}
        onConfirm={() => {
          setConfirmNpmRemove(false);
          onApplyNpmHardening(false);
        }}
      />

      <ConfirmDialog
        open={confirmAiRemove}
        title={m.aiHooks.removeConfirmTitle}
        description={m.aiHooks.removeConfirmBody}
        confirmLabel={m.aiHooks.removeSelected}
        variant="danger"
        onCancel={() => setConfirmAiRemove(false)}
        onConfirm={() => {
          setConfirmAiRemove(false);
          onInstallAiHooks(aiHookSelection);
        }}
      />
    </div>
  );
}

function AiHookOption({
  checked,
  disabled,
  label,
  hint,
  onToggle,
}: {
  checked: boolean;
  disabled: boolean;
  label: string;
  hint: string;
  onToggle: () => void;
}) {
  return (
    <li>
      <label className="flex cursor-pointer items-start gap-2 rounded-lg border border-border bg-surface-3/50 px-3 py-2 text-[11px] text-muted">
        <input
          type="checkbox"
          className="mt-0.5"
          checked={checked}
          disabled={disabled}
          onChange={onToggle}
        />
        <span className="min-w-0 flex-1">
          <span className="block font-medium text-text">{label}</span>
          <span className="text-[10px] text-faint">{hint}</span>
        </span>
      </label>
    </li>
  );
}
