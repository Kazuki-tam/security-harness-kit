import { useI18n } from "../i18n";
import type { ActionState, ProjectStatus } from "../types";
import { SetupActionCard } from "./SetupActionCard";

type Props = {
  status: ProjectStatus;
  actionState: ActionState;
  onInitPolicy: (strict: boolean) => void;
  onFixDoctorIgnore: () => void;
  onInstallPreCommit: () => void;
  onInstallAiHooks: () => void;
  onApplyNpmHardening: () => void;
  onInstallSkills: () => void;
};

export function ProjectSetupPanel({
  status,
  actionState,
  onInitPolicy,
  onFixDoctorIgnore,
  onInstallPreCommit,
  onInstallAiHooks,
  onApplyNpmHardening,
  onInstallSkills,
}: Props) {
  const { messages } = useI18n();
  const m = messages.setup;
  const running = actionState.status === "running";
  const policyExists = status.policy.exists;
  const ignoreMissingPatterns = status.doctor.missingIgnorePatterns;
  const ignoreReady = policyExists && status.doctor.ignoreOk;
  const aiHooksInstalled = status.hooks.aiTools.some((tool) => tool.installed);
  const hasNpmProjects = status.npmHardening.hasProjects;
  const npmReady = status.npmHardening.ok;
  const projectSkills = status.skills.filter((s) => s.label.includes("(project)"));
  const skillsInstalled = projectSkills.some((s) => s.installed);

  return (
    <div className="grid gap-4">
      <SetupActionCard
        title={m.policy.title}
        description={m.policy.description}
        statusLabel={policyExists ? m.statusReady : m.statusMissing}
        statusTone={policyExists ? "ok" : "warn"}
        primaryLabel={policyExists ? m.policy.recreate : m.policy.create}
        secondaryLabel={policyExists ? undefined : m.policy.createStrict}
        onPrimary={() => onInitPolicy(false)}
        onSecondary={policyExists ? undefined : () => onInitPolicy(true)}
        primaryLoading={running}
        primaryDisabled={running}
      />

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
        primaryLabel={m.ignore.apply}
        onPrimary={onFixDoctorIgnore}
        primaryLoading={running}
        primaryDisabled={running || !policyExists || ignoreReady}
      >
        {ignoreMissingPatterns.length > 0 && (
          <ul className="grid gap-1 text-[11px] text-muted">
            {ignoreMissingPatterns.map((pat) => (
              <li key={pat} className="font-mono">
                · {pat}
              </li>
            ))}
          </ul>
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
        statusTone={
          status.hooks.preCommit.installed && status.hooks.preCommit.isGitRepo ? "ok" : "warn"
        }
        primaryLabel={m.gitHook.install}
        onPrimary={onInstallPreCommit}
        primaryLoading={running}
        primaryDisabled={running || !policyExists || !status.hooks.preCommit.isGitRepo}
      >
        {status.hooks.preCommit.hookPath && (
          <p className="font-mono text-[11px] text-faint">{status.hooks.preCommit.hookPath}</p>
        )}
      </SetupActionCard>

      <SetupActionCard
        title={m.aiHooks.title}
        description={m.aiHooks.description}
        statusLabel={aiHooksInstalled ? m.statusReady : m.statusMissing}
        statusTone={aiHooksInstalled ? "ok" : "warn"}
        primaryLabel={m.aiHooks.install}
        onPrimary={onInstallAiHooks}
        primaryLoading={running}
        primaryDisabled={running || !policyExists}
      >
        <ul className="grid gap-1.5">
          {status.hooks.aiTools.map((tool) => (
            <li
              key={tool.tool}
              className="flex items-center justify-between gap-2 text-[11px] text-muted"
            >
              <span className="font-medium text-text">{tool.tool}</span>
              <span>{tool.installed ? m.statusReady : m.statusMissing}</span>
            </li>
          ))}
        </ul>
      </SetupActionCard>

      <SetupActionCard
        title={m.npm.title}
        description={m.npm.description}
        statusLabel={
          !hasNpmProjects ? m.npm.notApplicable : npmReady ? m.statusReady : m.statusNeedsAttention
        }
        statusTone={!hasNpmProjects ? "neutral" : npmReady ? "ok" : "warn"}
        primaryLabel={m.npm.apply}
        onPrimary={onApplyNpmHardening}
        primaryLoading={running}
        primaryDisabled={running || !hasNpmProjects}
      >
        {status.npmHardening.recommendations.length > 0 && (
          <ul className="grid gap-1 text-[11px] text-muted">
            {status.npmHardening.recommendations.map((rec) => (
              <li key={rec}>· {rec}</li>
            ))}
          </ul>
        )}
      </SetupActionCard>

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

      {actionState.status !== "idle" && actionState.status !== "running" && (
        <ActionFeedback state={actionState} />
      )}
    </div>
  );
}

function ActionFeedback({ state }: { state: ActionState }) {
  const { messages } = useI18n();
  const m = messages.setup.action;

  if (state.status === "error") {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-[12px] text-red-100">
        <strong className="block">{m.failed}</strong>
        <p className="mt-1">{state.message}</p>
      </div>
    );
  }

  if (state.status === "done") {
    return (
      <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-[12px] text-emerald-100">
        <strong className="block">{state.result.message}</strong>
        {state.result.details.length > 0 && (
          <ul className="mt-2 grid gap-1 text-emerald-100/90">
            {state.result.details.map((detail) => (
              <li key={detail} className="font-mono text-[11px]">
                {detail}
              </li>
            ))}
          </ul>
        )}
      </div>
    );
  }

  return null;
}
