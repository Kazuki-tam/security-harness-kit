import { AlertTriangle, CheckCircle2, Info, Lock, XCircle } from "lucide-react";
import { useI18n } from "../i18n";
import type { DoctorIssue, DoctorStatus, EnvFileReport } from "../types";
import { Button } from "./Button";

const MAX_VISIBLE_PLAINTEXT_KEYS = 6;

type Props = {
  doctor: DoctorStatus;
  npmApplicable: boolean;
  envFiles?: EnvFileReport[];
  onOpenSetup?: () => void;
};

export function DoctorPanel({ doctor, npmApplicable, envFiles = [], onOpenSetup }: Props) {
  const { messages } = useI18n();
  const m = messages.setup.doctor;

  const checks = [
    { ok: doctor.gitPreCommit, label: m.gitHook },
    { ok: doctor.aiManagedHooks, label: m.aiHooks },
    { ok: doctor.ignoreOk, label: m.ignore },
    { ok: doctor.claudeDenyOk, label: m.claudeDeny },
    { ok: doctor.codexConfigOk, label: m.codexConfig },
    ...(doctor.envApplicable ? [{ ok: doctor.envOk, label: m.env }] : []),
    ...(doctor.workflowsApplicable ? [{ ok: doctor.workflowsOk, label: m.workflows }] : []),
    ...(npmApplicable ? [{ ok: doctor.npmOk, label: m.npm }] : []),
  ];
  const issues = doctor.issues.filter((issue) => {
    if (!npmApplicable && issue.id === "npm_hardening") {
      return false;
    }
    if (
      !doctor.envApplicable &&
      (issue.id.startsWith("env:") || issue.id.startsWith("env_mixed:"))
    ) {
      return false;
    }
    return true;
  });

  return (
    <section className="rounded-xl border border-border bg-surface-2 p-4">
      <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h3 className="text-sm font-semibold text-white">{m.title}</h3>
          <p className="mt-1 text-[12px] text-muted">{m.subtitle}</p>
        </div>
        {onOpenSetup && issues.length > 0 && (
          <Button variant="primary" size="sm" className="shrink-0 self-start" onClick={onOpenSetup}>
            {m.openSetup}
          </Button>
        )}
      </div>

      <ul className="grid gap-2 sm:grid-cols-2">
        {checks.map(({ ok, label }) => (
          <li
            key={label}
            className="flex items-center gap-2 rounded-lg border border-border bg-surface-3/50 px-3 py-2 text-[12px]"
          >
            {ok ? (
              <CheckCircle2 size={14} className="shrink-0 text-emerald-300" aria-hidden="true" />
            ) : (
              <AlertTriangle size={14} className="shrink-0 text-amber-300" aria-hidden="true" />
            )}
            <span className={ok ? "text-text" : "text-amber-100"}>{label}</span>
          </li>
        ))}
      </ul>

      {doctor.envApplicable && envFiles.length > 0 && (
        <div className="mt-4">
          <h4 className="text-[11px] font-semibold tracking-[0.14em] text-faint uppercase">
            {m.envFiles.title}
          </h4>
          <ul className="mt-2 grid gap-2">
            {envFiles.map((file) => (
              <EnvFileRow key={file.name} file={file} />
            ))}
          </ul>
        </div>
      )}

      {issues.length > 0 && (
        <div className="mt-4">
          <h4 className="text-[11px] font-semibold tracking-[0.14em] text-faint uppercase">
            {m.issues}
          </h4>
          <ul className="mt-2 grid gap-2">
            {issues.map((issue) => (
              <IssueRow key={`${issue.id}:${issue.message}`} issue={issue} />
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function EnvFileRow({ file }: { file: EnvFileReport }) {
  const { messages, t } = useI18n();
  const m = messages.setup.doctor;
  const encrypted = file.state === "encrypted";
  const stateLabel = m.envFiles.states[file.state];
  const visibleKeys = file.plaintextKeys.slice(0, MAX_VISIBLE_PLAINTEXT_KEYS);
  const hiddenKeyCount = file.plaintextKeys.length - visibleKeys.length;

  return (
    <li
      className={`rounded-lg border px-3 py-2 text-[12px] ${
        encrypted ? "border-emerald-500/20 bg-emerald-500/5" : "border-amber-500/20 bg-amber-500/5"
      }`}
    >
      <div className="flex flex-wrap items-center gap-2">
        {encrypted ? (
          <Lock size={13} className="shrink-0 text-emerald-300" aria-hidden="true" />
        ) : (
          <AlertTriangle size={13} className="shrink-0 text-amber-300" aria-hidden="true" />
        )}
        <code className="font-medium text-text">{file.name}</code>
        <span
          className={`rounded-full px-2 py-0.5 text-[10px] font-medium ring-1 ring-inset ${
            encrypted
              ? "bg-emerald-500/15 text-emerald-200 ring-emerald-400/30"
              : "bg-amber-500/15 text-amber-100 ring-amber-400/30"
          }`}
        >
          {stateLabel}
        </span>
        {file.encryptedKeyCount > 0 && (
          <span className="text-[10px] text-faint">
            {t(m.envFiles.encryptedCount, { count: file.encryptedKeyCount })}
          </span>
        )}
      </div>
      {file.plaintextKeys.length > 0 && (
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] text-faint">{m.envFiles.plaintextKeys}</span>
          {visibleKeys.map((key, index) => (
            <code
              key={`${key}-${index}`}
              className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] text-amber-100 ring-1 ring-inset ring-amber-400/25"
            >
              {key}
            </code>
          ))}
          {hiddenKeyCount > 0 && (
            <span className="text-[10px] text-faint">
              {t(m.envFiles.moreKeys, { count: hiddenKeyCount })}
            </span>
          )}
        </div>
      )}
    </li>
  );
}

function IssueRow({ issue }: { issue: DoctorIssue }) {
  const Icon =
    issue.severity === "warn" ? AlertTriangle : issue.severity === "critical" ? XCircle : Info;
  const tone =
    issue.severity === "warn"
      ? "border-amber-500/20 bg-amber-500/10 text-amber-100"
      : issue.severity === "critical"
        ? "border-red-500/20 bg-red-500/10 text-red-100"
        : "border-[var(--color-border)] bg-[var(--color-surface-3)]/40 text-[var(--color-text)]";

  return (
    <li className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-[12px] ${tone}`}>
      <Icon size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
      <span>{issue.message}</span>
    </li>
  );
}
