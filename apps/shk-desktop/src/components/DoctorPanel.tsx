import { AlertTriangle, CheckCircle2, Info, XCircle } from "lucide-react";
import { useI18n } from "../i18n";
import type { DoctorIssue, DoctorStatus } from "../types";
import { Button } from "./Button";

type Props = {
  doctor: DoctorStatus;
  npmApplicable: boolean;
  onOpenSetup?: () => void;
};

export function DoctorPanel({ doctor, npmApplicable, onOpenSetup }: Props) {
  const { messages } = useI18n();
  const m = messages.setup.doctor;

  const checks = [
    { ok: doctor.gitPreCommit, label: m.gitHook },
    { ok: doctor.aiManagedHooks, label: m.aiHooks },
    { ok: doctor.ignoreOk, label: m.ignore },
    { ok: doctor.claudeDenyOk, label: m.claudeDeny },
    { ok: doctor.codexConfigOk, label: m.codexConfig },
    ...(doctor.envApplicable ? [{ ok: doctor.envOk, label: m.env }] : []),
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
