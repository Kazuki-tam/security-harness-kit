import { Check, ChevronDown, TriangleAlert } from "lucide-react";
import { useId } from "react";
import type { Messages } from "../../i18n/types";
import type { PolicyTone } from "../../hooks/useMaskPolicyStatus";
import type { Project } from "../../types";
import { MaskModeToggle, type MaskMode } from "./MaskModeToggle";

export type MaskStep = { id: number; label: string };

type Props = {
  title: string;
  subtitle: string;
  mode: MaskMode;
  onModeChange: (mode: MaskMode) => void;
  modeDisabled: boolean;
  policyLabel?: string;
  policyPath?: string;
  policyTone: PolicyTone;
  policySelectLabel: string;
  policyDefaultOption: string;
  projects: Project[];
  selectedPolicyProjectId: string | null;
  policySelectionDisabled: boolean;
  onPolicyProjectChange: (projectId: string | null) => void;
  /** Shown under the project select when the mode cannot run yet. */
  gate?: { title: string; body: string } | null;
  gateId?: string;
  currentStep: number;
  steps: MaskStep[];
  messages: Messages["mask"];
};

export function MaskHeader({
  title,
  subtitle,
  mode,
  onModeChange,
  modeDisabled,
  policyLabel,
  policyPath,
  policyTone,
  policySelectLabel,
  policyDefaultOption,
  projects,
  selectedPolicyProjectId,
  policySelectionDisabled,
  onPolicyProjectChange,
  gate,
  gateId,
  currentStep,
  steps,
  messages: m,
}: Props) {
  const policySelectId = useId();

  return (
    <header className="grid gap-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold text-white">{title}</h1>
          <p className="mt-1 max-w-2xl text-[13px] leading-relaxed text-muted">{subtitle}</p>
        </div>
        <div className="grid w-full gap-3 self-start rounded-xl border border-border bg-surface-2/70 p-3 sm:w-80">
          <MaskModeToggle
            mode={mode}
            onChange={onModeChange}
            disabled={modeDisabled}
            messages={m.mode}
          />
          <div className="grid gap-2">
            <div className="flex items-center justify-between gap-3">
              <label
                htmlFor={policySelectId}
                className="text-[10px] font-semibold tracking-[0.12em] text-white/70 uppercase"
              >
                {policySelectLabel}
              </label>
              {policyLabel && (
                <span
                  className={`inline-flex min-w-0 items-center gap-1.5 text-[10px] ${
                    policyTone === "project"
                      ? "text-emerald-200"
                      : policyTone === "error"
                        ? "text-red-200"
                        : "text-muted"
                  }`}
                  title={policyPath ?? policyLabel}
                >
                  <span
                    className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                      policyTone === "project"
                        ? "bg-emerald-400"
                        : policyTone === "error"
                          ? "bg-red-400"
                          : policyTone === "loading"
                            ? "animate-pulse bg-sky-300"
                            : "bg-slate-400"
                    }`}
                    aria-hidden="true"
                  />
                  <span className="truncate">{policyLabel}</span>
                </span>
              )}
            </div>
            <div className="relative">
              <select
                id={policySelectId}
                value={selectedPolicyProjectId ?? ""}
                disabled={policySelectionDisabled}
                onChange={(event) => onPolicyProjectChange(event.target.value || null)}
                className="w-full appearance-none rounded-lg border border-border-strong bg-canvas/70 py-2 pr-9 pl-3 text-[12px] font-medium text-white outline-none transition hover:border-sky-400/40 focus:border-sky-300/70 focus:ring-2 focus:ring-sky-300/20 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <option value="">{policyDefaultOption}</option>
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
              <ChevronDown
                size={14}
                className="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 text-muted"
                aria-hidden="true"
              />
            </div>
            {gate && (
              <div
                id={gateId}
                role="note"
                className="flex items-start gap-2 rounded-lg border border-amber-400/35 bg-amber-500/10 px-3 py-2 text-[11px] leading-relaxed text-amber-100"
              >
                <TriangleAlert size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
                <div>
                  <p className="font-semibold">{gate.title}</p>
                  <p className="mt-0.5 text-amber-100/85">{gate.body}</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <ol
        className={`grid gap-2 sm:gap-3 ${steps.length === 4 ? "grid-cols-4" : "grid-cols-3"}`}
        aria-label={title}
      >
        {steps.map((step, index) => {
          const active = currentStep === step.id;
          const done = currentStep > step.id;
          return (
            <li
              key={step.id}
              aria-current={active ? "step" : undefined}
              className={`rounded-xl border px-3 py-2.5 transition sm:px-4 ${
                active
                  ? "border-sky-400/40 bg-sky-500/10 shadow-[0_12px_40px_rgba(44,202,251,0.08)]"
                  : done
                    ? "border-emerald-500/25 bg-emerald-500/5"
                    : "border-border bg-surface-2/50"
              }`}
            >
              <div className="flex items-center gap-2">
                <span
                  className={`grid h-6 w-6 shrink-0 place-items-center rounded-full text-[11px] font-semibold ${
                    active
                      ? "bg-sky-400/20 text-sky-100 ring-1 ring-inset ring-sky-400/35"
                      : done
                        ? "bg-emerald-500/15 text-emerald-200"
                        : "bg-surface-3 text-muted"
                  }`}
                >
                  {done ? <Check size={12} aria-hidden="true" /> : index + 1}
                </span>
                <span
                  className={`text-[12px] font-medium ${active ? "text-white" : done ? "text-emerald-100" : "text-muted"}`}
                >
                  {step.label}
                </span>
              </div>
            </li>
          );
        })}
      </ol>
    </header>
  );
}
