import {
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronDown,
  Copy,
  Eraser,
  ExternalLink,
  FileText,
  FileUp,
  Loader2,
  Save,
  TriangleAlert,
  X,
} from "lucide-react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { useEffect, useId, useState, type DragEvent } from "react";
import { AI_TOOL_OPTIONS, type PreferredAiTool } from "../aiTool";
import { useMaskWorkspace, type MaskInputMode } from "../hooks/useMaskWorkspace";
import {
  fetchMaskPolicyStatus,
  maskFileBasename,
  maskFileKind,
  type MaskPolicyStatus,
  type MaskState,
} from "../mask";
import type { Messages } from "../i18n/types";
import { severityOrder, type Severity } from "../scan";
import type { Project } from "../types";
import { shortenPath } from "../utils";
import { Button } from "./Button";
import { FindingList } from "./FindingList";
import { SeveritySummary } from "./SeveritySummary";

type Props = {
  projects: Project[];
  initialPolicyProjectId: string | null;
  preferredAiTool: PreferredAiTool;
  onPreferredAiToolChange: (tool: PreferredAiTool) => void;
  onNotice?: (message: string) => void;
};

type PolicyStatusState =
  | { status: "loading"; projectPath: string }
  | { status: "done"; projectPath: string | null; data: MaskPolicyStatus }
  | { status: "error"; projectPath: string; message: string };

export function MaskWorkspace({
  projects,
  initialPolicyProjectId,
  preferredAiTool,
  onPreferredAiToolChange,
  onNotice,
}: Props) {
  const [policyProjectId, setPolicyProjectId] = useState<string | null>(() =>
    projects.some((project) => project.id === initialPolicyProjectId)
      ? initialPolicyProjectId
      : null,
  );
  const policyProject = projects.find((project) => project.id === policyProjectId);
  const projectPath = policyProject?.path ?? null;
  const [policyStatus, setPolicyStatus] = useState<PolicyStatusState>({
    status: "done",
    projectPath: null,
    data: { usesProjectPolicy: false },
  });
  const workspace = useMaskWorkspace({
    projectPath,
    preferredAiTool,
    onPreferredAiToolChange,
    onNotice,
  });
  const {
    messages: m,
    t,
    inputMode,
    inputText,
    setInputText,
    selectedFilePath,
    maskState,
    copied,
    saving,
    saveMessage,
    dragActive,
    setDragActive,
    maskedOutput,
    findings,
    fileMeta,
    actionableFindings,
    isLoading,
    canCopy,
    hasInput,
    currentStep,
    resetResult,
    clearInput,
    switchInputMode,
    applySelectedFile,
    chooseFile,
    runMask,
    copyMasked,
    copyAndOpenTool,
    saveMaskedFile,
    removeSelectedFile,
  } = workspace;

  const [findingFilter, setFindingFilter] = useState<Severity | "all">("all");

  useEffect(() => {
    if (policyProjectId && !policyProject) {
      setPolicyProjectId(null);
      resetResult();
    }
  }, [policyProject, policyProjectId, resetResult]);

  useEffect(() => {
    if (!projectPath) {
      setPolicyStatus({
        status: "done",
        projectPath: null,
        data: { usesProjectPolicy: false },
      });
      return;
    }

    let disposed = false;
    setPolicyStatus({ status: "loading", projectPath });
    void fetchMaskPolicyStatus(projectPath)
      .then((data) => {
        if (!disposed) {
          setPolicyStatus({ status: "done", projectPath, data });
        }
      })
      .catch((error) => {
        if (!disposed) {
          setPolicyStatus({
            status: "error",
            projectPath,
            message: error instanceof Error ? error.message : String(error),
          });
        }
      });
    return () => {
      disposed = true;
    };
  }, [projectPath]);

  const currentPolicyStatus: PolicyStatusState =
    policyStatus.projectPath === projectPath
      ? policyStatus
      : projectPath
        ? ({ status: "loading", projectPath } as const)
        : ({
            status: "done",
            projectPath: null,
            data: { usesProjectPolicy: false },
          } as const);
  const policyLabel = !policyProject
    ? undefined
    : currentPolicyStatus.status === "loading"
      ? t(m.policyChecking, { project: policyProject.name })
      : currentPolicyStatus.status === "error"
        ? t(m.policyError, { project: policyProject.name })
        : currentPolicyStatus.data.usesProjectPolicy
          ? t(m.policyProject, { project: policyProject.name })
          : t(m.policyProjectFallback, { project: policyProject.name });
  const policyPath =
    currentPolicyStatus.status === "done" ? currentPolicyStatus.data.policyPath : undefined;
  const policyTone = !policyProject
    ? "default"
    : currentPolicyStatus.status === "loading"
      ? "loading"
      : currentPolicyStatus.status === "error"
        ? "error"
        : currentPolicyStatus.data.usesProjectPolicy
          ? "project"
          : "default";

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      const isEditing =
        target?.isContentEditable ||
        target?.tagName === "INPUT" ||
        target?.tagName === "TEXTAREA" ||
        target?.tagName === "SELECT";
      if (event.defaultPrevented || !isEditing) return;
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
        event.preventDefault();
        void runMask();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [runMask]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;

    void getCurrentWebview()
      .onDragDropEvent((event) => {
        if (disposed) return;

        if (event.payload.type === "drop") {
          setDragActive(false);
          const path = event.payload.paths[0];
          if (path) applySelectedFile(path);
          return;
        }

        if (event.payload.type === "leave") {
          setDragActive(false);
          return;
        }

        if (inputMode === "file") setDragActive(true);
      })
      .then((stopListening) => {
        if (disposed) {
          stopListening();
        } else {
          unlisten = stopListening;
        }
      })
      .catch(() => {
        // Browser drag events below remain available outside the Tauri runtime.
      });

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [applySelectedFile, inputMode, setDragActive]);

  const reportForSummary =
    maskState.status === "done"
      ? {
          version: 1,
          scanned_paths: [],
          findings,
          summary: {
            total: findings.length,
            by_severity: Object.fromEntries(
              severityOrder.map((level) => [
                level,
                findings.filter((f) => String(f.severity) === level).length,
              ]),
            ),
          },
          exit_threshold: "medium",
          suppressed: 0,
          deduplicated: 0,
          color_mode: "never",
        }
      : null;

  return (
    <div className="shk-scroll shk-fade-in min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-5 px-6 py-6">
        <MaskHeader
          title={m.title}
          subtitle={m.subtitle}
          policyLabel={policyLabel}
          policyPath={policyPath}
          policyTone={policyTone}
          policySelectLabel={m.policySelectLabel}
          policyDefaultOption={m.policyDefaultOption}
          projects={projects}
          selectedPolicyProjectId={policyProjectId}
          policySelectionDisabled={isLoading}
          onPolicyProjectChange={(projectId) => {
            setPolicyProjectId(projectId);
            setFindingFilter("all");
            resetResult();
          }}
          currentStep={currentStep}
          steps={m.steps}
        />

        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] lg:items-stretch">
          <MaskInputPanel
            inputMode={inputMode}
            inputText={inputText}
            selectedFilePath={selectedFilePath}
            dragActive={dragActive}
            isLoading={isLoading}
            hasInput={hasInput}
            fileMeta={fileMeta}
            onSwitchMode={switchInputMode}
            onInputTextChange={(value) => {
              setInputText(value);
              resetResult();
            }}
            onChooseFile={() => void chooseFile()}
            onClear={clearInput}
            onRunMask={() => void runMask()}
            onRemoveFile={removeSelectedFile}
            onDragActive={setDragActive}
            onDropFile={applySelectedFile}
            messages={m}
            t={t}
          />

          <div className="hidden place-items-center lg:grid" aria-hidden="true">
            <div className="grid h-10 w-10 place-items-center rounded-full border border-sky-400/25 bg-sky-500/10 text-sky-200">
              <ArrowRight size={18} />
            </div>
          </div>

          <MaskOutputPanel
            maskedOutput={maskedOutput}
            maskState={maskState}
            isLoading={isLoading}
            canCopy={canCopy}
            actionableFindings={actionableFindings}
            findingsCount={findings.length}
            messages={m}
            t={t}
          />
        </div>

        {canCopy && (
          <MaskTransferPanel
            preferredAiTool={preferredAiTool}
            onPreferredAiToolChange={onPreferredAiToolChange}
            copied={copied}
            saving={saving}
            saveMessage={saveMessage}
            showOfficeSave={fileMeta?.fileKind === "office"}
            onCopy={() => void copyMasked()}
            onCopyAndOpen={() => void copyAndOpenTool()}
            onSave={() => void saveMaskedFile()}
            messages={m}
            t={t}
          />
        )}

        {maskState.status === "error" && (
          <div
            role="alert"
            className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-[13px] text-red-200"
          >
            {m.failed}: {maskState.message}
          </div>
        )}

        {reportForSummary && findings.length > 0 && (
          <section className="grid gap-3">
            <SeveritySummary
              report={reportForSummary}
              filter={findingFilter}
              onFilterChange={setFindingFilter}
            />
            <FindingList findings={findings} filter={findingFilter} />
          </section>
        )}

        {maskState.status === "done" && findings.length === 0 && (
          <section className="overflow-hidden rounded-xl border border-emerald-500/25 bg-emerald-500/5 px-5 py-4">
            <div className="flex items-start gap-3">
              <CheckCircle2
                size={20}
                className="mt-0.5 shrink-0 text-emerald-300"
                aria-hidden="true"
              />
              <div>
                <h2 className="text-sm font-semibold text-white">{m.findingsTitle}</h2>
                <p className="mt-1 text-[12px] leading-relaxed text-emerald-100/85">
                  {m.outputSafe}
                </p>
              </div>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

function MaskHeader({
  title,
  subtitle,
  policyLabel,
  policyPath,
  policyTone,
  policySelectLabel,
  policyDefaultOption,
  projects,
  selectedPolicyProjectId,
  policySelectionDisabled,
  onPolicyProjectChange,
  currentStep,
  steps,
}: {
  title: string;
  subtitle: string;
  policyLabel?: string;
  policyPath?: string;
  policyTone: "default" | "loading" | "error" | "project";
  policySelectLabel: string;
  policyDefaultOption: string;
  projects: Project[];
  selectedPolicyProjectId: string | null;
  policySelectionDisabled: boolean;
  onPolicyProjectChange: (projectId: string | null) => void;
  currentStep: 1 | 2 | 3;
  steps: { input: string; mask: string; transfer: string };
}) {
  const policySelectId = useId();
  const stepItems = [
    { id: 1 as const, label: steps.input },
    { id: 2 as const, label: steps.mask },
    { id: 3 as const, label: steps.transfer },
  ];

  return (
    <header className="grid gap-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold text-white">{title}</h1>
          <p className="mt-1 max-w-2xl text-[13px] leading-relaxed text-muted">{subtitle}</p>
        </div>
        <div className="grid w-full gap-2 self-start rounded-xl border border-border bg-surface-2/70 p-3 sm:w-72">
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
        </div>
      </div>

      <ol className="grid grid-cols-3 gap-2 sm:gap-3" aria-label={title}>
        {stepItems.map((step, index) => {
          const active = currentStep === step.id;
          const done = currentStep > step.id;
          return (
            <li
              key={step.id}
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

function MaskInputPanel({
  inputMode,
  inputText,
  selectedFilePath,
  dragActive,
  isLoading,
  hasInput,
  fileMeta,
  onSwitchMode,
  onInputTextChange,
  onChooseFile,
  onClear,
  onRunMask,
  onRemoveFile,
  onDragActive,
  onDropFile,
  messages: m,
  t,
}: {
  inputMode: MaskInputMode;
  inputText: string;
  selectedFilePath: string | null;
  dragActive: boolean;
  isLoading: boolean;
  hasInput: boolean;
  fileMeta?: { fileKind: string; sourceLabel: string };
  onSwitchMode: (mode: MaskInputMode) => void;
  onInputTextChange: (value: string) => void;
  onChooseFile: () => void;
  onClear: () => void;
  onRunMask: () => void;
  onRemoveFile: () => void;
  onDragActive: (active: boolean) => void;
  onDropFile: (path: string) => void;
  messages: Messages["mask"];
  t: (template: string, vars?: Record<string, string | number>) => string;
}) {
  function handleDragOver(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    onDragActive(true);
  }

  function handleDragLeave() {
    onDragActive(false);
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    onDragActive(false);
    const file = event.dataTransfer.files[0];
    if (!file) return;
    const path = (file as File & { path?: string }).path;
    if (typeof path === "string" && path) {
      onDropFile(path);
    }
  }

  const fileLabel = selectedFilePath ? maskFileBasename(selectedFilePath) : "";
  const selectedFileKind =
    fileMeta?.fileKind ?? (selectedFilePath ? maskFileKind(selectedFilePath) : null);
  const fileKindLabel =
    selectedFileKind === "office"
      ? m.fileKinds.office
      : selectedFileKind === "pdf"
        ? m.fileKinds.pdf
        : selectedFilePath
          ? m.fileKinds.text
          : null;

  return (
    <section className="grid gap-3 rounded-xl border border-border bg-surface-2/70 p-4 ring-1 ring-inset ring-white/5">
      <div className="flex min-h-[52px] flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-white">{m.inputTitle}</h2>
          <p className="mt-1 text-[12px] text-muted">{m.inputHint}</p>
        </div>
        <div
          className="inline-flex rounded-lg border border-border bg-canvas p-0.5"
          role="tablist"
          aria-label={m.inputTitle}
        >
          {(["text", "file"] as const).map((mode) => {
            const active = inputMode === mode;
            return (
              <button
                key={mode}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => onSwitchMode(mode)}
                className={`rounded-md px-3 py-1.5 text-[11px] font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70 ${
                  active
                    ? "bg-sky-500/15 text-sky-100 ring-1 ring-inset ring-sky-400/30"
                    : "text-muted hover:text-text"
                }`}
              >
                {mode === "text" ? m.inputModeText : m.inputModeFile}
              </button>
            );
          })}
        </div>
      </div>

      {inputMode === "text" ? (
        <>
          <textarea
            value={inputText}
            onChange={(event) => onInputTextChange(event.target.value)}
            placeholder={m.inputPlaceholder}
            className="border-border bg-canvas placeholder:text-faint min-h-[300px] w-full resize-y rounded-lg border px-3 py-3 font-mono text-[12px] leading-relaxed text-white outline-none transition focus:border-sky-300/70 focus:ring-2 focus:ring-sky-300/25"
          />
          <p className="text-right text-[11px] text-faint">
            {t(m.charCount, { count: inputText.length })}
          </p>
        </>
      ) : (
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`grid min-h-[300px] place-items-center rounded-xl border border-dashed px-4 py-8 text-center transition ${
            dragActive
              ? "border-sky-400/60 bg-sky-500/10"
              : selectedFilePath
                ? "border-sky-400/30 bg-sky-500/5"
                : "border-border bg-canvas/40 hover:border-sky-400/30 hover:bg-surface-3/40"
          }`}
        >
          {selectedFilePath ? (
            <div className="w-full max-w-md">
              <div className="mx-auto grid h-12 w-12 place-items-center rounded-2xl bg-sky-400/15 text-sky-200 ring-1 ring-inset ring-sky-400/25">
                <FileText size={22} aria-hidden="true" />
              </div>
              <p className="mt-3 text-sm font-semibold text-white">{fileLabel}</p>
              {fileKindLabel && (
                <p className="mt-1 text-[11px] font-medium text-sky-200/90">{fileKindLabel}</p>
              )}
              <p
                className="mt-2 break-all font-mono text-[11px] text-muted"
                title={selectedFilePath}
              >
                {shortenPath(selectedFilePath)}
              </p>
              <div className="mt-4 flex flex-wrap items-center justify-center gap-2">
                <Button variant="secondary" size="sm" onClick={onChooseFile}>
                  {m.selectFile}
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  icon={<X size={14} aria-hidden="true" />}
                  onClick={onRemoveFile}
                >
                  {m.removeFile}
                </Button>
              </div>
            </div>
          ) : (
            <button
              type="button"
              onClick={onChooseFile}
              className="grid w-full max-w-sm gap-3 rounded-xl px-4 py-6 transition hover:bg-surface-3/30 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70"
            >
              <div className="mx-auto grid h-12 w-12 place-items-center rounded-2xl bg-surface-3 text-muted">
                <FileUp size={22} aria-hidden="true" />
              </div>
              <span className="text-sm font-medium text-white">
                {dragActive ? m.dropActive : m.dropHint}
              </span>
              <span className="text-[11px] text-muted">{m.selectFile}</span>
            </button>
          )}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-border/80 pt-3">
        <Button
          variant="primary"
          onClick={onRunMask}
          loading={isLoading}
          disabled={isLoading || !hasInput}
          icon={<Eraser size={14} aria-hidden="true" />}
        >
          {isLoading ? m.masking : m.runMask}
        </Button>
        <Button variant="secondary" onClick={onClear} disabled={!hasInput && !inputText}>
          {m.clearInput}
        </Button>
        {inputMode === "file" && (
          <button
            type="button"
            onClick={() => onSwitchMode("text")}
            className="text-[11px] font-medium text-sky-200 transition hover:text-white"
          >
            {m.useTextInstead}
          </button>
        )}
      </div>
    </section>
  );
}

function MaskOutputPanel({
  maskedOutput,
  maskState,
  isLoading,
  canCopy,
  actionableFindings,
  findingsCount,
  messages: m,
  t,
}: {
  maskedOutput: string;
  maskState: MaskState;
  isLoading: boolean;
  canCopy: boolean;
  actionableFindings: number;
  findingsCount: number;
  messages: Messages["mask"];
  t: (template: string, vars?: Record<string, string | number>) => string;
}) {
  const statusTone =
    maskState.status === "done"
      ? actionableFindings > 0
        ? "amber"
        : "emerald"
      : isLoading
        ? "sky"
        : "neutral";

  return (
    <section
      className={`grid gap-3 rounded-xl border p-4 ring-1 ring-inset ${
        statusTone === "emerald"
          ? "border-emerald-400/45 bg-emerald-500/12 shadow-[0_16px_50px_rgba(16,185,129,0.12)] ring-emerald-400/20"
          : statusTone === "amber"
            ? "border-amber-400/45 bg-amber-500/12 shadow-[0_16px_50px_rgba(245,158,11,0.12)] ring-amber-400/20"
            : statusTone === "sky"
              ? "border-sky-400/30 bg-sky-500/5 ring-sky-400/15"
              : "border-border bg-surface-2/70 ring-white/5"
      }`}
    >
      <div className="flex min-h-[52px] items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-white">{m.outputTitle}</h2>
          <p className="mt-1 text-[12px] text-muted">
            {canCopy
              ? actionableFindings > 0
                ? t(m.outputNeedsReview, { count: actionableFindings })
                : m.outputSafe
              : m.outputHint}
          </p>
        </div>
      </div>

      {isLoading ? (
        <div className="grid min-h-[300px] place-items-center gap-3 rounded-lg border border-dashed border-sky-400/25 bg-canvas/50 px-6 py-10 text-center">
          <Loader2 size={28} className="animate-spin text-sky-200" aria-hidden="true" />
          <p className="text-sm text-sky-100">{m.masking}</p>
          <div className="h-1.5 w-full max-w-xs overflow-hidden rounded-full bg-sky-950/70">
            <div className="shk-indeterminate-progress h-full w-1/2 rounded-full bg-sky-400" />
          </div>
        </div>
      ) : canCopy ? (
        <textarea
          readOnly
          value={maskedOutput}
          className={`bg-canvas min-h-[300px] w-full resize-y rounded-lg border px-3 py-3 font-mono text-[12px] leading-relaxed text-white outline-none ${
            actionableFindings > 0
              ? "border-amber-400/35 ring-1 ring-inset ring-amber-400/10"
              : "border-emerald-400/35 ring-1 ring-inset ring-emerald-400/10"
          }`}
        />
      ) : (
        <div className="grid min-h-[300px] place-items-center gap-3 rounded-lg border border-dashed border-border bg-canvas/40 px-6 py-10 text-center">
          {maskState.status === "idle" ? (
            <>
              <Eraser size={28} className="text-muted" aria-hidden="true" />
              <p className="max-w-xs text-[13px] leading-relaxed text-muted">
                {m.outputPlaceholder}
              </p>
            </>
          ) : (
            <>
              <TriangleAlert size={28} className="text-amber-300" aria-hidden="true" />
              <p className="max-w-xs text-[13px] leading-relaxed text-muted">
                {m.outputPlaceholder}
              </p>
            </>
          )}
        </div>
      )}

      {canCopy && (
        <p className="text-[11px] text-muted">{t(m.findingsCount, { count: findingsCount })}</p>
      )}
    </section>
  );
}

function MaskTransferPanel({
  preferredAiTool,
  onPreferredAiToolChange,
  copied,
  saving,
  saveMessage,
  showOfficeSave,
  onCopy,
  onCopyAndOpen,
  onSave,
  messages: m,
  t,
}: {
  preferredAiTool: PreferredAiTool;
  onPreferredAiToolChange: (tool: PreferredAiTool) => void;
  copied: boolean;
  saving: boolean;
  saveMessage: string | null;
  showOfficeSave?: boolean;
  onCopy: () => void;
  onCopyAndOpen: () => void;
  onSave: () => void;
  messages: Messages["mask"];
  t: (template: string, vars?: Record<string, string | number>) => string;
}) {
  return (
    <section className="overflow-hidden rounded-xl border border-sky-400/30 bg-sky-500/8 p-4 ring-1 ring-inset ring-sky-400/20">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-white">{m.transferTitle}</h2>
          <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-muted">{m.transferHint}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <label className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-canvas px-2.5 py-1.5 text-[11px] font-medium text-text">
            <span className="text-muted">{m.preferredTool}</span>
            <select
              value={preferredAiTool}
              onChange={(event) => onPreferredAiToolChange(event.target.value as PreferredAiTool)}
              className="bg-transparent text-white outline-none"
            >
              {AI_TOOL_OPTIONS.map((tool) => (
                <option key={tool} value={tool}>
                  {m.toolNames[tool]}
                </option>
              ))}
            </select>
          </label>

          <Button
            variant="primary"
            icon={<ExternalLink size={14} aria-hidden="true" />}
            onClick={onCopyAndOpen}
          >
            {t(m.copyAndOpen, { tool: m.toolNames[preferredAiTool] })}
          </Button>

          <Button
            variant="secondary"
            size="sm"
            icon={
              copied ? (
                <Check size={14} aria-hidden="true" />
              ) : (
                <Copy size={14} aria-hidden="true" />
              )
            }
            onClick={onCopy}
          >
            {copied ? m.copied : m.copyMasked}
          </Button>

          {showOfficeSave && (
            <Button
              variant="secondary"
              size="sm"
              icon={<Save size={14} aria-hidden="true" />}
              onClick={onSave}
              loading={saving}
              disabled={saving}
            >
              {saving ? m.saving : m.saveMaskedFile}
            </Button>
          )}
        </div>
      </div>

      {saveMessage && <p className="mt-3 text-[11px] text-sky-100/85">{saveMessage}</p>}
    </section>
  );
}
