import { ArrowRight, Eraser, KeyRound } from "lucide-react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { openAiTool, type PreferredAiTool } from "../aiTool";
import { useI18n } from "../i18n";
import { operationErrorMessage } from "../i18n/interpolate";
import { useMaskInput, type MaskInputChange } from "../hooks/useMaskInput";
import { useMaskPolicyStatus } from "../hooks/useMaskPolicyStatus";
import { MASK_FILE_EXTENSIONS, useMaskWorkspace } from "../hooks/useMaskWorkspace";
import { usePseudonymizeWorkspace, type PastedKind } from "../hooks/usePseudonymizeWorkspace";
import { PSEUDONYMIZE_FILE_EXTENSIONS, isPseudonymizableFile, isTableFile } from "../pseudonymize";
import type { Project } from "../types";
import { MaskHeader, type MaskStep } from "./mask/MaskHeader";
import { MaskInputPanel } from "./mask/MaskInputPanel";
import type { MaskMode } from "./mask/MaskModeToggle";
import { MaskOutputPanel } from "./mask/MaskOutputPanel";
import { PseudonymizeSection } from "./mask/PseudonymizeSection";
import { RedactResultsSection } from "./mask/RedactResultsSection";

type Props = {
  projects: Project[];
  initialPolicyProjectId: string | null;
  preferredAiTool: PreferredAiTool;
  onPreferredAiToolChange: (tool: PreferredAiTool) => void;
  onNotice?: (message: string) => void;
};

const PASTED_KINDS: PastedKind[] = ["text", "csv", "tsv"];

export function MaskWorkspace({
  projects,
  initialPolicyProjectId,
  preferredAiTool,
  onPreferredAiToolChange,
  onNotice,
}: Props) {
  const { messages, t } = useI18n();
  const m = messages.mask;
  const mp = m.pseudonymize;
  const gateId = useId();
  const pastedKindId = useId();

  const [mode, setMode] = useState<MaskMode>("redact");
  const [policyProjectId, setPolicyProjectId] = useState<string | null>(() =>
    projects.some((project) => project.id === initialPolicyProjectId)
      ? initialPolicyProjectId
      : null,
  );
  const policyProject = projects.find((project) => project.id === policyProjectId);
  const projectPath = policyProject?.path ?? null;
  const policy = useMaskPolicyStatus(policyProject);
  const isPseudonymize = mode === "pseudonymize";
  const pseudonymizeReady = Boolean(policyProject) && policy.usesProjectPolicy;

  // Results of both modes are dropped whenever the input changes, so
  // switching back never shows stale output for new content. The ref is
  // written after render so the input hook can keep stable callbacks.
  const resetRef = useRef<(change: MaskInputChange) => void>(() => {});
  const input = useMaskInput({
    extensions: isPseudonymize ? PSEUDONYMIZE_FILE_EXTENSIONS : MASK_FILE_EXTENSIONS,
    enforceExtensions: isPseudonymize,
    unsupportedMessage: mp.unsupportedFile,
    onInputChange: (change) => resetRef.current(change),
    onNotice,
  });
  const redact = useMaskWorkspace({
    projectPath,
    input,
    preferredAiTool,
    onPreferredAiToolChange,
    onNotice,
  });
  const pseudonymize = usePseudonymizeWorkspace({
    projectPath,
    active: isPseudonymize && pseudonymizeReady,
    input,
    onNotice,
  });
  const { resetResult: resetRedact, runMask } = redact;
  const {
    resetResult: resetPseudonymizeResult,
    reset: resetPseudonymize,
    canRun: canRunPseudonymize,
    run: runPseudonymize,
    copyInlineOutput,
  } = pseudonymize;
  // Edits keep the plan and column choices; only results are dropped.
  const resetResults = useCallback(() => {
    resetRedact();
    resetPseudonymizeResult();
  }, [resetPseudonymizeResult, resetRedact]);
  // A different mode or project starts the pseudonymize flow from scratch.
  const resetAll = useCallback(() => {
    resetRedact();
    resetPseudonymize();
  }, [resetPseudonymize, resetRedact]);
  useLayoutEffect(() => {
    // Editing the same content keeps its plan; replacing it starts over.
    resetRef.current = (change) => (change === "edit" ? resetResults() : resetAll());
  });

  const {
    inputMode,
    inputText,
    selectedFilePath,
    dragActive,
    setDragActive,
    hasInput,
    removeSelectedFile,
    clearInput,
  } = input;

  // "Start over" returns to step 1: no content, no plan, no result.
  const startOver = useCallback(() => {
    resetAll();
    clearInput();
  }, [clearInput, resetAll]);

  useEffect(() => {
    if (policyProjectId && !policyProject) {
      setPolicyProjectId(null);
      resetAll();
    }
  }, [policyProject, policyProjectId, resetAll]);

  const changeMode = useCallback(
    (next: MaskMode) => {
      if (next === mode) return;
      setMode(next);
      resetAll();
      if (next === "pseudonymize" && selectedFilePath && !isPseudonymizableFile(selectedFilePath)) {
        removeSelectedFile();
        onNotice?.(mp.unsupportedFile);
      }
    },
    [mode, mp.unsupportedFile, onNotice, removeSelectedFile, resetAll, selectedFilePath],
  );

  const runActive = useCallback(() => {
    if (isPseudonymize) {
      if (canRunPseudonymize) void runPseudonymize();
    } else {
      void runMask();
    }
  }, [canRunPseudonymize, isPseudonymize, runMask, runPseudonymize]);

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
        runActive();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [runActive]);

  const { applySelectedFile } = input;
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

  const copyAndOpenInline = useCallback(async () => {
    if (!(await copyInlineOutput())) return;
    onPreferredAiToolChange(preferredAiTool);
    try {
      await openAiTool(preferredAiTool);
    } catch (error) {
      onNotice?.(operationErrorMessage(messages.app.operationFailed, error));
    }
  }, [
    copyInlineOutput,
    messages.app.operationFailed,
    onNotice,
    onPreferredAiToolChange,
    preferredAiTool,
  ]);

  const gate =
    !isPseudonymize || pseudonymizeReady || policy.status === "loading"
      ? null
      : !policyProject
        ? { title: mp.requiresProjectTitle, body: mp.requiresProject }
        : policy.status === "error"
          ? {
              title: mp.requiresProjectTitle,
              body: t(mp.requiresPolicyError, {
                project: policyProject.name,
                message: policy.errorMessage ?? "",
              }),
            }
          : {
              title: mp.requiresProjectTitle,
              body: t(mp.requiresPolicy, { project: policyProject.name }),
            };

  const redactSteps: MaskStep[] = [
    { id: 1, label: m.steps.input },
    { id: 2, label: m.steps.mask },
    { id: 3, label: m.steps.transfer },
  ];
  const pseudonymizeSteps: MaskStep[] = [
    { id: 1, label: mp.steps.input },
    { id: 2, label: mp.steps.columns },
    { id: 3, label: mp.steps.run },
    { id: 4, label: mp.steps.save },
  ];
  const pseudonymizeStep =
    pseudonymize.phase.status === "done"
      ? 4
      : pseudonymize.phase.status === "running"
        ? 3
        : hasInput
          ? pseudonymize.isTableInput
            ? 2
            : 3
          : 1;

  const isLoading = isPseudonymize ? pseudonymize.isRunning : redact.isLoading;
  const pseudonymizeFileKind = !selectedFilePath
    ? undefined
    : isTableFile(selectedFilePath)
      ? mp.fileKindTable
      : /\.(docx|pptx)$/i.test(selectedFilePath)
        ? m.fileKinds.office
        : m.fileKinds.text;

  return (
    <div className="shk-scroll shk-fade-in min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-5 px-6 py-6">
        <MaskHeader
          title={m.title}
          subtitle={isPseudonymize ? mp.subtitle : m.subtitle}
          mode={mode}
          onModeChange={changeMode}
          modeDisabled={isLoading || pseudonymize.preparing}
          policyLabel={policy.policyLabel}
          policyPath={policy.policyPath}
          policyTone={policy.policyTone}
          policySelectLabel={m.policySelectLabel}
          policyDefaultOption={isPseudonymize ? mp.policySelectRequired : m.policyDefaultOption}
          projects={projects}
          selectedPolicyProjectId={policyProjectId}
          policySelectionDisabled={isLoading || pseudonymize.preparing}
          onPolicyProjectChange={(projectId) => {
            setPolicyProjectId(projectId);
            resetAll();
          }}
          gate={gate}
          gateId={gateId}
          currentStep={isPseudonymize ? pseudonymizeStep : redact.currentStep}
          steps={isPseudonymize ? pseudonymizeSteps : redactSteps}
          messages={m}
        />

        {isPseudonymize ? (
          <>
            <MaskInputPanel
              inputMode={inputMode}
              inputText={inputText}
              selectedFilePath={selectedFilePath}
              dragActive={dragActive}
              isLoading={pseudonymize.isRunning}
              inputLocked={pseudonymize.isRunning || pseudonymize.preparing}
              hasInput={hasInput}
              fileKindLabel={pseudonymizeFileKind}
              inputHint={mp.inputHint}
              inputPlaceholder={mp.inputPlaceholder}
              runLabel={inputMode === "file" ? mp.run : mp.runText}
              runningLabel={mp.running}
              runIcon={<KeyRound size={14} aria-hidden="true" />}
              runDisabled={!pseudonymize.canRun}
              runDisabledReasonId={gate ? gateId : undefined}
              textControls={
                <label
                  htmlFor={pastedKindId}
                  className="inline-flex items-center gap-2 text-[11px] text-muted"
                >
                  <span>{mp.pastedKindLabel}</span>
                  <select
                    id={pastedKindId}
                    value={pseudonymize.pastedKind}
                    onChange={(event) =>
                      pseudonymize.changePastedKind(event.target.value as PastedKind)
                    }
                    className="rounded-md border border-border-strong bg-canvas/70 px-2 py-1 text-[11px] font-medium text-white outline-none transition focus:border-sky-300/70 focus:ring-2 focus:ring-sky-300/20"
                  >
                    {PASTED_KINDS.map((kind) => (
                      <option key={kind} value={kind}>
                        {mp.pastedKinds[kind]}
                      </option>
                    ))}
                  </select>
                </label>
              }
              onSwitchMode={input.switchInputMode}
              onInputTextChange={input.setInputText}
              onChooseFile={() => void input.chooseFile()}
              onClear={input.clearInput}
              onRun={() => void runPseudonymize()}
              onRemoveFile={input.removeSelectedFile}
              onDragActive={setDragActive}
              onDropFile={(path) => void applySelectedFile(path)}
              messages={m}
              t={t}
            />
            <PseudonymizeSection
              workspace={pseudonymize}
              projectName={policyProject?.name ?? null}
              selectedFilePath={selectedFilePath}
              hasInput={hasInput && pseudonymizeReady}
              preferredAiTool={preferredAiTool}
              onPreferredAiToolChange={onPreferredAiToolChange}
              onCopyAndOpen={() => void copyAndOpenInline()}
              onStartOver={startOver}
              maskMessages={m}
            />
          </>
        ) : (
          <>
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] lg:items-stretch">
              <MaskInputPanel
                inputMode={inputMode}
                inputText={inputText}
                selectedFilePath={selectedFilePath}
                dragActive={dragActive}
                isLoading={redact.isLoading}
                hasInput={hasInput}
                fileMeta={redact.fileMeta}
                inputHint={m.inputHint}
                inputPlaceholder={m.inputPlaceholder}
                runLabel={m.runMask}
                runningLabel={m.masking}
                runIcon={<Eraser size={14} aria-hidden="true" />}
                runDisabled={false}
                onSwitchMode={input.switchInputMode}
                onInputTextChange={input.setInputText}
                onChooseFile={() => void input.chooseFile()}
                onClear={input.clearInput}
                onRun={() => void runMask()}
                onRemoveFile={input.removeSelectedFile}
                onDragActive={setDragActive}
                onDropFile={(path) => void applySelectedFile(path)}
                messages={m}
                t={t}
              />

              <div className="hidden place-items-center lg:grid" aria-hidden="true">
                <div className="grid h-10 w-10 place-items-center rounded-full border border-sky-400/25 bg-sky-500/10 text-sky-200">
                  <ArrowRight size={18} />
                </div>
              </div>

              <MaskOutputPanel
                maskedOutput={redact.maskedOutput}
                maskState={redact.maskState}
                isLoading={redact.isLoading}
                canCopy={redact.canCopy}
                copied={redact.copied}
                actionableFindings={redact.actionableFindings}
                findingsCount={redact.findings.length}
                onCopy={() => void redact.copyMasked()}
                messages={m}
                t={t}
              />
            </div>

            <RedactResultsSection
              key={policyProjectId ?? "default"}
              maskState={redact.maskState}
              findings={redact.findings}
              fileMeta={redact.fileMeta}
              canCopy={redact.canCopy}
              saving={redact.saving}
              saveMessage={redact.saveMessage}
              preferredAiTool={preferredAiTool}
              onPreferredAiToolChange={onPreferredAiToolChange}
              onCopyAndOpen={() => void redact.copyAndOpenTool()}
              onSave={() => void redact.saveMaskedFile()}
              messages={m}
              t={t}
            />
          </>
        )}
      </div>
    </div>
  );
}
