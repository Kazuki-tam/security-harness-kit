import { Check, Copy, Info } from "lucide-react";
import type { PreferredAiTool } from "../../aiTool";
import type { PseudonymizeWorkspaceApi } from "../../hooks/usePseudonymizeWorkspace";
import type { Messages } from "../../i18n/types";
import { restoreMapSuggestedPath, pseudonymizeSuggestedOutputPath } from "../../pseudonymize";
import { basenameOf } from "../../utils";
import { Button } from "../Button";
import { CollapsibleSection } from "../CollapsibleSection";
import { ConfirmDialog } from "../ConfirmDialog";
import { MaskTransferPanel } from "./MaskTransferPanel";
import { PseudonymizeAdvancedOptions } from "./PseudonymizeAdvancedOptions";
import { PseudonymizeColumnPanel } from "./PseudonymizeColumnPanel";
import { PseudonymizeSummary } from "./PseudonymizeSummary";

type Props = {
  workspace: PseudonymizeWorkspaceApi;
  projectName: string | null;
  selectedFilePath: string | null;
  hasInput: boolean;
  preferredAiTool: PreferredAiTool;
  onPreferredAiToolChange: (tool: PreferredAiTool) => void;
  onCopyAndOpen: () => void;
  maskMessages: Messages["mask"];
};

/** Column choices, options, confirmation, and results for pseudonymize mode. */
export function PseudonymizeSection({
  workspace,
  projectName,
  selectedFilePath,
  hasInput,
  preferredAiTool,
  onPreferredAiToolChange,
  onCopyAndOpen,
  maskMessages,
}: Props) {
  const {
    messages: m,
    t,
    phase,
    inspect,
    columns,
    dispatchColumns,
    columnErrors,
    sheet,
    changeSheet,
    noHeader,
    changeNoHeader,
    restoreMap,
    setRestoreMap,
    advancedOpen,
    setAdvancedOpen,
    keyDialog,
    resolveKeyDialog,
    isTableInput,
    isFileInput,
    isRunning,
    isInspecting,
    inlineOutput,
    copied,
    copiedPath,
    reset,
    copyInlineOutput,
    copyPath,
  } = workspace;

  const busy = isRunning || isInspecting;
  const showColumns = hasInput && isTableInput && inspect?.table;
  const showTextCard = hasInput && !isTableInput && phase.status !== "done";
  const restoreMapName = selectedFilePath
    ? basenameOf(restoreMapSuggestedPath(pseudonymizeSuggestedOutputPath(selectedFilePath)))
    : null;
  const liveStatus =
    phase.status === "inspecting"
      ? m.inspecting
      : phase.status === "ready" && inspect?.table
        ? t(m.columnsLoaded, { count: inspect.table.headers.length, rows: inspect.table.rowCount })
        : phase.status === "running"
          ? m.running
          : phase.status === "done"
            ? m.statusDone
            : "";

  return (
    <>
      <p role="status" aria-live="polite" className="sr-only">
        {liveStatus}
      </p>

      {showColumns && inspect && (
        <PseudonymizeColumnPanel
          inspect={inspect}
          columns={columns}
          dispatch={dispatchColumns}
          columnErrors={columnErrors}
          sheet={sheet}
          onSheetChange={changeSheet}
          disabled={busy}
          inspecting={isInspecting}
          messages={m}
          t={t}
        />
      )}

      {showTextCard && (
        <section className="flex items-start gap-3 rounded-xl border border-border bg-surface-2/50 px-4 py-3">
          <Info size={16} className="mt-0.5 shrink-0 text-sky-200" aria-hidden="true" />
          <div>
            <h2 className="text-[13px] font-semibold text-white">{m.textModeTitle}</h2>
            <p className="mt-1 text-[12px] leading-relaxed text-muted">{m.textModeHint}</p>
            {inspect?.inputKind === "text-office" && (
              <p className="mt-1 text-[12px] leading-relaxed text-muted">{m.textModeOfficeHint}</p>
            )}
          </div>
        </section>
      )}

      {hasInput && phase.status !== "done" && (
        <CollapsibleSection
          title={m.advancedTitle}
          description={m.advancedHint}
          open={advancedOpen}
          onToggle={() => setAdvancedOpen(!advancedOpen)}
        >
          <PseudonymizeAdvancedOptions
            restoreMap={restoreMap}
            onRestoreMapChange={setRestoreMap}
            noHeader={noHeader}
            onNoHeaderChange={changeNoHeader}
            isFileInput={isFileInput}
            isTableInput={isTableInput}
            restoreMapName={restoreMapName}
            disabled={busy}
            messages={m}
            t={t}
          />
        </CollapsibleSection>
      )}

      {phase.status === "error" && (
        <div
          role="alert"
          className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-[13px] text-red-200"
        >
          {m.failed}: {phase.message}
        </div>
      )}

      {phase.status === "done" && (
        <>
          {inlineOutput && (
            <section className="grid gap-3 rounded-xl border border-emerald-400/45 bg-emerald-500/12 p-4 ring-1 ring-inset ring-emerald-400/20">
              <div>
                <h2 className="text-sm font-semibold text-white">{m.outputTitle}</h2>
                <p className="mt-1 text-[12px] text-muted">{m.outputHint}</p>
              </div>
              <textarea
                readOnly
                aria-label={m.outputTitle}
                value={inlineOutput}
                className="bg-canvas min-h-[240px] w-full resize-y rounded-lg border border-emerald-400/35 px-3 py-3 font-mono text-[12px] leading-relaxed text-white outline-none ring-1 ring-inset ring-emerald-400/10"
              />
              <div className="flex flex-wrap items-center justify-end gap-3 border-t border-border/70 pt-3">
                <Button
                  variant="secondary"
                  icon={
                    copied ? (
                      <Check size={14} aria-hidden="true" />
                    ) : (
                      <Copy size={14} aria-hidden="true" />
                    )
                  }
                  onClick={() => void copyInlineOutput()}
                >
                  {copied ? maskMessages.copied : maskMessages.copyMasked}
                </Button>
                <span aria-live="polite" className="sr-only">
                  {copied ? maskMessages.copied : ""}
                </span>
              </div>
            </section>
          )}
          {inlineOutput && (
            <MaskTransferPanel
              preferredAiTool={preferredAiTool}
              onPreferredAiToolChange={onPreferredAiToolChange}
              onCopyAndOpen={onCopyAndOpen}
              messages={maskMessages}
              t={t}
            />
          )}
          <PseudonymizeSummary
            result={phase.result}
            copiedPath={copiedPath}
            onCopyPath={(path) => void copyPath(path)}
            onStartOver={reset}
            messages={m}
            t={t}
          />
        </>
      )}

      <ConfirmDialog
        open={keyDialog.open}
        title={t(m.keyDialogTitle, { project: projectName ?? "" })}
        description={t(m.keyDialogBody, { backend: keyDialog.backend })}
        confirmLabel={m.keyDialogConfirm}
        onConfirm={() => resolveKeyDialog(true)}
        onCancel={() => resolveKeyDialog(false)}
      />
    </>
  );
}
