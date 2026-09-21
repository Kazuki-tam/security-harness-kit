import { FileText, FileUp, X } from "lucide-react";
import type { DragEvent, ReactNode } from "react";
import type { MaskInputMode } from "../../hooks/useMaskInput";
import type { Messages } from "../../i18n/types";
import { maskFileBasename, maskFileKind } from "../../mask";
import { shortenPath } from "../../utils";
import { Button } from "../Button";

type Props = {
  inputMode: MaskInputMode;
  inputText: string;
  selectedFilePath: string | null;
  dragActive: boolean;
  isLoading: boolean;
  hasInput: boolean;
  fileMeta?: { fileKind: string; sourceLabel: string };
  inputHint: string;
  inputPlaceholder: string;
  runLabel: string;
  runningLabel: string;
  runIcon: ReactNode;
  runDisabled: boolean;
  /** Element id describing why the run button is disabled (for `aria-describedby`). */
  runDisabledReasonId?: string;
  /** Extra controls under the text area, such as the pasted-content kind. */
  textControls?: ReactNode;
  onSwitchMode: (mode: MaskInputMode) => void;
  onInputTextChange: (value: string) => void;
  onChooseFile: () => void;
  onClear: () => void;
  onRun: () => void;
  onRemoveFile: () => void;
  onDragActive: (active: boolean) => void;
  onDropFile: (path: string) => void;
  messages: Messages["mask"];
  t: (template: string, vars?: Record<string, string | number>) => string;
};

export function MaskInputPanel({
  inputMode,
  inputText,
  selectedFilePath,
  dragActive,
  isLoading,
  hasInput,
  fileMeta,
  inputHint,
  inputPlaceholder,
  runLabel,
  runningLabel,
  runIcon,
  runDisabled,
  runDisabledReasonId,
  textControls,
  onSwitchMode,
  onInputTextChange,
  onChooseFile,
  onClear,
  onRun,
  onRemoveFile,
  onDragActive,
  onDropFile,
  messages: m,
  t,
}: Props) {
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
          <p className="mt-1 text-[12px] text-muted">{inputHint}</p>
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
            placeholder={inputPlaceholder}
            className="border-border bg-canvas placeholder:text-faint min-h-[300px] w-full resize-y rounded-lg border px-3 py-3 font-mono text-[12px] leading-relaxed text-white outline-none transition focus:border-sky-300/70 focus:ring-2 focus:ring-sky-300/25"
          />
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>{textControls}</div>
            <p className="text-right text-[11px] text-faint">
              {t(m.charCount, { count: inputText.length })}
            </p>
          </div>
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
          onClick={onRun}
          loading={isLoading}
          disabled={isLoading || !hasInput || runDisabled}
          aria-describedby={runDisabled ? runDisabledReasonId : undefined}
          icon={runIcon}
        >
          {isLoading ? runningLabel : runLabel}
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
