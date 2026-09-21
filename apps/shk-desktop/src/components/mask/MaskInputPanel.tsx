import { FileText, FileUp, X } from "lucide-react";
import { useId, useRef, useEffect, type DragEvent, type ReactNode } from "react";
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
  /** Freeze the content controls while a run that depends on them is in flight. */
  inputLocked?: boolean;
  hasInput: boolean;
  fileMeta?: { fileKind: string; sourceLabel: string };
  /** Overrides the label derived from the file kind (pseudonymize names tables). */
  fileKindLabel?: string;
  inputHint: string;
  inputPlaceholder: string;
  runLabel: string;
  runningLabel: string;
  runIcon: ReactNode;
  runDisabled: boolean;
  showRun?: boolean;
  /** Element id describing why the run button is disabled (for `aria-describedby`). */
  runDisabledReasonId?: string;
  /** Extra controls under the text area, such as the pasted-content kind. */
  textControls?: ReactNode;
  inputFeedback?: ReactNode;
  onSwitchMode: (mode: MaskInputMode) => void;
  onInputTextChange: (value: string, pasted?: boolean) => void;
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
  inputLocked = false,
  hasInput,
  fileMeta,
  fileKindLabel: fileKindLabelOverride,
  inputHint,
  inputPlaceholder,
  runLabel,
  runningLabel,
  runIcon,
  runDisabled,
  showRun = true,
  runDisabledReasonId,
  textControls,
  inputFeedback,
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
  const inputId = useId();
  const hintId = useId();

  // Some webviews omit inputType on a real paste. Scope the fallback to
  // this event turn so a cancelled/empty paste cannot mark later typing.
  const pastePending = useRef(false);
  const pasteTimer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(pasteTimer.current), []);

  function handleDragOver(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    if (!inputLocked) onDragActive(true);
  }

  function handleDragLeave() {
    onDragActive(false);
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    onDragActive(false);
    if (inputLocked) return;
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
    fileKindLabelOverride ??
    (selectedFileKind === "office"
      ? m.fileKinds.office
      : selectedFileKind === "pdf"
        ? m.fileKinds.pdf
        : selectedFilePath
          ? m.fileKinds.text
          : null);

  return (
    <section className="grid gap-3 rounded-xl border border-border bg-surface-2/70 p-4 ring-1 ring-inset ring-white/5">
      <div className="flex min-h-[52px] flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id={inputId} className="text-sm font-semibold text-white">
            {m.inputTitle}
          </h2>
          <p id={hintId} className="mt-1 text-[12px] text-muted">
            {inputHint}
          </p>
        </div>
        <div
          className="inline-flex rounded-lg border border-border bg-canvas p-0.5"
          role="group"
          aria-label={m.inputTitle}
        >
          {(["text", "file"] as const).map((mode) => {
            const active = inputMode === mode;
            return (
              <button
                key={mode}
                type="button"
                aria-pressed={active}
                disabled={inputLocked}
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

      {inputFeedback}

      <div className="flex flex-wrap items-center gap-2 border-b border-border/80 pb-3">
        {showRun && (
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
        )}
        <Button
          variant="secondary"
          onClick={onClear}
          disabled={inputLocked || (!hasInput && !inputText)}
        >
          {m.clearInput}
        </Button>
        {inputMode === "file" && (
          <button
            type="button"
            disabled={inputLocked}
            onClick={() => onSwitchMode("text")}
            className="text-[11px] font-medium text-sky-200 transition hover:text-white disabled:opacity-60"
          >
            {m.useTextInstead}
          </button>
        )}
      </div>

      {inputMode === "text" ? (
        <>
          <textarea
            onPaste={(event) => {
              pastePending.current = Boolean(event.clipboardData?.getData("text/plain"));
              window.clearTimeout(pasteTimer.current);
              pasteTimer.current = window.setTimeout(() => {
                pastePending.current = false;
              }, 0);
            }}
            onBlur={() => {
              pastePending.current = false;
            }}
            aria-labelledby={inputId}
            aria-describedby={hintId}
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
            value={inputText}
            disabled={inputLocked}
            onChange={(event) => {
              const pasted =
                pastePending.current ||
                (event.nativeEvent as InputEvent).inputType === "insertFromPaste";
              pastePending.current = false;
              window.clearTimeout(pasteTimer.current);
              onInputTextChange(event.target.value, pasted);
            }}
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
                <Button variant="secondary" size="sm" disabled={inputLocked} onClick={onChooseFile}>
                  {m.selectFile}
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  icon={<X size={14} aria-hidden="true" />}
                  disabled={inputLocked}
                  onClick={onRemoveFile}
                >
                  {m.removeFile}
                </Button>
              </div>
            </div>
          ) : (
            <button
              type="button"
              disabled={inputLocked}
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
    </section>
  );
}
