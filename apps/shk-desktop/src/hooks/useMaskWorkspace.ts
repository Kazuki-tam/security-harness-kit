import { save } from "@tauri-apps/plugin-dialog";
import { useCallback, useLayoutEffect, useMemo, useRef, useState } from "react";
import { openAiTool, type PreferredAiTool } from "../aiTool";
import { useI18n } from "../i18n";
import { operationErrorMessage } from "../i18n/interpolate";
import {
  findingsBySeverity,
  maskContent,
  maskFile,
  maskOfficeSuggestedName,
  type MaskFileMeta,
  type MaskState,
} from "../mask";
import { actionableCount } from "../scan";
import type { MaskInputApi } from "./useMaskInput";

export type { MaskInputMode } from "./useMaskInput";

export const MASK_FILE_EXTENSIONS = [
  "txt",
  "md",
  "json",
  "yaml",
  "yml",
  "csv",
  "tsv",
  "log",
  "docx",
  "xlsx",
  "pptx",
  "pdf",
] as const;

type UseMaskWorkspaceOptions = {
  projectPath: string | null;
  input: MaskInputApi;
  preferredAiTool: PreferredAiTool;
  onPreferredAiToolChange: (tool: PreferredAiTool) => void;
  onNotice?: (message: string) => void;
};

/** The redaction path: `[REDACTED]` replacement with findings to review. */
export function useMaskWorkspace({
  projectPath,
  input,
  preferredAiTool,
  onPreferredAiToolChange,
  onNotice,
}: UseMaskWorkspaceOptions) {
  const { messages, t } = useI18n();
  const m = messages.mask;
  const { inputMode, inputText, selectedFilePath, hasInput } = input;

  // Invalidate work before accepting new input; backend operations cannot be
  // cancelled, but their results must never replace a newer workspace.
  const generation = useRef(0);
  const running = useRef(false);
  const savingRef = useRef(false);
  const [maskState, setMaskState] = useState<MaskState>({ status: "idle" });
  const [copied, setCopied] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  const maskedOutput = maskState.status === "done" ? maskState.result.masked_content : "";
  const findings = maskState.status === "done" ? maskState.result.findings : [];
  const severityCounts = useMemo(() => findingsBySeverity(findings), [findings]);
  const fileMeta = maskState.status === "done" ? maskState.fileMeta : undefined;
  const actionableFindings = actionableCount(severityCounts);
  const isLoading = maskState.status === "loading";
  const canCopy = maskedOutput.length > 0 && maskState.status === "done";
  const currentStep: 1 | 2 | 3 = maskState.status === "done" ? 3 : hasInput ? 2 : 1;

  const resetResult = useCallback(() => {
    generation.current += 1;
    running.current = false;
    savingRef.current = false;
    setSaving(false);
    setMaskState({ status: "idle" });
    setCopied(false);
    setSaveMessage(null);
  }, []);

  useLayoutEffect(() => {
    resetResult();
    return () => {
      generation.current += 1;
      running.current = false;
      savingRef.current = false;
    };
  }, [projectPath, resetResult]);

  const runMask = useCallback(async () => {
    if (running.current || savingRef.current) return;
    if (inputMode === "text" && !inputText.trim()) {
      setMaskState({ status: "error", message: m.emptyInput });
      return;
    }
    if (inputMode === "file" && !selectedFilePath) {
      setMaskState({ status: "error", message: m.emptyInput });
      return;
    }

    const requestId = ++generation.current;
    const isCurrent = () => generation.current === requestId;
    running.current = true;
    setMaskState({ status: "loading" });
    setCopied(false);
    setSaveMessage(null);

    try {
      if (inputMode === "file" && selectedFilePath) {
        const result = await maskFile(projectPath, selectedFilePath);
        if (!isCurrent()) return;
        const nextFileMeta: MaskFileMeta = {
          inputPath: selectedFilePath,
          fileKind: result.fileKind,
          sourceLabel: result.sourceLabel,
          outputPath: result.outputPath,
        };
        setMaskState({
          status: "done",
          source: "file",
          fileMeta: nextFileMeta,
          result: {
            masked_content: result.maskedContent,
            findings: result.findings,
          },
        });
        return;
      }

      const result = await maskContent(projectPath, inputText);
      if (!isCurrent()) return;
      setMaskState({ status: "done", source: "text", result });
    } catch (error) {
      if (!isCurrent()) return;
      setMaskState({
        status: "error",
        message: error instanceof Error ? error.message : String(error),
      });
    } finally {
      if (isCurrent()) running.current = false;
    }
  }, [inputMode, inputText, m.emptyInput, projectPath, selectedFilePath]);

  const copyMasked = useCallback(async () => {
    if (!maskedOutput) return false;
    try {
      await navigator.clipboard.writeText(maskedOutput);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
      return true;
    } catch (error) {
      onNotice?.(operationErrorMessage(messages.app.clipboardFailed, error));
      return false;
    }
  }, [maskedOutput, messages.app.clipboardFailed, onNotice]);

  const copyAndOpenTool = useCallback(async () => {
    if (!maskedOutput) return;
    if (!(await copyMasked())) return;
    onPreferredAiToolChange(preferredAiTool);
    try {
      await openAiTool(preferredAiTool);
    } catch (error) {
      onNotice?.(operationErrorMessage(messages.app.operationFailed, error));
    }
  }, [
    copyMasked,
    maskedOutput,
    messages.app.operationFailed,
    onNotice,
    onPreferredAiToolChange,
    preferredAiTool,
  ]);

  const saveMaskedFile = useCallback(async () => {
    if (!fileMeta || fileMeta.fileKind !== "office" || savingRef.current || running.current) return;
    const requestId = generation.current;
    const isCurrent = () => generation.current === requestId;
    savingRef.current = true;
    setSaving(true);
    setSaveMessage(null);
    try {
      const outputPath = await save({
        title: m.saveMaskedFile,
        defaultPath: maskOfficeSuggestedName(fileMeta.sourceLabel),
        filters: [{ name: "Office", extensions: ["docx", "xlsx", "pptx"] }],
      });
      if (!isCurrent() || typeof outputPath !== "string" || !outputPath) return;

      const result = await maskFile(projectPath, fileMeta.inputPath, outputPath);
      if (!isCurrent()) return;
      setMaskState((prev) =>
        prev.status === "done"
          ? {
              ...prev,
              fileMeta: {
                ...fileMeta,
                outputPath: result.outputPath,
              },
              result: {
                masked_content: result.maskedContent,
                findings: result.findings,
              },
            }
          : prev,
      );
      if (result.outputPath) {
        setSaveMessage(t(m.savedTo, { path: result.outputPath }));
      }
    } catch (error) {
      if (!isCurrent()) return;
      setMaskState({
        status: "error",
        message: error instanceof Error ? error.message : String(error),
      });
    } finally {
      if (isCurrent()) {
        savingRef.current = false;
        setSaving(false);
      }
    }
  }, [fileMeta, m.saveMaskedFile, m.savedTo, projectPath, t]);

  return {
    messages: m,
    t,
    maskState,
    copied,
    saving,
    saveMessage,
    maskedOutput,
    findings,
    severityCounts,
    fileMeta,
    actionableFindings,
    isLoading,
    canCopy,
    currentStep,
    preferredAiTool,
    onPreferredAiToolChange,
    resetResult,
    runMask,
    copyMasked,
    copyAndOpenTool,
    saveMaskedFile,
  };
}
