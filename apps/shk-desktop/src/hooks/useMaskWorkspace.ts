import { open, save } from "@tauri-apps/plugin-dialog";
import { useCallback, useMemo, useState } from "react";
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

export type MaskInputMode = "text" | "file";

const MASK_FILE_EXTENSIONS = [
  "txt",
  "md",
  "json",
  "yaml",
  "yml",
  "csv",
  "log",
  "docx",
  "xlsx",
  "pptx",
  "pdf",
] as const;

type UseMaskWorkspaceOptions = {
  projectPath: string | null;
  preferredAiTool: PreferredAiTool;
  onPreferredAiToolChange: (tool: PreferredAiTool) => void;
  onNotice?: (message: string) => void;
};

export function useMaskWorkspace({
  projectPath,
  preferredAiTool,
  onPreferredAiToolChange,
  onNotice,
}: UseMaskWorkspaceOptions) {
  const { messages, t } = useI18n();
  const m = messages.mask;

  const [inputMode, setInputMode] = useState<MaskInputMode>("text");
  const [inputText, setInputText] = useState("");
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
  const [maskState, setMaskState] = useState<MaskState>({ status: "idle" });
  const [copied, setCopied] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);

  const maskedOutput = maskState.status === "done" ? maskState.result.masked_content : "";
  const findings = maskState.status === "done" ? maskState.result.findings : [];
  const severityCounts = useMemo(() => findingsBySeverity(findings), [findings]);
  const fileMeta = maskState.status === "done" ? maskState.fileMeta : undefined;
  const actionableFindings = actionableCount(severityCounts);
  const isLoading = maskState.status === "loading";
  const canCopy = maskedOutput.length > 0 && maskState.status === "done";
  const hasInput = inputMode === "text" ? inputText.trim().length > 0 : Boolean(selectedFilePath);
  const currentStep: 1 | 2 | 3 = maskState.status === "done" ? 3 : hasInput ? 2 : 1;

  const resetResult = useCallback(() => {
    setMaskState({ status: "idle" });
    setCopied(false);
    setSaveMessage(null);
  }, []);

  const clearInput = useCallback(() => {
    setInputText("");
    setSelectedFilePath(null);
    resetResult();
  }, [resetResult]);

  const switchInputMode = useCallback(
    (mode: MaskInputMode) => {
      setInputMode(mode);
      resetResult();
      if (mode === "text") {
        setSelectedFilePath(null);
      } else {
        setInputText("");
      }
    },
    [resetResult],
  );

  const applySelectedFile = useCallback(
    (path: string) => {
      setSelectedFilePath(path);
      setInputMode("file");
      setInputText("");
      resetResult();
    },
    [resetResult],
  );

  const chooseFile = useCallback(async () => {
    try {
      const path = await open({
        directory: false,
        multiple: false,
        title: m.selectFile,
        filters: [{ name: "Supported", extensions: [...MASK_FILE_EXTENSIONS] }],
      });
      if (typeof path === "string" && path) {
        applySelectedFile(path);
      }
    } catch (error) {
      onNotice?.(operationErrorMessage(messages.app.operationFailed, error));
    }
  }, [applySelectedFile, messages.app.operationFailed, m.selectFile, onNotice]);

  const runMask = useCallback(async () => {
    if (inputMode === "text" && !inputText.trim()) {
      setMaskState({ status: "error", message: m.emptyInput });
      return;
    }
    if (inputMode === "file" && !selectedFilePath) {
      setMaskState({ status: "error", message: m.emptyInput });
      return;
    }

    setMaskState({ status: "loading" });
    setCopied(false);
    setSaveMessage(null);

    try {
      if (inputMode === "file" && selectedFilePath) {
        const result = await maskFile(projectPath, selectedFilePath);
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
      setMaskState({ status: "done", source: "text", result });
    } catch (error) {
      setMaskState({
        status: "error",
        message: error instanceof Error ? error.message : String(error),
      });
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
    if (!fileMeta || fileMeta.fileKind !== "office") return;
    setSaving(true);
    setSaveMessage(null);
    try {
      const outputPath = await save({
        title: m.saveMaskedFile,
        defaultPath: maskOfficeSuggestedName(fileMeta.sourceLabel),
        filters: [{ name: "Office", extensions: ["docx", "xlsx", "pptx"] }],
      });
      if (typeof outputPath !== "string" || !outputPath) return;

      const result = await maskFile(projectPath, fileMeta.inputPath, outputPath);
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
      setMaskState({
        status: "error",
        message: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setSaving(false);
    }
  }, [fileMeta, m.saveMaskedFile, m.savedTo, projectPath, t]);

  const removeSelectedFile = useCallback(() => {
    setSelectedFilePath(null);
    resetResult();
  }, [resetResult]);

  return {
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
    severityCounts,
    fileMeta,
    actionableFindings,
    isLoading,
    canCopy,
    hasInput,
    currentStep,
    preferredAiTool,
    onPreferredAiToolChange,
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
  };
}
