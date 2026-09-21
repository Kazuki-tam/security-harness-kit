import { open } from "@tauri-apps/plugin-dialog";
import { useCallback, useLayoutEffect, useRef, useState } from "react";
import { useI18n } from "../i18n";
import { operationErrorMessage } from "../i18n/interpolate";
import { fileExtension } from "../pseudonymize";

export type MaskInputMode = "text" | "file";

/** `edit` keeps the same content and changes it; `replace` swaps it for other content. */
export type MaskInputChange = "edit" | "replace";

type UseMaskInputOptions = {
  /** Extensions offered by the file picker. */
  extensions: readonly string[];
  /** Reject dropped or picked files outside `extensions` (pseudonymize only). */
  enforceExtensions?: boolean;
  unsupportedMessage?: string;
  /** Called whenever the text, file, or input mode changes, so result state can reset. */
  onInputChange?: (change: MaskInputChange) => void;
  onNotice?: (message: string) => void;
};

/** The text or file a user wants to mask, shared by every masking method. */
export function useMaskInput({
  extensions,
  enforceExtensions = false,
  unsupportedMessage,
  onInputChange,
  onNotice,
}: UseMaskInputOptions) {
  const { messages } = useI18n();
  const m = messages.mask;
  const [inputMode, setInputMode] = useState<MaskInputMode>("text");
  const [inputText, setInputTextState] = useState("");
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);

  // Callbacks below stay stable across renders even when the caller passes
  // a fresh closure each time; the refs are written after render, not during.
  const onInputChangeRef = useRef(onInputChange);
  const onNoticeRef = useRef(onNotice);
  useLayoutEffect(() => {
    onInputChangeRef.current = onInputChange;
    onNoticeRef.current = onNotice;
  });

  const notifyChange = useCallback(
    (change: MaskInputChange) => onInputChangeRef.current?.(change),
    [],
  );

  const setInputText = useCallback(
    (value: string) => {
      setInputTextState(value);
      notifyChange("edit");
    },
    [notifyChange],
  );

  const clearInput = useCallback(() => {
    setInputTextState("");
    setSelectedFilePath(null);
    notifyChange("replace");
  }, [notifyChange]);

  const switchInputMode = useCallback(
    (mode: MaskInputMode) => {
      setInputMode(mode);
      if (mode === "text") {
        setSelectedFilePath(null);
      } else {
        setInputTextState("");
      }
      notifyChange("replace");
    },
    [notifyChange],
  );

  const applySelectedFile = useCallback(
    (path: string): boolean => {
      if (enforceExtensions && !extensions.includes(fileExtension(path))) {
        if (unsupportedMessage) onNoticeRef.current?.(unsupportedMessage);
        return false;
      }
      setSelectedFilePath(path);
      setInputMode("file");
      setInputTextState("");
      notifyChange("replace");
      return true;
    },
    [enforceExtensions, extensions, notifyChange, unsupportedMessage],
  );

  const chooseFile = useCallback(async () => {
    try {
      const path = await open({
        directory: false,
        multiple: false,
        title: m.selectFile,
        filters: [{ name: "Supported", extensions: [...extensions] }],
      });
      if (typeof path === "string" && path) {
        applySelectedFile(path);
      }
    } catch (error) {
      onNoticeRef.current?.(operationErrorMessage(messages.app.operationFailed, error));
    }
  }, [applySelectedFile, extensions, m.selectFile, messages.app.operationFailed]);

  const removeSelectedFile = useCallback(() => {
    setSelectedFilePath(null);
    notifyChange("replace");
  }, [notifyChange]);

  const hasInput = inputMode === "text" ? inputText.trim().length > 0 : Boolean(selectedFilePath);

  return {
    inputMode,
    inputText,
    setInputText,
    selectedFilePath,
    dragActive,
    setDragActive,
    hasInput,
    clearInput,
    switchInputMode,
    applySelectedFile,
    chooseFile,
    removeSelectedFile,
  };
}

export type MaskInputApi = ReturnType<typeof useMaskInput>;
