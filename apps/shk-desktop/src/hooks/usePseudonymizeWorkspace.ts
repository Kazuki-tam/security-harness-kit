import { save } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import { useI18n } from "../i18n";
import { operationErrorMessage } from "../i18n/interpolate";
import {
  isTableFile,
  isTableInputKind,
  outputFilterFor,
  pseudonymizeInspect,
  pseudonymizeKeyStatus,
  pseudonymizeRun,
  pseudonymizeSuggestedOutputPath,
  restoreMapSuggestedPath,
  type PseudonymizeFormat,
  type PseudonymizeInspectOptions,
  type PseudonymizeInspectResult,
  type PseudonymizeRunOptions,
  type PseudonymizeRunResult,
} from "../pseudonymize";
import {
  columnsReducer,
  toRunColumns,
  validationErrors,
  type ColumnChoice,
  type ColumnAction,
} from "../pseudonymizeColumns";
import { createRequestTracker } from "../utils/requestTracker";
import type { MaskInputApi } from "./useMaskInput";

/** What pasted text is: prose, or a delimited table. */
export type PastedKind = "text" | "csv" | "tsv";

export type PseudonymizePhase =
  | { status: "idle" }
  | { status: "inspecting" }
  | { status: "ready"; inspect: PseudonymizeInspectResult }
  | { status: "running"; inspect: PseudonymizeInspectResult | null }
  | { status: "done"; inspect: PseudonymizeInspectResult | null; result: PseudonymizeRunResult }
  | { status: "error"; message: string; inspect: PseudonymizeInspectResult | null };

type UsePseudonymizeWorkspaceOptions = {
  projectPath: string | null;
  /** The mode is selected and a project with shk.toml is chosen. */
  active: boolean;
  input: MaskInputApi;
  onNotice?: (message: string) => void;
};

const INSPECT_KEY = "inspect";
const PASTED_INSPECT_DELAY_MS = 400;

function inspectOf(phase: PseudonymizePhase): PseudonymizeInspectResult | null {
  return phase.status === "idle" || phase.status === "inspecting" ? null : phase.inspect;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function usePseudonymizeWorkspace({
  projectPath,
  active,
  input,
  onNotice,
}: UsePseudonymizeWorkspaceOptions) {
  const { messages, t } = useI18n();
  const m = messages.mask.pseudonymize;
  const { inputMode, inputText, selectedFilePath } = input;

  const [phase, setPhase] = useState<PseudonymizePhase>({ status: "idle" });
  const [columns, dispatchColumns] = useReducer(columnsReducer, [] as ColumnChoice[]);
  const [pastedKind, setPastedKind] = useState<PastedKind>("text");
  const [sheet, setSheet] = useState<string | undefined>(undefined);
  const [noHeader, setNoHeader] = useState(false);
  const [restoreMap, setRestoreMap] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [preparing, setPreparing] = useState(false);
  const [keyDialog, setKeyDialog] = useState<{ open: boolean; backend: string }>({
    open: false,
    backend: "",
  });
  const [copied, setCopied] = useState(false);
  const [copiedPath, setCopiedPath] = useState<string | null>(null);
  const keyResolver = useRef<((accepted: boolean) => void) | null>(null);
  const tracker = useMemo(() => createRequestTracker(), []);

  const isFileInput = inputMode === "file" && Boolean(selectedFilePath);
  const isPastedInput = inputMode === "text" && inputText.trim().length > 0;
  const isTableInput = isFileInput
    ? isTableFile(selectedFilePath ?? "")
    : isPastedInput && pastedKind !== "text";
  const inspect = inspectOf(phase);
  const isRunning = phase.status === "running";
  const isInspecting = phase.status === "inspecting";
  const columnErrors = useMemo(() => validationErrors(columns), [columns]);
  const canRun =
    Boolean(projectPath) &&
    active &&
    (isFileInput || isPastedInput) &&
    !isRunning &&
    !isInspecting &&
    !preparing &&
    columnErrors.length === 0 &&
    // A table needs its plan first; text inputs run directly.
    (!isTableInput ||
      phase.status === "ready" ||
      phase.status === "done" ||
      phase.status === "error");

  const reset = useCallback(() => {
    tracker.begin(INSPECT_KEY);
    setPhase({ status: "idle" });
    dispatchColumns({ type: "init", table: emptyTable() });
    setSheet(undefined);
    setNoHeader(false);
    setCopied(false);
    setCopiedPath(null);
  }, [tracker]);

  const baseRequest = useCallback(
    (overrides: { sheet?: string; noHeader?: boolean } = {}): PseudonymizeInspectOptions | null => {
      const nextNoHeader = overrides.noHeader ?? noHeader;
      if (inputMode === "file" && selectedFilePath) {
        return {
          inputPath: selectedFilePath,
          sheet: overrides.sheet ?? sheet,
          noHeader: nextNoHeader,
        };
      }
      if (inputMode === "text" && inputText.trim()) {
        if (pastedKind === "text") {
          return { inlineText: inputText, mode: "text" };
        }
        return {
          inlineText: inputText,
          mode: "table",
          format: pastedKind satisfies PseudonymizeFormat,
          noHeader: nextNoHeader,
        };
      }
      return null;
    },
    [inputMode, inputText, noHeader, pastedKind, selectedFilePath, sheet],
  );

  const runInspect = useCallback(
    async (
      overrides: { sheet?: string; noHeader?: boolean },
      columnAction: (table: NonNullable<PseudonymizeInspectResult["table"]>) => ColumnAction,
    ) => {
      if (!projectPath || !active) return;
      const request = baseRequest(overrides);
      if (!request) return;
      const requestId = tracker.begin(INSPECT_KEY);
      setPhase({ status: "inspecting" });
      try {
        const result = await pseudonymizeInspect(projectPath, request);
        if (!tracker.isLatest(INSPECT_KEY, requestId)) return;
        if (result.table) {
          dispatchColumns(columnAction(result.table));
        } else {
          dispatchColumns({ type: "init", table: emptyTable() });
        }
        setPhase({ status: "ready", inspect: result });
      } catch (error) {
        if (!tracker.isLatest(INSPECT_KEY, requestId)) return;
        setPhase({
          status: "error",
          message: `${m.inspectFailed}: ${errorMessage(error)}`,
          inspect: null,
        });
      }
    },
    [active, baseRequest, m.inspectFailed, projectPath, tracker],
  );

  // Plan as soon as there is something to plan: immediately for a file,
  // after a short pause for pasted tables so typing does not spam the engine.
  // The latest `runInspect` is read through a ref so this effect re-runs only
  // when the input itself changes, not when options such as the sheet do.
  const runInspectRef = useRef(runInspect);
  runInspectRef.current = runInspect;
  useEffect(() => {
    if (!active || !projectPath) return;
    if (isFileInput) {
      void runInspectRef.current({}, (table) => ({ type: "init", table }));
      return;
    }
    if (isPastedInput && pastedKind !== "text") {
      const timer = window.setTimeout(() => {
        void runInspectRef.current({}, (table) => ({ type: "init", table }));
      }, PASTED_INSPECT_DELAY_MS);
      return () => window.clearTimeout(timer);
    }
    // Plain text needs no plan.
  }, [active, projectPath, isFileInput, isPastedInput, pastedKind, selectedFilePath, inputText]);

  const changeSheet = useCallback(
    (next: string) => {
      setSheet(next);
      void runInspect({ sheet: next }, (table) => ({ type: "reinspect", table, keep: "byName" }));
    },
    [runInspect],
  );

  const changeNoHeader = useCallback(
    (next: boolean) => {
      setNoHeader(next);
      void runInspect({ noHeader: next }, (table) => ({ type: "reinspect", table, keep: "none" }));
    },
    [runInspect],
  );

  const changePastedKind = useCallback(
    (next: PastedKind) => {
      setPastedKind(next);
      reset();
    },
    [reset],
  );

  const confirmKeyCreation = useCallback((backend: string) => {
    return new Promise<boolean>((resolve) => {
      keyResolver.current = resolve;
      setKeyDialog({ open: true, backend });
    });
  }, []);

  const resolveKeyDialog = useCallback((accepted: boolean) => {
    setKeyDialog((dialog) => ({ ...dialog, open: false }));
    keyResolver.current?.(accepted);
    keyResolver.current = null;
  }, []);

  const run = useCallback(async () => {
    if (!projectPath || !active) return;
    const request = baseRequest();
    if (!request) return;
    if (columnErrors.length > 0) return;
    const current = inspectOf(phase);

    setPreparing(true);
    setCopied(false);
    setCopiedPath(null);
    try {
      let outputPath: string | undefined;
      let mapPath: string | undefined;
      if (inputMode === "file" && selectedFilePath) {
        const chosen = await save({
          title: m.chooseOutput,
          defaultPath: pseudonymizeSuggestedOutputPath(selectedFilePath),
          filters: [outputFilterFor(selectedFilePath)],
        });
        if (typeof chosen !== "string" || !chosen) return;
        outputPath = chosen;
        if (restoreMap) mapPath = restoreMapSuggestedPath(chosen);
      }

      const key = await pseudonymizeKeyStatus(projectPath);
      if (key.unavailableReason) {
        throw new Error(t(m.keyUnavailable, { reason: key.unavailableReason }));
      }
      let createKey = false;
      if (!key.exists) {
        if (!(await confirmKeyCreation(key.backend))) return;
        createKey = true;
      }

      setPhase({ status: "running", inspect: current });
      const options: PseudonymizeRunOptions = {
        ...request,
        columns: isTableInput ? toRunColumns(columns) : undefined,
        outputPath,
        mapPath,
        createKey,
      };
      const result = await pseudonymizeRun(projectPath, options);
      setPhase({ status: "done", inspect: current, result });
    } catch (error) {
      setPhase({ status: "error", message: errorMessage(error), inspect: current });
    } finally {
      setPreparing(false);
    }
  }, [
    active,
    baseRequest,
    columnErrors.length,
    columns,
    confirmKeyCreation,
    inputMode,
    isTableInput,
    m.chooseOutput,
    m.keyUnavailable,
    phase,
    projectPath,
    restoreMap,
    selectedFilePath,
    t,
  ]);

  const inlineOutput = phase.status === "done" ? (phase.result.inlineOutput ?? "") : "";

  const copyText = useCallback(
    async (text: string) => {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch (error) {
        onNotice?.(operationErrorMessage(messages.app.clipboardFailed, error));
        return false;
      }
    },
    [messages.app.clipboardFailed, onNotice],
  );

  const copyInlineOutput = useCallback(async () => {
    if (!inlineOutput) return false;
    const ok = await copyText(inlineOutput);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    }
    return ok;
  }, [copyText, inlineOutput]);

  const copyPath = useCallback(
    async (path: string) => {
      if (await copyText(path)) {
        setCopiedPath(path);
        window.setTimeout(() => setCopiedPath(null), 1800);
      }
    },
    [copyText],
  );

  const tableInputKind =
    inspect?.inputKind !== undefined ? isTableInputKind(inspect.inputKind) : isTableInput;

  return {
    messages: m,
    t,
    phase,
    inspect,
    columns,
    dispatchColumns,
    columnErrors,
    pastedKind,
    changePastedKind,
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
    isTableInput: tableInputKind,
    isFileInput,
    isRunning,
    isInspecting,
    preparing,
    canRun,
    inlineOutput,
    copied,
    copiedPath,
    reset,
    run,
    copyInlineOutput,
    copyPath,
  };
}

export type PseudonymizeWorkspaceApi = ReturnType<typeof usePseudonymizeWorkspace>;

function emptyTable() {
  return {
    hasHeader: true,
    delimiter: ",",
    headers: [],
    sampleRows: [],
    rowCount: 0,
    columns: [],
    sheets: [],
    selectedSheet: null,
  };
}
