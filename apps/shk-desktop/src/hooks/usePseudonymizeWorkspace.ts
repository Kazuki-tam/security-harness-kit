import { save } from "@tauri-apps/plugin-dialog";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
} from "react";
import { useI18n } from "../i18n";
import { operationErrorMessage } from "../i18n/interpolate";
import {
  isTableFile,
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
  type PseudonymizeTablePreview,
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
  | { status: "inspecting"; inspect: PseudonymizeInspectResult | null }
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
const RUN_KEY = "run";
const PASTED_INSPECT_DELAY_MS = 400;

const EMPTY_TABLE: PseudonymizeTablePreview = {
  hasHeader: true,
  delimiter: ",",
  headers: [],
  sampleRows: [],
  rowCount: 0,
  columns: [],
  sheets: [],
  selectedSheet: null,
};

function inspectOf(phase: PseudonymizePhase): PseudonymizeInspectResult | null {
  return phase.status === "idle" ? null : phase.inspect;
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
  /// Bumped by `reset()` so the same content can be planned again.
  const [planGeneration, setPlanGeneration] = useState(0);
  /** A pasted-table re-plan is scheduled but has not run yet. */
  const [replanPending, setReplanPending] = useState(false);
  const [keyDialog, setKeyDialog] = useState<{ open: boolean; backend: string }>({
    open: false,
    backend: "",
  });
  const [copied, setCopied] = useState(false);
  const [copiedPath, setCopiedPath] = useState<string | null>(null);
  const runPending = useRef(false);
  const keyResolver = useRef<((accepted: boolean) => void) | null>(null);
  const tracker = useMemo(() => createRequestTracker(), []);

  const isFileInput = inputMode === "file" && Boolean(selectedFilePath);
  const isPastedInput = inputMode === "text" && inputText.trim().length > 0;
  const isTableInput = isFileInput
    ? isTableFile(selectedFilePath ?? "")
    : isPastedInput && pastedKind !== "text";
  const inspect = inspectOf(phase);
  const hasPlan = inspect?.table != null;
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
    !replanPending &&
    columnErrors.length === 0 &&
    // A table needs its plan first; text inputs run directly.
    (!isTableInput || hasPlan);

  /** Drop results only; the plan, column choices, and options survive edits. */
  const resetResult = useCallback(() => {
    tracker.begin(RUN_KEY);
    runPending.current = false;
    setPreparing(false);
    keyResolver.current?.(false);
    keyResolver.current = null;
    setKeyDialog((dialog) => ({ ...dialog, open: false }));
    setPhase((current) => {
      if (current.status === "idle" || current.status === "inspecting") return current;
      if (current.status === "ready") return current;
      // A run in flight is abandoned (its result is ignored by the guard);
      // a finished or failed one goes back to its plan when there is one.
      const plan = current.inspect;
      return plan?.table ? { status: "ready", inspect: plan } : { status: "idle" };
    });
    setCopied(false);
    setCopiedPath(null);
  }, [tracker]);

  /** Start from scratch: used when the mode, project, or content changes. */
  const reset = useCallback(() => {
    tracker.begin(INSPECT_KEY);
    tracker.begin(RUN_KEY);
    runPending.current = false;
    setPreparing(false);
    keyResolver.current?.(false);
    keyResolver.current = null;
    setKeyDialog((dialog) => ({ ...dialog, open: false }));
    setPhase({ status: "idle" });
    dispatchColumns({ type: "init", table: EMPTY_TABLE });
    setSheet(undefined);
    setNoHeader(false);
    setCopied(false);
    setCopiedPath(null);
    setPlanGeneration((generation) => generation + 1);
  }, [tracker]);

  useLayoutEffect(() => {
    return () => {
      tracker.begin(INSPECT_KEY);
      tracker.begin(RUN_KEY);
      runPending.current = false;
      keyResolver.current?.(false);
      keyResolver.current = null;
    };
  }, [tracker]);

  const baseRequest = useCallback(
    (overrides: { sheet?: string; noHeader?: boolean } = {}): PseudonymizeInspectOptions | null => {
      // An override that is present but `undefined` clears the value.
      const nextSheet = "sheet" in overrides ? overrides.sheet : sheet;
      const nextNoHeader = "noHeader" in overrides ? overrides.noHeader : noHeader;
      if (inputMode === "file" && selectedFilePath) {
        return {
          inputPath: selectedFilePath,
          sheet: nextSheet,
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
      columnAction: (table: PseudonymizeTablePreview) => ColumnAction,
    ) => {
      if (!projectPath || !active) return;
      const request = baseRequest(overrides);
      if (!request) return;
      const requestId = tracker.begin(INSPECT_KEY);
      // Keep the previous plan on screen while the new one loads.
      setPhase((current) => ({ status: "inspecting", inspect: inspectOf(current) }));
      try {
        const result = await pseudonymizeInspect(projectPath, request);
        if (!tracker.isLatest(INSPECT_KEY, requestId)) return;
        dispatchColumns(
          result.table ? columnAction(result.table) : { type: "init", table: EMPTY_TABLE },
        );
        setPhase({ status: "ready", inspect: result });
      } catch (error) {
        if (!tracker.isLatest(INSPECT_KEY, requestId)) return;
        dispatchColumns({ type: "init", table: EMPTY_TABLE });
        setPhase({
          status: "error",
          message: `${m.inspectFailed}: ${errorMessage(error)}`,
          inspect: null,
        });
      }
    },
    [active, baseRequest, m.inspectFailed, projectPath, tracker],
  );

  // The effects below read the latest `runInspect` through a ref so they
  // re-run only when the input itself changes, not when options such as the
  // sheet do. The ref is written after render, never during it.
  const runInspectRef = useRef(runInspect);
  useLayoutEffect(() => {
    runInspectRef.current = runInspect;
  });

  // A newly selected file gets a fresh plan; the container already cleared
  // the previous plan and options when the file was replaced. Re-choosing
  // the same file bumps the generation, so it is read again as well.
  useEffect(() => {
    if (!active || !projectPath || !isFileInput) return;
    void runInspectRef.current({ sheet: undefined }, (table) => ({ type: "init", table }));
  }, [active, projectPath, isFileInput, selectedFilePath, planGeneration]);

  // Pasted tables re-plan after a short pause so typing does not spam the
  // engine; edits the user already made to same-named columns are kept.
  useEffect(() => {
    if (!active || !projectPath || !isPastedInput || pastedKind === "text") return;
    setReplanPending(true);
    const timer = window.setTimeout(() => {
      setReplanPending(false);
      void runInspectRef.current({}, (table) => ({ type: "reinspect", table, keep: "byName" }));
    }, PASTED_INSPECT_DELAY_MS);
    return () => {
      window.clearTimeout(timer);
      setReplanPending(false);
    };
  }, [active, projectPath, isPastedInput, pastedKind, inputText, planGeneration]);

  // Content that was emptied by hand has nothing to plan or report.
  useEffect(() => {
    if (isFileInput || isPastedInput) return;
    tracker.begin(INSPECT_KEY);
    setPhase((current) => (current.status === "idle" ? current : { status: "idle" }));
  }, [isFileInput, isPastedInput, tracker]);

  const retryInspect = useCallback(() => {
    void runInspect({}, (table) => ({ type: "init", table }));
  }, [runInspect]);

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
    if (!projectPath || !canRun || runPending.current) return;
    if (isTableInput && !hasPlan) return;
    const request = baseRequest();
    if (!request) return;
    if (columnErrors.length > 0) return;
    const current = inspect;
    // An input change during the run invalidates this generation, so a late
    // result never overwrites what the user now sees.
    const runId = tracker.begin(RUN_KEY);
    const stillCurrent = () => tracker.isLatest(RUN_KEY, runId);

    runPending.current = true;
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
        if (!stillCurrent() || typeof chosen !== "string" || !chosen) return;
        outputPath = chosen;
        if (restoreMap) mapPath = restoreMapSuggestedPath(chosen);
      }

      const key = await pseudonymizeKeyStatus(projectPath);
      if (!stillCurrent()) return;
      if (key.unavailableReason) {
        throw new Error(t(m.keyUnavailable, { reason: key.unavailableReason }));
      }
      let createKey = false;
      if (!key.exists) {
        if (!(await confirmKeyCreation(key.backend))) return;
        createKey = true;
      }
      if (!stillCurrent()) return;

      setPhase({ status: "running", inspect: current });
      const options: PseudonymizeRunOptions = {
        ...request,
        columns: isTableInput ? toRunColumns(columns) : undefined,
        outputPath,
        mapPath,
        createKey,
      };
      const result = await pseudonymizeRun(projectPath, options);
      if (!stillCurrent()) return;
      setPhase({ status: "done", inspect: current, result });
    } catch (error) {
      if (!stillCurrent()) return;
      setPhase({ status: "error", message: errorMessage(error), inspect: current });
    } finally {
      if (stillCurrent()) {
        runPending.current = false;
        setPreparing(false);
      }
    }
  }, [
    canRun,
    baseRequest,
    columnErrors.length,
    columns,
    confirmKeyCreation,
    hasPlan,
    inputMode,
    inspect,
    isTableInput,
    m.chooseOutput,
    m.keyUnavailable,
    projectPath,
    restoreMap,
    selectedFilePath,
    t,
    tracker,
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
    isTableInput,
    isFileInput,
    isRunning,
    isInspecting,
    preparing,
    canRun,
    inlineOutput,
    copied,
    copiedPath,
    resetResult,
    reset,
    retryInspect,
    run,
    copyInlineOutput,
    copyPath,
  };
}

export type PseudonymizeWorkspaceApi = ReturnType<typeof usePseudonymizeWorkspace>;
