import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { PseudonymizeInspectResult } from "../pseudonymize";
import type { PastedKind } from "./usePseudonymizeWorkspace";

type Options = {
  active: boolean;
  hasInput: boolean;
  projectPath: string | null;
  pastedKind: PastedKind;
  selectedFilePath?: string | null;
  inspect: PseudonymizeInspectResult | null;
  ready: boolean;
  failed: boolean;
};

function reveal(region: HTMLElement | null, focusTarget: HTMLElement | null = region) {
  if (!region) return;
  focusTarget?.focus({ preventScroll: true });
  region.scrollIntoView?.({
    block: "start",
    behavior: window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
  });
}

/**
 * File selection, a completed paste, or a kind change may reveal a table once.
 * Typing and unrelated focus changes must not collapse the editor or navigate.
 */
export function useTablePreviewNavigation({
  active,
  hasInput,
  projectPath,
  pastedKind,
  selectedFilePath,
  inspect,
  ready,
  failed,
}: Options) {
  const [inputCollapsed, setInputCollapsed] = useState(false);
  const focusInputPending = useRef(false);
  const focusPreviewPending = useRef(false);
  const inputRegion = useRef<HTMLDivElement>(null);
  const previewRegion = useRef<HTMLDivElement>(null);
  const pending = useRef<{
    previous: PseudonymizeInspectResult | null;
    projectPath: string | null;
    kind: PastedKind | null;
    source: Element | null;
  } | null>(null);

  // A selected file replaces the large picker immediately. Once its plan is
  // ready, keep the compact file controls and the table together in view.
  useEffect(() => {
    if (active && selectedFilePath) {
      pending.current = {
        previous: null,
        projectPath,
        kind: null,
        source: document.activeElement,
      };
    }
  }, [active, selectedFilePath, projectPath]);

  const cancel = useCallback(() => {
    pending.current = null;
    focusInputPending.current = false;
    focusPreviewPending.current = false;
    setInputCollapsed(false);
  }, []);
  const inputChanged = useCallback(
    (pasted: boolean) => {
      pending.current =
        active && pasted && pastedKind !== "text"
          ? { previous: inspect, projectPath, kind: pastedKind, source: document.activeElement }
          : null;
    },
    [active, inspect, pastedKind, projectPath],
  );
  /** Choosing CSV/TSV for content that is already pasted is the other way a table appears. */
  const kindChanged = useCallback(
    (next: PastedKind) => {
      pending.current =
        active && hasInput && next !== "text"
          ? { previous: inspect, projectPath, kind: next, source: document.activeElement }
          : null;
    },
    [active, hasInput, inspect, projectPath],
  );
  const revealPreview = useCallback(() => {
    if (!inputCollapsed) {
      focusPreviewPending.current = true;
      setInputCollapsed(true);
      return;
    }
    reveal(previewRegion.current);
  }, [inputCollapsed]);
  const returnToInput = useCallback(() => {
    pending.current = null;
    focusPreviewPending.current = false;
    if (inputCollapsed) {
      focusInputPending.current = true;
      setInputCollapsed(false);
      return;
    }
    const region = inputRegion.current;
    reveal(region, region?.querySelector("textarea") ?? region);
  }, [inputCollapsed]);
  useLayoutEffect(() => {
    if (inputCollapsed && focusPreviewPending.current) {
      focusPreviewPending.current = false;
      reveal(previewRegion.current);
    }
    if (!inputCollapsed && focusInputPending.current) {
      focusInputPending.current = false;
      const region = inputRegion.current;
      reveal(region, region?.querySelector("textarea") ?? region);
    }
  }, [inputCollapsed]);

  useEffect(() => {
    // A failed re-plan must leave the editor open for correction. Otherwise a
    // later successful retry could hide the field while the user is typing.
    if (!active || !hasInput || failed) {
      cancel();
      return;
    }
    const request = pending.current;
    if (!request) return;
    if (
      request.projectPath !== projectPath ||
      (request.kind !== null && request.kind !== pastedKind)
    ) {
      cancel();
      return;
    }
    if (ready && inspect?.table && inspect !== request.previous) {
      cancel();
      // Do not steal focus if the user moved to another control while parsing.
      if (document.activeElement === request.source) {
        if (request.kind === null) reveal(inputRegion.current, previewRegion.current);
        else revealPreview();
      }
    }
  }, [active, hasInput, projectPath, pastedKind, failed, ready, inspect, cancel, revealPreview]);

  return {
    inputCollapsed,
    inputRegion,
    previewRegion,
    inputChanged,
    kindChanged,
    cancel,
    revealPreview,
    returnToInput,
  };
}
