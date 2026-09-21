import { useCallback, useEffect, useRef } from "react";
import type { PseudonymizeInspectResult } from "../pseudonymize";
import type { PastedKind } from "./usePseudonymizeWorkspace";

type Options = {
  active: boolean;
  hasInput: boolean;
  projectPath: string | null;
  pastedKind: PastedKind;
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
 * A completed paste, or a kind change that turns pasted content into a table,
 * may navigate once; typing and unrelated focus changes must not.
 */
export function useTablePreviewNavigation({
  active,
  hasInput,
  projectPath,
  pastedKind,
  inspect,
  ready,
  failed,
}: Options) {
  const inputRegion = useRef<HTMLDivElement>(null);
  const previewRegion = useRef<HTMLDivElement>(null);
  const pending = useRef<{
    previous: PseudonymizeInspectResult | null;
    projectPath: string | null;
    kind: PastedKind;
    source: Element | null;
  } | null>(null);

  const cancel = useCallback(() => {
    pending.current = null;
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
  const revealPreview = useCallback(() => reveal(previewRegion.current), []);
  const returnToInput = useCallback(() => {
    const region = inputRegion.current;
    reveal(region, region?.querySelector("textarea") ?? region);
  }, []);

  useEffect(() => {
    const request = pending.current;
    if (!request) return;
    if (
      !active ||
      !hasInput ||
      request.projectPath !== projectPath ||
      request.kind !== pastedKind ||
      failed
    ) {
      cancel();
      return;
    }
    if (ready && inspect?.table && inspect !== request.previous) {
      cancel();
      // Do not steal focus if the user moved to another control while parsing.
      if (document.activeElement === request.source) revealPreview();
    }
  }, [active, hasInput, projectPath, pastedKind, failed, ready, inspect, cancel, revealPreview]);

  return {
    inputRegion,
    previewRegion,
    inputChanged,
    kindChanged,
    cancel,
    revealPreview,
    returnToInput,
  };
}
