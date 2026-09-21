// @vitest-environment jsdom
import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { PseudonymizeInspectResult } from "../pseudonymize";
import { useTablePreviewNavigation } from "./useTablePreviewNavigation";

const inspect: PseudonymizeInspectResult = {
  inputKind: "table-csv",
  sourceLabel: "demo.csv",
  table: {
    hasHeader: true,
    delimiter: ",",
    headers: [],
    columns: [],
    sampleRows: [],
    rowCount: 0,
    sheets: [],
    selectedSheet: null,
  },
};
const initial = {
  active: true,
  hasInput: true,
  projectPath: "/demo",
  pastedKind: "csv" as const,
  inspect: null as PseudonymizeInspectResult | null,
  ready: false,
  failed: false,
};
const nodes: HTMLElement[] = [];
afterEach(() => {
  nodes.splice(0).forEach((node) => node.remove());
  vi.unstubAllGlobals();
});

function setup() {
  const hook = renderHook(useTablePreviewNavigation, { initialProps: initial });
  const inputRegion = document.createElement("div");
  const textarea = document.createElement("textarea");
  inputRegion.append(textarea);
  const preview = document.createElement("div");
  preview.tabIndex = -1;
  preview.scrollIntoView = vi.fn();
  inputRegion.scrollIntoView = vi.fn();
  document.body.append(inputRegion, preview);
  nodes.push(inputRegion, preview);
  hook.result.current.inputRegion.current = inputRegion;
  hook.result.current.previewRegion.current = preview;
  textarea.focus();
  return { ...hook, textarea, inputRegion, preview };
}

describe("table preview navigation", () => {
  it("navigates once and respects reduced motion, then returns to the editor", () => {
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: true }));
    const { result, rerender, preview, textarea, inputRegion } = setup();
    act(() => result.current.inputChanged(true));
    rerender({ ...initial, inspect, ready: true });
    expect(preview).toHaveFocus();
    expect(preview.scrollIntoView).toHaveBeenCalledWith({ block: "start", behavior: "auto" });
    rerender({ ...initial, inspect: { ...inspect }, ready: true });
    expect(preview.scrollIntoView).toHaveBeenCalledTimes(1);
    act(() => result.current.returnToInput());
    expect(textarea).toHaveFocus();
    expect(inputRegion.scrollIntoView).toHaveBeenCalledTimes(1);
  });

  it("does not steal focus after the user moves to another control", () => {
    const { result, rerender, preview } = setup();
    act(() => result.current.inputChanged(true));
    const other = document.createElement("button");
    document.body.append(other);
    nodes.push(other);
    other.focus();
    rerender({ ...initial, inspect, ready: true });
    expect(other).toHaveFocus();
    expect(preview.scrollIntoView).not.toHaveBeenCalled();
  });

  it("navigates when already pasted content is declared a table", () => {
    const { result, rerender, preview } = setup();
    const select = document.createElement("select");
    document.body.append(select);
    nodes.push(select);
    select.focus();
    act(() => result.current.kindChanged("tsv"));
    rerender({ ...initial, pastedKind: "tsv", inspect, ready: true });
    expect(preview).toHaveFocus();
    expect(preview.scrollIntoView).toHaveBeenCalledTimes(1);
  });

  it("does not arm navigation when the kind returns to plain text", () => {
    const { result, rerender, preview } = setup();
    act(() => result.current.inputChanged(true));
    act(() => result.current.kindChanged("text"));
    rerender({ ...initial, pastedKind: "text", inspect, ready: true });
    expect(preview.scrollIntoView).not.toHaveBeenCalled();
  });

  it.each(["clear", "project", "kind", "error", "cancel"])(
    "cancels a pending reveal on %s",
    (reason) => {
      const { result, rerender, preview } = setup();
      act(() => result.current.inputChanged(true));
      if (reason === "cancel") act(() => result.current.cancel());
      rerender({
        ...initial,
        hasInput: reason !== "clear",
        projectPath: reason === "project" ? "/other" : "/demo",
        pastedKind: reason === "kind" ? "tsv" : "csv",
        failed: reason === "error",
      });
      rerender({ ...initial, inspect, ready: true });
      expect(preview.scrollIntoView).not.toHaveBeenCalled();
    },
  );
});
