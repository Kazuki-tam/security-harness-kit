import { describe, expect, it } from "vitest";
import type { PseudonymizeColumnPlan, PseudonymizeTablePreview } from "./pseudonymize";
import {
  columnsReducer,
  hasUnappliedSuggestions,
  initialChoices,
  selectedCount,
  toRunColumns,
  validationErrors,
} from "./pseudonymizeColumns";

function plan(overrides: Partial<PseudonymizeColumnPlan> & { index: number; name: string }) {
  return {
    kind: "none",
    customLabel: null,
    source: "none",
    matchRate: null,
    formula: false,
    ...overrides,
  } as PseudonymizeColumnPlan;
}

function table(columns: PseudonymizeColumnPlan[]): PseudonymizeTablePreview {
  return {
    hasHeader: true,
    delimiter: ",",
    headers: columns.map((column) => column.name),
    sampleRows: [],
    rowCount: 0,
    columns,
    sheets: [],
    selectedSheet: null,
  };
}

const fixture = table([
  plan({ index: 0, name: "Mail", kind: "email", source: "inferred", matchRate: 0.9 }),
  plan({ index: 1, name: "Member ID", kind: "custom", customLabel: "member", source: "config" }),
  plan({ index: 2, name: "Note" }),
]);

describe("column choices", () => {
  it("starts from the suggestions and proposes labels for the rest", () => {
    const choices = initialChoices(fixture);
    expect(choices.map((choice) => choice.kind)).toEqual(["email", "custom", "none"]);
    expect(choices[0].suggestion).toEqual({
      kind: "email",
      customLabel: undefined,
      source: "inferred",
      matchRate: 0.9,
    });
    expect(choices[1].customLabel).toBe("member");
    expect(choices[2].suggestion).toBeUndefined();
    expect(choices[2].customLabel).toBe("note");
    expect(selectedCount(choices)).toBe(2);
    expect(hasUnappliedSuggestions(choices)).toBe(false);
  });

  it("edits, clears, and re-applies suggestions", () => {
    let state = initialChoices(fixture);
    state = columnsReducer(state, { type: "setKind", index: 0, kind: "none" });
    expect(selectedCount(state)).toBe(1);
    expect(hasUnappliedSuggestions(state)).toBe(true);
    state = columnsReducer(state, { type: "setKind", index: 2, kind: "custom" });
    state = columnsReducer(state, { type: "setCustomLabel", index: 2, label: "Bad Label" });
    expect(validationErrors(state)).toEqual([{ index: 2, reason: "invalid" }]);
    state = columnsReducer(state, { type: "setCustomLabel", index: 2, label: "email" });
    expect(validationErrors(state)).toEqual([{ index: 2, reason: "reserved" }]);
    state = columnsReducer(state, { type: "setCustomLabel", index: 2, label: "note_1" });
    expect(validationErrors(state)).toEqual([]);

    const cleared = columnsReducer(state, { type: "clearAll" });
    expect(selectedCount(cleared)).toBe(0);
    const applied = columnsReducer(cleared, { type: "applySuggestions" });
    expect(applied.map((choice) => choice.kind)).toEqual(["email", "custom", "none"]);
    expect(hasUnappliedSuggestions(applied)).toBe(false);
  });

  it("keeps user edits across a re-plan when the header survives", () => {
    let state = initialChoices(fixture);
    state = columnsReducer(state, { type: "setKind", index: 0, kind: "phone" });
    state = columnsReducer(state, { type: "setKind", index: 2, kind: "name" });
    const next = table([
      plan({ index: 0, name: "mail", kind: "email", source: "inferred", matchRate: 0.5 }),
      plan({ index: 1, name: "Other" }),
    ]);
    const kept = columnsReducer(state, { type: "reinspect", table: next, keep: "byName" });
    expect(kept.map((choice) => choice.kind)).toEqual(["phone", "none"]);
    expect(kept[0].suggestion?.matchRate).toBe(0.5);
    const reset = columnsReducer(state, { type: "reinspect", table: next, keep: "none" });
    expect(reset.map((choice) => choice.kind)).toEqual(["email", "none"]);
  });

  it("sends every column so the engine applies the exact selection", () => {
    let state = initialChoices(fixture);
    state = columnsReducer(state, { type: "setCustomLabel", index: 1, label: " member " });
    expect(toRunColumns(state)).toEqual([
      { index: 0, name: "Mail", kind: "email", customLabel: null },
      { index: 1, name: "Member ID", kind: "custom", customLabel: "member" },
      { index: 2, name: "Note", kind: "none", customLabel: null },
    ]);
  });

  it("never selects a formula column", () => {
    const withFormula = table([
      plan({
        index: 0,
        name: "Total",
        kind: "email",
        source: "inferred",
        matchRate: 1,
        formula: true,
      }),
      plan({ index: 1, name: "Mail", kind: "email", source: "inferred", matchRate: 1 }),
    ]);
    let state = initialChoices(withFormula);
    expect(state.map((choice) => choice.kind)).toEqual(["none", "email"]);
    expect(hasUnappliedSuggestions(state)).toBe(false);
    state = columnsReducer(state, { type: "setKind", index: 0, kind: "email" });
    expect(state[0].kind).toBe("none");
    state = columnsReducer(state, { type: "clearAll" });
    state = columnsReducer(state, { type: "applySuggestions" });
    expect(state.map((choice) => choice.kind)).toEqual(["none", "email"]);
  });
});
