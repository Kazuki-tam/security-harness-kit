import {
  suggestCustomLabel,
  validateCustomLabel,
  type CustomLabelValidity,
  type PseudonymizeColumnChoiceDto,
  type PseudonymizeColumnPlan,
  type PseudonymizeColumnSource,
  type PseudonymizeKindChoice,
  type PseudonymizeTablePreview,
} from "./pseudonymize";

export type ColumnSuggestion = {
  kind: PseudonymizeKindChoice;
  customLabel?: string;
  source: Exclude<PseudonymizeColumnSource, "none">;
  matchRate?: number;
};

export type ColumnChoice = {
  index: number;
  name: string;
  kind: PseudonymizeKindChoice;
  customLabel: string;
  suggestion?: ColumnSuggestion;
  /** A formula column is always left as it is. */
  formula: boolean;
  previousKind?: Exclude<PseudonymizeKindChoice, "none">;
};

export type ColumnAction =
  | { type: "init"; table: PseudonymizeTablePreview }
  | { type: "setSelected"; index: number; selected: boolean }
  | { type: "setKind"; index: number; kind: PseudonymizeKindChoice }
  | { type: "setCustomLabel"; index: number; label: string }
  | { type: "applySuggestions" }
  | { type: "clearAll" }
  /** A re-plan after a sheet or header change; `byName` keeps edits whose header survived. */
  | { type: "reinspect"; table: PseudonymizeTablePreview; keep: "byName" | "none" };

function suggestionOf(plan: PseudonymizeColumnPlan): ColumnSuggestion | undefined {
  if (plan.source === "none" || plan.kind === "none") return undefined;
  return {
    kind: plan.kind,
    customLabel: plan.customLabel ?? undefined,
    source: plan.source,
    matchRate: plan.matchRate ?? undefined,
  };
}

export function initialChoices(table: PseudonymizeTablePreview): ColumnChoice[] {
  return table.columns.map((plan) => {
    const suggestion = suggestionOf(plan);
    return {
      index: plan.index,
      name: plan.name,
      kind: plan.formula ? "none" : (suggestion?.kind ?? "none"),
      customLabel: suggestion?.customLabel ?? suggestCustomLabel(plan.name),
      suggestion,
      formula: plan.formula,
    };
  });
}

function foldName(name: string): string {
  return name.trim().toLowerCase();
}

function userChanged(choice: ColumnChoice): boolean {
  const suggested = choice.suggestion?.kind ?? "none";
  if (choice.kind !== suggested) return true;
  return choice.kind === "custom" && choice.customLabel !== (choice.suggestion?.customLabel ?? "");
}

function withKind(choice: ColumnChoice, kind: PseudonymizeKindChoice): ColumnChoice {
  if (choice.formula) return choice;
  return {
    ...choice,
    kind,
    previousKind:
      kind !== "none" ? kind : choice.kind !== "none" ? choice.kind : choice.previousKind,
  };
}

function uniqueColumns(choices: ColumnChoice[]): Map<string, ColumnChoice | null> {
  const names = new Map<string, ColumnChoice | null>();
  for (const choice of choices) {
    const name = foldName(choice.name);
    if (name) names.set(name, names.has(name) ? null : choice);
  }
  return names;
}

export function columnsReducer(state: ColumnChoice[], action: ColumnAction): ColumnChoice[] {
  switch (action.type) {
    case "init":
      return initialChoices(action.table);
    case "setSelected":
      return state.map((choice) => {
        if (choice.index !== action.index) return choice;
        return withKind(
          choice,
          action.selected
            ? choice.kind !== "none"
              ? choice.kind
              : (choice.previousKind ?? choice.suggestion?.kind ?? "custom")
            : "none",
        );
      });
    case "setKind":
      return state.map((choice) =>
        choice.index === action.index ? withKind(choice, action.kind) : choice,
      );
    case "setCustomLabel":
      return state.map((choice) =>
        choice.index === action.index ? { ...choice, customLabel: action.label } : choice,
      );
    case "applySuggestions":
      return state.map((choice) =>
        choice.suggestion && !choice.formula
          ? {
              ...withKind(choice, choice.suggestion.kind),
              customLabel: choice.suggestion.customLabel ?? choice.customLabel,
            }
          : choice,
      );
    case "clearAll":
      return state.map((choice) => withKind(choice, "none"));
    case "reinspect": {
      const fresh = initialChoices(action.table);
      if (action.keep === "none") return fresh;
      const sameLayout =
        state.length === fresh.length &&
        state.every(
          (choice, index) =>
            choice.index === fresh[index].index && choice.name === fresh[index].name,
        );
      // Duplicate/blank headers cannot safely be matched by name after a layout change.
      const oldNames = uniqueColumns(state);
      const newNames = uniqueColumns(fresh);
      return fresh.map((choice, index) => {
        const name = foldName(choice.name);
        const candidate = sameLayout
          ? state[index]
          : newNames.get(name)
            ? oldNames.get(name)
            : undefined;
        const previous = candidate && userChanged(candidate) ? candidate : undefined;
        return previous && !choice.formula
          ? {
              ...choice,
              kind: previous.kind,
              customLabel: previous.customLabel,
              previousKind: previous.previousKind,
            }
          : choice;
      });
    }
  }
}

/** Every column is sent by position, so the engine applies exactly this selection. */
export function toRunColumns(choices: ColumnChoice[]): PseudonymizeColumnChoiceDto[] {
  return choices.map((choice) => ({
    index: choice.index,
    name: choice.name,
    kind: choice.kind,
    customLabel: choice.kind === "custom" ? choice.customLabel.trim() : null,
  }));
}

export function selectedCount(choices: ColumnChoice[]): number {
  return choices.filter((choice) => choice.kind !== "none").length;
}

export type ColumnValidationError = { index: number; reason: Exclude<CustomLabelValidity, "ok"> };

export function validationErrors(choices: ColumnChoice[]): ColumnValidationError[] {
  const errors: ColumnValidationError[] = [];
  for (const choice of choices) {
    if (choice.kind !== "custom") continue;
    const validity = validateCustomLabel(choice.customLabel.trim());
    if (validity !== "ok") errors.push({ index: choice.index, reason: validity });
  }
  return errors;
}

export function hasUnappliedSuggestions(choices: ColumnChoice[]): boolean {
  return choices.some(
    (choice) =>
      choice.suggestion &&
      !choice.formula &&
      (choice.kind !== choice.suggestion.kind ||
        (choice.kind === "custom" &&
          choice.suggestion.customLabel !== undefined &&
          choice.customLabel !== choice.suggestion.customLabel)),
  );
}
