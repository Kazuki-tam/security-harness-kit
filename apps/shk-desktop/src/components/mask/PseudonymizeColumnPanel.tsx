import { Check, Loader2 } from "lucide-react";
import { useId, type Dispatch } from "react";
import type { Messages } from "../../i18n/types";
import type { PseudonymizeInspectResult, PseudonymizeKindChoice } from "../../pseudonymize";
import {
  hasUnappliedSuggestions,
  selectedCount,
  type ColumnAction,
  type ColumnChoice,
  type ColumnValidationError,
} from "../../pseudonymizeColumns";
import { Button } from "../Button";

type Props = {
  inspect: PseudonymizeInspectResult;
  columns: ColumnChoice[];
  dispatch: Dispatch<ColumnAction>;
  columnErrors: ColumnValidationError[];
  sheet: string | undefined;
  onSheetChange: (sheet: string) => void;
  disabled: boolean;
  inspecting: boolean;
  messages: Messages["mask"]["pseudonymize"];
  t: (template: string, vars?: Record<string, string | number>) => string;
};

const KIND_ORDER: PseudonymizeKindChoice[] = ["email", "phone", "name", "custom", "none"];

/** One row per column: name, a couple of sample values, and how to treat it. */
export function PseudonymizeColumnPanel({
  inspect,
  columns,
  dispatch,
  columnErrors,
  sheet,
  onSheetChange,
  disabled,
  inspecting,
  messages: m,
  t,
}: Props) {
  const sheetId = useId();
  const table = inspect.table;
  if (!table) return null;

  const selected = selectedCount(columns);
  const errorFor = (index: number) => columnErrors.find((error) => error.index === index);
  const suggestionsPending = hasUnappliedSuggestions(columns);
  const sampleCount = Math.min(2, table.sampleRows.length);

  return (
    <section
      className="grid gap-3 rounded-xl border border-border bg-surface-2/70 p-4 ring-1 ring-inset ring-white/5"
      aria-busy={inspecting}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-white">{m.columnsTitle}</h2>
          <p className="mt-1 text-[12px] text-muted">{m.columnsHint}</p>
        </div>
        {table.sheets.length > 1 && (
          <label htmlFor={sheetId} className="grid gap-1 text-[11px] text-muted">
            <span className="font-semibold tracking-[0.08em] text-white/70 uppercase">
              {m.sheetLabel}
            </span>
            <select
              id={sheetId}
              value={sheet ?? table.selectedSheet ?? ""}
              disabled={disabled}
              onChange={(event) => onSheetChange(event.target.value)}
              className="rounded-lg border border-border-strong bg-canvas/70 px-3 py-1.5 text-[12px] font-medium text-white outline-none transition focus:border-sky-300/70 focus:ring-2 focus:ring-sky-300/20 disabled:opacity-60"
            >
              {table.sheets.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
            <span>{m.sheetHint}</span>
          </label>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border/70 bg-canvas/40 px-3 py-2">
        <p className="text-[12px] font-medium text-white">
          {inspecting ? (
            <span className="inline-flex items-center gap-2 text-sky-100">
              <Loader2 size={14} className="animate-spin" aria-hidden="true" />
              {m.inspecting}
            </span>
          ) : (
            t(m.selectedCount, { count: selected, total: columns.length })
          )}
        </p>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="secondary"
            size="sm"
            disabled={disabled || !suggestionsPending}
            onClick={() => dispatch({ type: "applySuggestions" })}
          >
            {m.applySuggestions}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            disabled={disabled || selected === 0}
            onClick={() => dispatch({ type: "clearAll" })}
          >
            {m.clearSelection}
          </Button>
        </div>
      </div>

      <div className="shk-scroll overflow-x-auto rounded-lg border border-border/70">
        <table className="w-full min-w-[640px] border-collapse text-left text-[12px]">
          <caption className="sr-only">{t(m.tableCaption, { file: inspect.sourceLabel })}</caption>
          <thead className="bg-canvas/60 text-[10px] font-semibold tracking-[0.08em] text-white/70 uppercase">
            <tr>
              <th scope="col" className="w-8 px-3 py-2">
                <span className="sr-only">{m.colSelected}</span>
              </th>
              <th scope="col" className="px-3 py-2">
                {m.colHeader}
              </th>
              <th scope="col" className="px-3 py-2">
                {m.colSamples}
              </th>
              <th scope="col" className="px-3 py-2">
                {m.colKind}
              </th>
              <th scope="col" className="px-3 py-2">
                {m.colSuggestion}
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/70">
            {columns.map((choice) => {
              const active = choice.kind !== "none";
              const error = errorFor(choice.index);
              const samples = table.sampleRows
                .slice(0, sampleCount)
                .map((row) => row[choice.index] ?? "");
              const suggestion = choice.suggestion;
              const suggestionMatches = suggestion ? suggestion.kind === choice.kind : true;
              // Without a header row the engine names columns 0, 1, …; people count from 1.
              const displayName = table.hasHeader ? choice.name : String(choice.index + 1);
              return (
                <tr
                  key={choice.index}
                  className={active ? "bg-sky-500/5" : undefined}
                  data-selected={active ? "true" : "false"}
                >
                  <td className="px-3 py-2 align-top text-sky-200">
                    {active && <Check size={14} aria-hidden="true" />}
                  </td>
                  <th scope="row" className="px-3 py-2 align-top font-medium text-white">
                    {displayName}
                  </th>
                  <td className="px-3 py-2 align-top">
                    <ul className="grid gap-0.5">
                      {samples.length === 0 && (
                        <li className="text-[11px] text-faint">{m.noSamples}</li>
                      )}
                      {samples.map((sample, sampleIndex) => (
                        <li
                          key={sampleIndex}
                          className="max-w-[220px] truncate font-mono text-[11px] text-muted"
                          title={sample}
                        >
                          {sample === "" ? m.noSamples : sample}
                        </li>
                      ))}
                    </ul>
                  </td>
                  <td className="px-3 py-2 align-top">
                    <div className="grid gap-1.5">
                      <select
                        aria-label={t(m.kindSelectLabel, { column: displayName })}
                        value={choice.kind}
                        disabled={disabled || choice.formula}
                        onChange={(event) =>
                          dispatch({
                            type: "setKind",
                            index: choice.index,
                            kind: event.target.value as PseudonymizeKindChoice,
                          })
                        }
                        className="w-full min-w-[180px] rounded-lg border border-border-strong bg-canvas/70 px-2.5 py-1.5 text-[12px] font-medium text-white outline-none transition focus:border-sky-300/70 focus:ring-2 focus:ring-sky-300/20 disabled:opacity-60"
                      >
                        {KIND_ORDER.map((kind) => (
                          <option key={kind} value={kind}>
                            {m.kinds[kind]}
                          </option>
                        ))}
                      </select>
                      {choice.kind === "custom" && (
                        <CustomLabelField
                          choice={choice}
                          error={error}
                          disabled={disabled}
                          dispatch={dispatch}
                          messages={m}
                        />
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2 align-top">
                    {choice.formula && (
                      <span
                        title={m.formulaBadgeTitle}
                        className="inline-flex items-center rounded-md bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium whitespace-nowrap text-amber-100 ring-1 ring-inset ring-amber-400/30"
                      >
                        {m.formulaBadge}
                      </span>
                    )}
                    {!choice.formula &&
                      suggestion &&
                      (suggestion.source === "inferred" || suggestion.source === "config") && (
                        <SuggestionBadge
                          source={suggestion.source}
                          matchRate={suggestion.matchRate}
                          muted={!suggestionMatches}
                          messages={m}
                          t={t}
                        />
                      )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {selected === 0 && !inspecting && (
        <p
          role="note"
          className="rounded-lg border border-amber-400/35 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-100"
        >
          {m.nothingSelected}
        </p>
      )}
    </section>
  );
}

function CustomLabelField({
  choice,
  error,
  disabled,
  dispatch,
  messages: m,
}: {
  choice: ColumnChoice;
  error: ColumnValidationError | undefined;
  disabled: boolean;
  dispatch: Dispatch<ColumnAction>;
  messages: Messages["mask"]["pseudonymize"];
}) {
  const hintId = useId();
  const message = error
    ? error.reason === "reserved"
      ? m.customLabelReserved
      : m.customLabelInvalid
    : m.customLabelHint;
  return (
    <div className="grid gap-1">
      <input
        type="text"
        aria-label={m.customLabelLabel}
        aria-invalid={Boolean(error)}
        aria-describedby={hintId}
        value={choice.customLabel}
        disabled={disabled}
        spellCheck={false}
        onChange={(event) =>
          dispatch({ type: "setCustomLabel", index: choice.index, label: event.target.value })
        }
        className={`w-full rounded-lg border bg-canvas/70 px-2.5 py-1.5 font-mono text-[12px] text-white outline-none transition focus:ring-2 focus:ring-sky-300/20 disabled:opacity-60 ${
          error
            ? "border-red-400/60 focus:border-red-300/80"
            : "border-border-strong focus:border-sky-300/70"
        }`}
      />
      <p id={hintId} className={`text-[10px] ${error ? "text-red-200" : "text-faint"}`}>
        {message}
      </p>
    </div>
  );
}

function SuggestionBadge({
  source,
  matchRate,
  muted,
  messages: m,
  t,
}: {
  source: "config" | "inferred";
  matchRate: number | undefined;
  muted: boolean;
  messages: Messages["mask"]["pseudonymize"];
  t: (template: string, vars?: Record<string, string | number>) => string;
}) {
  const percent = Math.round((matchRate ?? 0) * 100);
  const label = source === "inferred" ? t(m.suggestedBadge, { percent }) : m.configuredBadge;
  const title = source === "inferred" ? t(m.suggestedBadgeTitle, { percent }) : undefined;
  const tone = muted
    ? "bg-surface-3 text-faint ring-border"
    : source === "inferred"
      ? "bg-sky-500/15 text-sky-100 ring-sky-400/30"
      : "bg-emerald-500/15 text-emerald-100 ring-emerald-400/30";
  return (
    <span
      title={title}
      className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-medium whitespace-nowrap ring-1 ring-inset ${tone}`}
    >
      {label}
    </span>
  );
}
