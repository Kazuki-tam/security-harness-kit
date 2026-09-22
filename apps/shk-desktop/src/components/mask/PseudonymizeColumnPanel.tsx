import { Loader2 } from "lucide-react";
import { useId, useLayoutEffect, useRef, type Dispatch } from "react";
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
  noHeader: boolean;
  onNoHeaderChange: (value: boolean) => void;
  messages: Messages["mask"]["pseudonymize"];
  t: (template: string, vars?: Record<string, string | number>) => string;
};

const KIND_ORDER: PseudonymizeKindChoice[] = ["email", "phone", "name", "custom", "none"];

/** Keep the source table orientation so choices line up with the values they affect. */
export function PseudonymizeColumnPanel({
  inspect,
  columns,
  dispatch,
  columnErrors,
  sheet,
  onSheetChange,
  disabled,
  inspecting,
  noHeader,
  onNoHeaderChange,
  messages: m,
  t,
}: Props) {
  const sheetId = useId();
  const table = inspect.table;
  const viewportRef = useRef<HTMLDivElement>(null);
  const tableRef = useRef<HTMLTableElement>(null);

  useLayoutEffect(() => {
    const viewport = viewportRef.current;
    const element = tableRef.current;
    if (!viewport || !element) return;

    const resize = () => {
      const headerHeight = element.tHead?.getBoundingClientRect().height ?? 0;
      const rows = Array.from(element.tBodies[0]?.rows ?? []).slice(0, 5);
      const rowsHeight = rows.reduce(
        (height, row) => height + row.getBoundingClientRect().height,
        0,
      );
      // Include the border and any horizontal scrollbar so all five rows fit.
      const chromeHeight = viewport.offsetHeight - viewport.clientHeight;
      viewport.style.maxHeight = `${headerHeight + rowsHeight + chromeHeight}px`;
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(element);
    if (element.tHead) observer.observe(element.tHead);
    for (const row of Array.from(element.tBodies[0]?.rows ?? []).slice(0, 5)) {
      observer.observe(row);
    }
    return () => observer.disconnect();
  }, [table, columns, columnErrors]);
  if (!table) return null;

  const selected = selectedCount(columns);
  const errorFor = (index: number) => columnErrors.find((error) => error.index === index);
  const suggestionsPending = hasUnappliedSuggestions(columns);
  const locked = disabled || inspecting;

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
              disabled={locked}
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
            disabled={locked || !suggestionsPending}
            onClick={() => dispatch({ type: "applySuggestions" })}
          >
            {m.applySuggestions}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            disabled={locked || selected === 0}
            onClick={() => dispatch({ type: "clearAll" })}
          >
            {m.clearSelection}
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 text-[12px] text-muted">
        <p>{t(m.previewRows, { count: table.sampleRows.length, total: table.rowCount })}</p>
        <label className="inline-flex items-center gap-2">
          <input
            type="checkbox"
            checked={!noHeader}
            disabled={locked}
            onChange={(event) => onNoHeaderChange(!event.target.checked)}
            className="h-4 w-4 accent-sky-400"
          />
          {m.firstRowHeader}
        </label>
      </div>
      <p className="text-[11px] text-muted">{m.previewHint}</p>
      <div
        ref={viewportRef}
        className="shk-sheet shk-scroll overflow-auto rounded-xl border border-slate-300 bg-white text-slate-800 shadow-sm focus-visible:outline-2 focus-visible:outline-sky-600"
        role="region"
        aria-label={t(m.tableCaption, { file: inspect.sourceLabel })}
        tabIndex={0}
      >
        <table
          ref={tableRef}
          className="w-full border-separate border-spacing-0 text-left text-[12px]"
        >
          <caption className="sr-only">{t(m.tableCaption, { file: inspect.sourceLabel })}</caption>
          <thead className="sticky top-0 z-10 bg-slate-50 text-slate-800">
            <tr>
              <th
                scope="col"
                className="sticky left-0 z-20 w-10 border-b border-slate-300 bg-slate-100 px-3 py-3 text-center align-top font-medium text-slate-500"
              >
                <span className="sr-only">{m.rowNumber}</span>#
              </th>
              {columns.map((choice) => {
                const active = choice.kind !== "none";
                const displayName =
                  table.hasHeader && choice.name ? choice.name : String(choice.index + 1);
                const suggestion = choice.suggestion;
                return (
                  <th
                    key={choice.index}
                    scope="col"
                    data-selected={active ? "true" : "false"}
                    className={`min-w-[220px] max-w-[300px] border-b border-l border-slate-300 px-3 py-3 align-top font-normal shadow-[inset_0_3px_0_var(--column-accent)] ${active ? "bg-blue-50 [--column-accent:var(--color-sky-600)]" : "bg-slate-50 [--column-accent:transparent]"}`}
                  >
                    <div className="grid gap-2">
                      <label className="flex cursor-pointer items-start gap-2 font-semibold">
                        <input
                          type="checkbox"
                          checked={active}
                          disabled={locked || choice.formula}
                          aria-label={t(m.selectColumn, {
                            column: displayName,
                            number: choice.index + 1,
                          })}
                          onChange={(event) =>
                            dispatch({
                              type: "setSelected",
                              index: choice.index,
                              selected: event.target.checked,
                            })
                          }
                          className="mt-0.5 h-4 w-4 shrink-0 accent-sky-700"
                        />
                        <span className="break-words">{displayName}</span>
                        <span className="ml-auto shrink-0 rounded bg-white/80 px-1.5 py-0.5 text-[10px] font-medium tabular-nums text-slate-500 ring-1 ring-slate-200">
                          #{choice.index + 1}
                        </span>
                      </label>
                      <select
                        aria-label={t(m.kindSelectLabel, { column: displayName })}
                        value={choice.kind}
                        disabled={locked || choice.formula}
                        onChange={(event) =>
                          dispatch({
                            type: "setKind",
                            index: choice.index,
                            kind: event.target.value as PseudonymizeKindChoice,
                          })
                        }
                        className="w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-[12px] text-slate-800 shadow-sm outline-none focus:border-sky-600 focus:ring-2 focus:ring-sky-600/20 disabled:bg-slate-100 disabled:text-slate-500"
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
                          error={errorFor(choice.index)}
                          disabled={locked}
                          dispatch={dispatch}
                          messages={m}
                        />
                      )}
                      {choice.formula ? (
                        <span title={m.formulaBadgeTitle} className="text-[11px] text-amber-800">
                          {m.formulaBadge}
                        </span>
                      ) : suggestion &&
                        (suggestion.source === "inferred" || suggestion.source === "config") ? (
                        <SuggestionBadge
                          source={suggestion.source}
                          matchRate={suggestion.matchRate}
                          muted={suggestion.kind !== choice.kind}
                          messages={m}
                          t={t}
                        />
                      ) : null}
                    </div>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {table.sampleRows.map((row, rowIndex) => (
              <tr key={rowIndex} className="group">
                <th
                  scope="row"
                  className="sticky left-0 z-[1] border-b border-slate-200 bg-slate-50 px-3 py-2.5 text-center align-top font-normal tabular-nums text-slate-500 group-hover:bg-slate-100"
                >
                  {rowIndex + 1}
                </th>
                {columns.map((choice) => (
                  <td
                    key={choice.index}
                    data-selected={choice.kind !== "none" ? "true" : "false"}
                    className={`max-w-[300px] border-b border-l border-slate-200 px-3 py-2.5 align-top text-slate-800 transition-colors ${choice.kind !== "none" ? "bg-blue-50/60 group-hover:bg-blue-100/70" : "bg-white group-hover:bg-slate-50"}`}
                  >
                    <div
                      title={row[choice.index] || undefined}
                      className="line-clamp-4 whitespace-pre-wrap break-words text-[12px] leading-5 tabular-nums"
                    >
                      {row[choice.index] || m.noSamples}
                    </div>
                  </td>
                ))}
              </tr>
            ))}
            {table.sampleRows.length === 0 && (
              <tr>
                <td colSpan={columns.length + 1} className="p-4 text-slate-600">
                  {m.noPreviewRows}
                </td>
              </tr>
            )}
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
        className={`w-full rounded-md border bg-white px-2.5 py-1.5 font-mono text-[12px] text-slate-800 shadow-sm outline-none transition focus:ring-2 focus:ring-sky-600/20 disabled:bg-slate-100 disabled:text-slate-500 ${
          error ? "border-red-500 focus:border-red-600" : "border-slate-300 focus:border-sky-600"
        }`}
      />
      <p id={hintId} className={`text-[10px] ${error ? "text-red-700" : "text-slate-600"}`}>
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
    ? "bg-slate-100 text-slate-600 ring-slate-200"
    : source === "inferred"
      ? "bg-sky-100 text-sky-900 ring-sky-200"
      : "bg-emerald-50 text-emerald-800 ring-emerald-200";
  return (
    <span
      title={title}
      className={`inline-flex w-fit items-center rounded-md px-1.5 py-0.5 text-[10px] font-medium whitespace-nowrap ring-1 ring-inset ${tone}`}
    >
      {label}
    </span>
  );
}
