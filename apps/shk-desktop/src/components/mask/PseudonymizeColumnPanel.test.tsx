// @vitest-environment jsdom
import { fireEvent, render, screen, within } from "@testing-library/react";
import { useReducer } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider, useI18n } from "../../i18n";
import type { PseudonymizeInspectResult, PseudonymizeTablePreview } from "../../pseudonymize";
import { columnsReducer, initialChoices, validationErrors } from "../../pseudonymizeColumns";
import { PseudonymizeColumnPanel } from "./PseudonymizeColumnPanel";

function preview(overrides: Partial<PseudonymizeTablePreview> = {}): PseudonymizeInspectResult {
  return {
    inputKind: "table-csv",
    sourceLabel: "orders.csv",
    table: {
      hasHeader: true,
      delimiter: ",",
      headers: ["Mail", "Member ID", "Note"],
      sampleRows: [
        ["sample-a", "m-1", "first"],
        ["sample-b", "m-2", ""],
        ["sample-c", "m-3", "third"],
      ],
      rowCount: 12,
      columns: [
        {
          index: 0,
          name: "Mail",
          kind: "email",
          customLabel: null,
          source: "inferred",
          matchRate: 0.9,
          formula: false,
        },
        {
          index: 1,
          name: "Member ID",
          kind: "custom",
          customLabel: "member",
          source: "config",
          matchRate: null,
          formula: false,
        },
        {
          index: 2,
          name: "Note",
          kind: "none",
          customLabel: null,
          source: "none",
          matchRate: null,
          formula: false,
        },
      ],
      sheets: [],
      selectedSheet: null,
      ...overrides,
    },
  };
}

function Harness({
  inspect,
  onSheetChange = () => {},
  inspecting = false,
  onNoHeaderChange = () => {},
}: {
  inspect: PseudonymizeInspectResult;
  onSheetChange?: (sheet: string) => void;
  inspecting?: boolean;
  onNoHeaderChange?: (value: boolean) => void;
}) {
  const { messages, t } = useI18n();
  const [columns, dispatch] = useReducer(columnsReducer, inspect.table!, initialChoices);
  return (
    <PseudonymizeColumnPanel
      inspect={inspect}
      columns={columns}
      dispatch={dispatch}
      columnErrors={validationErrors(columns)}
      sheet={undefined}
      onSheetChange={onSheetChange}
      disabled={false}
      inspecting={inspecting}
      noHeader={!inspect.table!.hasHeader}
      onNoHeaderChange={onNoHeaderChange}
      messages={messages.mask.pseudonymize}
      t={t}
    />
  );
}

function renderPanel(props: Parameters<typeof Harness>[0]) {
  return render(
    <I18nProvider>
      <Harness {...props} />
    </I18nProvider>,
  );
}

describe("PseudonymizeColumnPanel", () => {
  beforeEach(() => {
    window.localStorage.setItem("shk.desktop.locale.v1", "en");
  });

  it("lists every column with samples, a choice, and the suggestion", () => {
    renderPanel({ inspect: preview() });

    const table = screen.getByRole("table", { name: "Columns in orders.csv" });
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(screen.getByRole("combobox", { name: "How to treat Mail" })).toHaveValue("email");
    expect(screen.getByRole("combobox", { name: "How to treat Member ID" })).toHaveValue("custom");
    expect(screen.getByRole("combobox", { name: "How to treat Note" })).toHaveValue("none");
    expect(screen.getByText("Auto-detected 90%")).toBeInTheDocument();
    expect(screen.getByText("Project setting")).toBeInTheDocument();
    expect(screen.getByText("sample-a")).toBeInTheDocument();
    expect(screen.getByText("sample-b")).toBeInTheDocument();
    expect(screen.getByText("sample-c")).toBeInTheDocument();
    expect(screen.getByText("2 of 3 columns will be pseudonymized")).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Label" })).toHaveValue("member");
    expect(screen.queryByRole("combobox", { name: "Sheet" })).not.toBeInTheDocument();
  });

  it("validates custom labels and lets the toolbar reset or restore choices", () => {
    renderPanel({ inspect: preview() });

    fireEvent.change(screen.getByRole("combobox", { name: "How to treat Note" }), {
      target: { value: "custom" },
    });
    const labels = screen.getAllByRole("textbox", { name: "Label" });
    expect(labels).toHaveLength(2);
    expect(labels[1]).toHaveValue("note");
    fireEvent.change(labels[1], { target: { value: "Bad Label" } });
    expect(labels[1]).toHaveAttribute("aria-invalid", "true");
    expect(
      screen.getByText(/Start with a lowercase letter and use only lowercase letters/),
    ).toBeInTheDocument();
    fireEvent.change(labels[1], { target: { value: "email" } });
    expect(screen.getByText("This label is reserved. Choose another.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: 'Set all to "Leave as is"' }));
    expect(screen.getByText("0 of 3 columns will be pseudonymized")).toBeInTheDocument();
    expect(screen.getByRole("note")).toHaveTextContent("No columns selected");

    fireEvent.click(screen.getByRole("button", { name: "Use all suggestions" }));
    expect(screen.getByText("2 of 3 columns will be pseudonymized")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Use all suggestions" })).toBeDisabled();
  });

  it("offers the sheet picker only for multi-sheet workbooks", () => {
    const onSheetChange = vi.fn();
    renderPanel({
      inspect: preview({ sheets: ["Customers", "Archive"], selectedSheet: "Customers" }),
      onSheetChange,
    });
    const sheet = screen.getByRole("combobox", { name: /Sheet/ });
    expect(sheet).toHaveValue("Customers");
    fireEvent.change(sheet, { target: { value: "Archive" } });
    expect(onSheetChange).toHaveBeenCalledWith("Archive");
  });

  it("marks formula columns and keeps them unselectable", () => {
    const withFormula = preview();
    withFormula.table!.columns[2] = { ...withFormula.table!.columns[2], formula: true };
    renderPanel({ inspect: withFormula });
    expect(screen.getByText("Formula (kept as is)")).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "How to treat Note" })).toBeDisabled();
  });

  it("shows numbered columns and the reading state", () => {
    renderPanel({
      inspect: preview({ hasHeader: false, headers: ["0", "1", "2"] }),
      inspecting: true,
    });
    expect(screen.getByRole("checkbox", { name: "Pseudonymize 1 (column 1)" })).toBeDisabled();
    expect(screen.getByText("Reading columns…")).toBeInTheDocument();
  });
  it("selects columns from the preview and preserves the chosen kind when toggled", () => {
    renderPanel({ inspect: preview() });
    const mail = screen.getByRole("checkbox", { name: "Pseudonymize Mail (column 1)" });
    const note = screen.getByRole("checkbox", { name: "Pseudonymize Note (column 3)" });
    expect(mail).toBeChecked();
    expect(note).not.toBeChecked();
    fireEvent.click(note);
    expect(screen.getByRole("combobox", { name: "How to treat Note" })).toHaveValue("custom");
    fireEvent.change(screen.getByRole("combobox", { name: "How to treat Note" }), {
      target: { value: "name" },
    });
    fireEvent.click(note);
    fireEvent.click(note);
    expect(screen.getByRole("combobox", { name: "How to treat Note" })).toHaveValue("name");
    expect(screen.getByText("3 of 3 columns will be pseudonymized")).toBeInTheDocument();
    const rows = within(screen.getByRole("table")).getAllByRole("row");
    expect(
      within(rows[1])
        .getAllByRole("cell")
        .map((cell) => cell.textContent),
    ).toEqual(["sample-a", "m-1", "first"]);
  });

  it("keeps duplicate headers individually selectable by position", () => {
    const inspect = preview({ headers: ["Mail", "Mail", "Note"] });
    inspect.table!.columns[1].name = "Mail";
    renderPanel({ inspect });
    fireEvent.click(screen.getByRole("checkbox", { name: "Pseudonymize Mail (column 2)" }));
    expect(screen.getByRole("checkbox", { name: "Pseudonymize Mail (column 1)" })).toBeChecked();
    expect(
      screen.getByRole("checkbox", { name: "Pseudonymize Mail (column 2)" }),
    ).not.toBeChecked();
  });

  it("renders markup in input as text", () => {
    renderPanel({ inspect: preview({ sampleRows: [["<img src=x onerror=alert(1)>", "", ""]] }) });
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });
  it.each(["csv", "tsv", "xlsx"])("shows a row-oriented preview for %s", (extension) => {
    const inspect = preview();
    inspect.sourceLabel = `demo.${extension}`;
    inspect.inputKind = extension === "xlsx" ? "table-xlsx" : "table-csv";
    renderPanel({ inspect });
    expect(screen.getByRole("table", { name: `Columns in demo.${extension}` })).toBeInTheDocument();
    expect(screen.getByText("Showing the first 3 of 12 rows")).toBeInTheDocument();
  });

  it("changes header interpretation next to the preview", () => {
    const onNoHeaderChange = vi.fn();
    renderPanel({ inspect: preview(), onNoHeaderChange });
    fireEvent.click(screen.getByRole("checkbox", { name: "Use the first row as column names" }));
    expect(onNoHeaderChange).toHaveBeenCalledWith(true);
  });

  it("explains an empty table and locks every control while reloading", () => {
    renderPanel({ inspect: preview({ sampleRows: [] }), inspecting: true });
    expect(
      screen.getByText("No data rows to preview. Check the header setting."),
    ).toBeInTheDocument();
    for (const control of [
      ...screen.getAllByRole("checkbox"),
      ...screen.getAllByRole("combobox"),
    ]) {
      expect(control).toBeDisabled();
    }
  });
});
