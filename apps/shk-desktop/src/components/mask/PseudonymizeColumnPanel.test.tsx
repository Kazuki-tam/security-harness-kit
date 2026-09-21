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
        },
        {
          index: 1,
          name: "Member ID",
          kind: "custom",
          customLabel: "member",
          source: "config",
          matchRate: null,
        },
        {
          index: 2,
          name: "Note",
          kind: "none",
          customLabel: null,
          source: "none",
          matchRate: null,
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
}: {
  inspect: PseudonymizeInspectResult;
  onSheetChange?: (sheet: string) => void;
  inspecting?: boolean;
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
    expect(screen.queryByText("sample-c")).not.toBeInTheDocument();
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

  it("shows numbered columns and the reading state", () => {
    renderPanel({
      inspect: preview({ hasHeader: false, headers: ["0", "1", "2"] }),
      inspecting: true,
    });
    expect(screen.getByRole("rowheader", { name: "1" })).toBeInTheDocument();
    expect(screen.getByText("Reading columns…")).toBeInTheDocument();
  });
});
