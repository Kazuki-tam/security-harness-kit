// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { I18nProvider } from "./i18n";

const invokeMock = vi.fn();
const openMock = vi.fn();
const saveMock = vi.fn();
const webviewMock = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: (...args: unknown[]) => openMock(...args),
  save: (...args: unknown[]) => saveMock(...args),
}));

vi.mock("@tauri-apps/api/webview", () => ({
  getCurrentWebview: () => {
    webviewMock();
    return {
      onDragDropEvent: vi.fn().mockResolvedValue(() => undefined),
    };
  },
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

vi.mock("@tauri-apps/plugin-notification", () => ({
  isPermissionGranted: vi.fn().mockResolvedValue(true),
  requestPermission: vi.fn().mockResolvedValue("granted"),
  sendNotification: vi.fn(),
}));

const DEMO_PROJECT = {
  id: "p1",
  name: "Demo",
  path: "/tmp/demo",
  addedAt: "2026-01-01T00:00:00.000Z",
};

const TABLE_PREVIEW = {
  inputKind: "table-csv",
  sourceLabel: "orders.csv",
  table: {
    hasHeader: true,
    delimiter: ",",
    headers: ["Mail", "Note"],
    sampleRows: [["sample-a", "memo"]],
    rowCount: 2,
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
  },
};

const RUN_RESULT = {
  mode: "table",
  rowsProcessed: 2,
  replaced: { email: 2 },
  unparsed: {},
  columns: [TABLE_PREVIEW.table.columns[0]],
  keyFingerprint: "0123abcd",
  outputPath: "/tmp/demo/orders.pseudo.csv",
  metaPath: "/tmp/demo/orders.pseudo.csv.shk-meta.json",
  mapPath: null,
  inlineOutput: null,
  remainingRuleIds: [],
  remainingCheckError: null,
};

function seedProject() {
  window.localStorage.setItem("shk.desktop.projects.v1", JSON.stringify([DEMO_PROJECT]));
  window.localStorage.setItem("shk.desktop.selectedProjectId.v1", DEMO_PROJECT.id);
}

function mockPseudonymizeCommands(overrides: { keyExists?: boolean } = {}) {
  invokeMock.mockImplementation(async (command: string) => {
    switch (command) {
      case "mask_policy_status":
        return { usesProjectPolicy: true, policyPath: "/tmp/demo/shk.toml" };
      case "pseudonymize_inspect":
        return TABLE_PREVIEW;
      case "pseudonymize_key_status":
        return {
          exists: overrides.keyExists ?? false,
          backend: "OS credential store",
          fingerprint: null,
          unavailableReason: null,
        };
      case "pseudonymize_run":
        return RUN_RESULT;
      default:
        return undefined;
    }
  });
}

function openMaskWorkspace() {
  render(
    <I18nProvider>
      <App />
    </I18nProvider>,
  );
  // The sidebar button carries a keyboard hint in its name once a project exists.
  fireEvent.click(screen.getAllByRole("button", { name: /Mask for AI/ })[0]);
}

async function chooseFileForPseudonymize(path: string) {
  fireEvent.click(screen.getByRole("radio", { name: /Pseudonymize/ }));
  fireEvent.click(screen.getByRole("button", { name: "Upload file" }));
  openMock.mockResolvedValue(path);
  fireEvent.click(screen.getByRole("button", { name: /Choose file/ }));
  return screen.findByRole("table");
}

describe("App", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    openMock.mockReset();
    saveMock.mockReset();
    // Commands are promises in the app; a bare `vi.fn()` would return
    // undefined and break fire-and-forget callers such as the audit watcher.
    invokeMock.mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
    window.localStorage.clear();
    window.localStorage.setItem("shk.desktop.locale.v1", "en");
  });

  it("opens Mask for AI without a project", () => {
    render(
      <I18nProvider>
        <App />
      </I18nProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: "Mask for AI" }));

    expect(screen.getByRole("heading", { name: "Mask for AI" })).toBeInTheDocument();
  });

  it("keeps the mask screen usable without a native webview and can return home", async () => {
    webviewMock.mockImplementationOnce(() => {
      throw new Error("No native webview");
    });
    render(
      <I18nProvider>
        <App />
      </I18nProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Mask for AI" }));
    await waitFor(() => expect(webviewMock).toHaveBeenCalled());
    expect(screen.getByRole("textbox", { name: "Input" })).toHaveAttribute("spellcheck", "false");
    fireEvent.click(screen.getByRole("button", { name: "Back to welcome" }));
    expect(screen.getByRole("button", { name: "Open project" })).toBeInTheDocument();
  });

  it.each([
    ["medium", "1 item(s) masked — review the output before sharing"],
    ["high", "1 item(s) need review before sharing"],
  ])("describes a %s finding without marking masked output as safe", async (severity, expected) => {
    invokeMock.mockResolvedValue({
      masked_content: "contact=[REDACTED]",
      findings: [
        {
          rule_id: "pii.email",
          severity,
          kind: "pii",
          file: "<input>",
          line: 1,
          column: 9,
          message: "Possible email address detected",
          redacted_value: "[REDACTED]",
          confidence: 0.95,
        },
      ],
    });

    render(
      <I18nProvider>
        <App />
      </I18nProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: "Mask for AI" }));
    fireEvent.change(screen.getByPlaceholderText("Paste prompt text, logs, or notes here…"), {
      target: { value: "synthetic sensitive input" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Mask" }));

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent(expected);
    });
    expect(screen.getByRole("textbox", { name: "Masked output" })).toHaveValue(
      "contact=[REDACTED]",
    );
    expect(
      screen.queryByText("No high-risk items detected — safe to copy"),
    ).not.toBeInTheDocument();
  });

  it("reports clipboard failures to the user", async () => {
    invokeMock.mockResolvedValue({
      masked_content: "[REDACTED]",
      findings: [],
    });
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockRejectedValue(new Error("clipboard denied")) },
    });

    render(
      <I18nProvider>
        <App />
      </I18nProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: "Mask for AI" }));
    fireEvent.change(screen.getByPlaceholderText("Paste prompt text, logs, or notes here…"), {
      target: { value: "synthetic sensitive input" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Mask" }));
    await screen.findByRole("textbox", { name: "Masked output" });

    fireEvent.click(screen.getByRole("button", { name: "Copy masked text" }));

    expect(
      await screen.findByText("Could not copy to clipboard: clipboard denied"),
    ).toBeInTheDocument();
  });

  it("pseudonymizes a table with the user's column choices after confirming the key", async () => {
    seedProject();
    mockPseudonymizeCommands();
    openMaskWorkspace();

    await chooseFileForPseudonymize("/tmp/demo/orders.csv");
    expect(invokeMock).toHaveBeenCalledWith("pseudonymize_inspect", {
      projectPath: "/tmp/demo",
      options: expect.objectContaining({ inputPath: "/tmp/demo/orders.csv" }),
    });
    expect(screen.getByText("Auto-detected 90%")).toBeInTheDocument();

    fireEvent.change(screen.getByRole("combobox", { name: "How to treat Note" }), {
      target: { value: "name" },
    });
    saveMock.mockResolvedValue("/tmp/demo/orders.pseudo.csv");
    fireEvent.click(screen.getByRole("button", { name: "Pseudonymize and save…" }));

    await waitFor(() => {
      expect(saveMock).toHaveBeenCalledWith(
        expect.objectContaining({ defaultPath: "/tmp/demo/orders.pseudo.csv" }),
      );
    });
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("Create a pseudonymize key for Demo?");
    fireEvent.click(within(dialog).getByRole("button", { name: "Create key and continue" }));

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("pseudonymize_run", {
        projectPath: "/tmp/demo",
        options: expect.objectContaining({
          inputPath: "/tmp/demo/orders.csv",
          outputPath: "/tmp/demo/orders.pseudo.csv",
          createKey: true,
          columns: [
            { index: 0, name: "Mail", kind: "email", customLabel: null },
            { index: 1, name: "Note", kind: "name", customLabel: null },
          ],
        }),
      });
    });
    const heading = await screen.findByRole("heading", { name: "Pseudonymized" });
    expect(heading).toHaveFocus();
    expect(screen.getByText("2 rows processed")).toBeInTheDocument();
    expect(screen.getByText("Email address: 2")).toBeInTheDocument();
    expect(screen.getByText("/tmp/demo/orders.pseudo.csv")).toBeInTheDocument();
    expect(screen.queryByText("Restore map (keep private)")).not.toBeInTheDocument();
  });

  it("does not run when the save dialog is cancelled and skips the key dialog when a key exists", async () => {
    seedProject();
    mockPseudonymizeCommands({ keyExists: true });
    openMaskWorkspace();
    await chooseFileForPseudonymize("/tmp/demo/orders.csv");

    saveMock.mockResolvedValue(null);
    fireEvent.click(screen.getByRole("button", { name: "Pseudonymize and save…" }));
    await waitFor(() => expect(saveMock).toHaveBeenCalled());
    expect(invokeMock).not.toHaveBeenCalledWith("pseudonymize_run", expect.anything());
    expect(screen.getByRole("table")).toBeInTheDocument();

    saveMock.mockResolvedValue("/tmp/demo/orders.pseudo.csv");
    fireEvent.click(screen.getByRole("button", { name: "Pseudonymize and save…" }));
    await screen.findByRole("heading", { name: "Pseudonymized" });
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith("pseudonymize_run", {
      projectPath: "/tmp/demo",
      options: expect.objectContaining({ createKey: false }),
    });
  });

  it("returns pasted text in place", async () => {
    seedProject();
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "mask_policy_status") {
        return { usesProjectPolicy: true, policyPath: "/tmp/demo/shk.toml" };
      }
      if (command === "pseudonymize_key_status") {
        return {
          exists: true,
          backend: "OS credential store",
          fingerprint: "x",
          unavailableReason: null,
        };
      }
      if (command === "pseudonymize_run") {
        return {
          ...RUN_RESULT,
          mode: "text",
          rowsProcessed: 1,
          outputPath: null,
          metaPath: null,
          inlineOutput: "contact email_abc",
        };
      }
      return undefined;
    });
    openMaskWorkspace();
    fireEvent.click(screen.getByRole("radio", { name: /Pseudonymize/ }));
    fireEvent.change(
      screen.getByPlaceholderText(
        "Paste text that contains names, email addresses, or phone numbers…",
      ),
      { target: { value: "contact someone" } },
    );
    // The project's policy status arrives asynchronously and gates the run.
    const run = screen.getByRole("button", { name: "Pseudonymize" });
    await waitFor(() => expect(run).toBeEnabled());
    fireEvent.click(run);

    expect(await screen.findByRole("textbox", { name: "Pseudonymized text" })).toHaveValue(
      "contact email_abc",
    );
    expect(saveMock).not.toHaveBeenCalled();
    expect(invokeMock).toHaveBeenCalledWith("pseudonymize_run", {
      projectPath: "/tmp/demo",
      options: expect.objectContaining({ inlineText: "contact someone", mode: "text" }),
    });
  });

  it("keeps column choices while a pasted table is edited", async () => {
    seedProject();
    mockPseudonymizeCommands({ keyExists: true });
    openMaskWorkspace();
    fireEvent.click(screen.getByRole("radio", { name: /Pseudonymize/ }));
    fireEvent.change(screen.getByRole("combobox", { name: "Pasted content is" }), {
      target: { value: "csv" },
    });
    const textarea = screen.getByPlaceholderText(
      "Paste text that contains names, email addresses, or phone numbers…",
    );
    fireEvent.change(textarea, { target: { value: "Mail,Note\nsample-a,memo" } });

    await screen.findByRole("table");
    fireEvent.change(screen.getByRole("combobox", { name: "How to treat Note" }), {
      target: { value: "name" },
    });

    // Editing the text re-plans after a pause; the user's choice survives.
    fireEvent.change(textarea, { target: { value: "Mail,Note\nsample-a,memo\nsample-b,more" } });
    await waitFor(() => {
      expect(
        invokeMock.mock.calls.filter(([command]) => command === "pseudonymize_inspect"),
      ).toHaveLength(2);
    });
    expect(screen.getByRole("combobox", { name: "How to treat Note" })).toHaveValue("name");
    expect(invokeMock).toHaveBeenLastCalledWith("pseudonymize_inspect", {
      projectPath: "/tmp/demo",
      options: expect.objectContaining({ mode: "table", format: "csv" }),
    });
  });

  it("disables the run button when the plan fails and offers a retry", async () => {
    seedProject();
    let inspectCalls = 0;
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "mask_policy_status") {
        return { usesProjectPolicy: true, policyPath: "/tmp/demo/shk.toml" };
      }
      if (command === "pseudonymize_inspect") {
        inspectCalls += 1;
        if (inspectCalls === 1) throw new Error("input changed");
        return TABLE_PREVIEW;
      }
      return undefined;
    });
    openMaskWorkspace();
    fireEvent.click(screen.getByRole("radio", { name: /Pseudonymize/ }));
    fireEvent.click(screen.getByRole("button", { name: "Upload file" }));
    openMock.mockResolvedValue("/tmp/demo/orders.csv");
    fireEvent.click(screen.getByRole("button", { name: /Choose file/ }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Could not read the content: input changed");
    expect(screen.getByRole("button", { name: "Pseudonymize and save…" })).toBeDisabled();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Try reading again" }));
    await screen.findByRole("table");
    expect(screen.getByRole("button", { name: "Pseudonymize and save…" })).toBeEnabled();
    expect(saveMock).not.toHaveBeenCalled();
  });

  it("drops an unsupported file when switching to pseudonymize", async () => {
    seedProject();
    mockPseudonymizeCommands();
    openMaskWorkspace();
    fireEvent.click(screen.getByRole("button", { name: "Upload file" }));
    openMock.mockResolvedValue("/tmp/demo/scan.pdf");
    fireEvent.click(screen.getByRole("button", { name: /Choose file/ }));
    await screen.findByRole("button", { name: "Remove file" });

    fireEvent.click(screen.getByRole("radio", { name: /Pseudonymize/ }));
    expect(await screen.findByText(/This file type cannot be pseudonymized/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove file" })).not.toBeInTheDocument();
    expect(invokeMock).not.toHaveBeenCalledWith("pseudonymize_inspect", expect.anything());
  });

  it("recovers when the input changes while a run is in flight", async () => {
    seedProject();
    let finishRun: (value: unknown) => void = () => {};
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "mask_policy_status") {
        return { usesProjectPolicy: true, policyPath: "/tmp/demo/shk.toml" };
      }
      if (command === "pseudonymize_key_status") {
        return {
          exists: true,
          backend: "OS credential store",
          fingerprint: "x",
          unavailableReason: null,
        };
      }
      if (command === "pseudonymize_run") {
        return new Promise((resolve) => {
          finishRun = resolve;
        });
      }
      return undefined;
    });
    openMaskWorkspace();
    fireEvent.click(screen.getByRole("radio", { name: /Pseudonymize/ }));
    const textarea = screen.getByPlaceholderText(
      "Paste text that contains names, email addresses, or phone numbers…",
    );
    fireEvent.change(textarea, { target: { value: "first draft" } });
    const run = screen.getByRole("button", { name: "Pseudonymize" });
    await waitFor(() => expect(run).toBeEnabled());
    fireEvent.click(run);
    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith("pseudonymize_run", expect.anything()),
    );

    // The content is frozen while running; "Clear" replaces it once unlocked.
    expect(textarea).toBeDisabled();
    finishRun({
      ...RUN_RESULT,
      mode: "text",
      inlineOutput: "email_abc",
      outputPath: null,
      metaPath: null,
    });
    await screen.findByRole("textbox", { name: "Pseudonymized text" });
    fireEvent.change(textarea, { target: { value: "second draft" } });
    expect(screen.queryByRole("textbox", { name: "Pseudonymized text" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Pseudonymize" })).toBeEnabled();
  });

  it("clears the sheet and plan when another file is chosen, and start over returns to step 1", async () => {
    seedProject();
    invokeMock.mockImplementation(
      async (command: string, args?: { options?: { sheet?: string } }) => {
        if (command === "mask_policy_status") {
          return { usesProjectPolicy: true, policyPath: "/tmp/demo/shk.toml" };
        }
        if (command === "pseudonymize_inspect") {
          return {
            ...TABLE_PREVIEW,
            inputKind: "table-xlsx",
            table: {
              ...TABLE_PREVIEW.table,
              sheets: ["Customers", "Archive"],
              selectedSheet: args?.options?.sheet ?? "Customers",
            },
          };
        }
        if (command === "pseudonymize_key_status") {
          return {
            exists: true,
            backend: "OS credential store",
            fingerprint: "x",
            unavailableReason: null,
          };
        }
        if (command === "pseudonymize_run") return RUN_RESULT;
        return undefined;
      },
    );
    openMaskWorkspace();
    await chooseFileForPseudonymize("/tmp/demo/a.xlsx");
    fireEvent.change(screen.getByRole("combobox", { name: /Sheet/ }), {
      target: { value: "Archive" },
    });
    await waitFor(() => {
      expect(invokeMock).toHaveBeenLastCalledWith("pseudonymize_inspect", {
        projectPath: "/tmp/demo",
        options: expect.objectContaining({ sheet: "Archive" }),
      });
    });

    openMock.mockResolvedValue("/tmp/demo/b.xlsx");
    fireEvent.click(screen.getByRole("button", { name: "Choose file" }));
    await waitFor(() => {
      expect(invokeMock).toHaveBeenLastCalledWith("pseudonymize_inspect", {
        projectPath: "/tmp/demo",
        options: { inputPath: "/tmp/demo/b.xlsx", sheet: undefined, noHeader: false },
      });
    });

    saveMock.mockResolvedValue("/tmp/demo/b.pseudo.xlsx");
    fireEvent.click(screen.getByRole("button", { name: "Pseudonymize and save…" }));
    await screen.findByRole("heading", { name: "Pseudonymized" });
    fireEvent.click(screen.getByRole("button", { name: "Start over" }));
    expect(screen.queryByRole("heading", { name: "Pseudonymized" })).not.toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.getByRole("listitem", { current: "step" })).toHaveTextContent("Add content");
  });

  it("re-reads a file that is chosen again and ignores clicks on the active tab", async () => {
    seedProject();
    mockPseudonymizeCommands({ keyExists: true });
    openMaskWorkspace();
    await chooseFileForPseudonymize("/tmp/demo/orders.csv");
    fireEvent.change(screen.getByRole("combobox", { name: "How to treat Note" }), {
      target: { value: "name" },
    });

    // Clicking the tab that is already active must not discard the plan.
    fireEvent.click(screen.getByRole("button", { name: "Upload file" }));
    expect(screen.getByRole("combobox", { name: "How to treat Note" })).toHaveValue("name");

    // Choosing the same file again (after editing it elsewhere) plans afresh.
    openMock.mockResolvedValue("/tmp/demo/orders.csv");
    fireEvent.click(screen.getByRole("button", { name: "Choose file" }));
    await waitFor(() => {
      expect(
        invokeMock.mock.calls.filter(([command]) => command === "pseudonymize_inspect"),
      ).toHaveLength(2);
    });
    expect(await screen.findByRole("combobox", { name: "How to treat Note" })).toHaveValue("none");
    expect(screen.getByRole("button", { name: "Pseudonymize and save…" })).toBeEnabled();
  });

  it("gates pseudonymize until a project with shk.toml is selected", async () => {
    openMaskWorkspace();
    fireEvent.click(screen.getByRole("radio", { name: /Pseudonymize/ }));

    expect(screen.getByRole("note")).toHaveTextContent("Choose a project to pseudonymize");
    fireEvent.change(
      screen.getByPlaceholderText(
        "Paste text that contains names, email addresses, or phone numbers…",
      ),
      { target: { value: "hello" } },
    );
    expect(screen.getByRole("button", { name: "Pseudonymize" })).toBeDisabled();
    expect(invokeMock).not.toHaveBeenCalledWith("pseudonymize_inspect", expect.anything());
    expect(invokeMock).not.toHaveBeenCalledWith("pseudonymize_run", expect.anything());
  });
});
