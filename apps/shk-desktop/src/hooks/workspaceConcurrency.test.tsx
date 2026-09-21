// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { save } from "@tauri-apps/plugin-dialog";
import { openAiTool } from "../aiTool";
import { I18nProvider } from "../i18n";
import { maskContent, maskFile } from "../mask";
import { pseudonymizeKeyStatus, pseudonymizeRun } from "../pseudonymize";
import { useMaskInput } from "./useMaskInput";
import { useMaskWorkspace } from "./useMaskWorkspace";
import { usePseudonymizeWorkspace } from "./usePseudonymizeWorkspace";

vi.mock("@tauri-apps/plugin-dialog", () => ({ save: vi.fn(), open: vi.fn() }));
vi.mock("../aiTool", () => ({ openAiTool: vi.fn() }));
const noticeMock = vi.fn();
const clipboardMock = vi.fn();
vi.mock("../mask", async (original) => ({
  ...(await original<typeof import("../mask")>()),
  maskContent: vi.fn(),
  maskFile: vi.fn(),
}));
vi.mock("../pseudonymize", async (original) => ({
  ...(await original<typeof import("../pseudonymize")>()),
  pseudonymizeKeyStatus: vi.fn(),
  pseudonymizeRun: vi.fn(),
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

function useRedact(projectPath: string | null = null) {
  const input = useMaskInput({ extensions: ["txt", "docx"] });
  return {
    input,
    workspace: useMaskWorkspace({
      projectPath,
      input,
      preferredAiTool: "cursor",
      onPreferredAiToolChange: vi.fn(),
      onNotice: noticeMock,
    }),
  };
}

beforeEach(() => {
  vi.resetAllMocks();
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: clipboardMock },
  });
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("redaction request lifecycle", () => {
  it.each(["resolve", "reject"] as const)("handles a current clipboard %s", async (outcome) => {
    vi.mocked(maskContent).mockResolvedValue({ masked_content: "masked", findings: [] });
    if (outcome === "resolve") clipboardMock.mockResolvedValue(undefined);
    else clipboardMock.mockRejectedValue(new Error("clipboard unavailable"));
    const { result } = renderHook(() => useRedact(), { wrapper: I18nProvider });
    act(() => result.current.input.setInputText("text"));
    await act(() => result.current.workspace.runMask());
    await act(() => result.current.workspace.copyAndOpenTool());
    expect(clipboardMock).toHaveBeenCalledWith("masked");
    expect(openAiTool).toHaveBeenCalledTimes(outcome === "resolve" ? 1 : 0);
    expect(noticeMock).toHaveBeenCalledTimes(outcome === "reject" ? 1 : 0);
    expect(result.current.workspace.copied).toBe(outcome === "resolve");
  });

  it.each(["resolve", "reject"] as const)(
    "does not reopen an app or restore feedback after a stale clipboard %s",
    async (outcome) => {
      vi.mocked(maskContent).mockResolvedValue({ masked_content: "masked", findings: [] });
      const pending = deferred<void>();
      clipboardMock.mockReturnValue(pending.promise);
      const { result } = renderHook(() => useRedact(), { wrapper: I18nProvider });
      act(() => result.current.input.setInputText("text"));
      await act(() => result.current.workspace.runMask());
      let copying!: Promise<void>;
      act(() => {
        copying = result.current.workspace.copyAndOpenTool();
      });
      act(() => result.current.workspace.resetResult());
      await act(async () => {
        if (outcome === "resolve") pending.resolve();
        else pending.reject(new Error("old clipboard failure"));
        await copying;
      });
      expect(result.current.workspace.copied).toBe(false);
      expect(openAiTool).not.toHaveBeenCalled();
      expect(noticeMock).not.toHaveBeenCalled();
    },
  );

  it("keeps the latest copy feedback for its full duration", async () => {
    vi.useFakeTimers();
    vi.mocked(maskContent).mockResolvedValue({ masked_content: "masked", findings: [] });
    clipboardMock.mockResolvedValue(undefined);
    const { result } = renderHook(() => useRedact(), { wrapper: I18nProvider });
    act(() => result.current.input.setInputText("text"));
    await act(() => result.current.workspace.runMask());
    await act(() => result.current.workspace.copyMasked());
    act(() => vi.advanceTimersByTime(1000));
    await act(() => result.current.workspace.copyMasked());
    act(() => vi.advanceTimersByTime(800));
    expect(result.current.workspace.copied).toBe(true);
    act(() => vi.advanceTimersByTime(1000));
    expect(result.current.workspace.copied).toBe(false);
  });
  it.each(["resolve", "reject"] as const)(
    "ignores a late %s after clearing input",
    async (outcome) => {
      const pending = deferred<Awaited<ReturnType<typeof maskContent>>>();
      vi.mocked(maskContent).mockReturnValue(pending.promise);
      const { result } = renderHook(() => useRedact(), { wrapper: I18nProvider });
      act(() => result.current.input.setInputText("old text"));
      let run!: Promise<void>;
      act(() => {
        run = result.current.workspace.runMask();
      });
      act(() => {
        result.current.input.clearInput();
        result.current.workspace.resetResult();
      });
      await act(async () => {
        if (outcome === "resolve") pending.resolve({ masked_content: "old result", findings: [] });
        else pending.reject(new Error("old error"));
        await run;
      });
      expect(result.current.workspace.maskState.status).toBe("idle");
      expect(result.current.workspace.canCopy).toBe(false);
    },
  );

  it("keeps the newer result when requests finish out of order", async () => {
    const old = deferred<Awaited<ReturnType<typeof maskContent>>>();
    vi.mocked(maskContent)
      .mockReturnValueOnce(old.promise)
      .mockResolvedValueOnce({ masked_content: "new result", findings: [] });
    const { result } = renderHook(() => useRedact(), { wrapper: I18nProvider });
    act(() => result.current.input.setInputText("old text"));
    let first!: Promise<void>;
    act(() => {
      first = result.current.workspace.runMask();
    });
    act(() => {
      result.current.input.setInputText("new text");
      result.current.workspace.resetResult();
    });
    await act(() => result.current.workspace.runMask());
    await act(async () => {
      old.resolve({ masked_content: "old result", findings: [] });
      await first;
    });
    expect(result.current.workspace.maskedOutput).toBe("new result");
  });

  it("deduplicates repeated execution before React renders", async () => {
    vi.mocked(maskContent).mockResolvedValue({ masked_content: "result", findings: [] });
    const { result } = renderHook(() => useRedact(), { wrapper: I18nProvider });
    act(() => result.current.input.setInputText("text"));
    await act(async () => {
      await Promise.all([result.current.workspace.runMask(), result.current.workspace.runMask()]);
    });
    expect(maskContent).toHaveBeenCalledTimes(1);
  });

  it("invalidates results when the policy project changes", async () => {
    const pending = deferred<Awaited<ReturnType<typeof maskContent>>>();
    vi.mocked(maskContent).mockReturnValue(pending.promise);
    const { result, rerender } = renderHook(({ path }) => useRedact(path), {
      initialProps: { path: "/old" },
      wrapper: I18nProvider,
    });
    act(() => result.current.input.setInputText("text"));
    let run!: Promise<void>;
    act(() => {
      run = result.current.workspace.runMask();
    });
    rerender({ path: "/new" });
    await act(async () => {
      pending.resolve({ masked_content: "old result", findings: [] });
      await run;
    });
    expect(result.current.workspace.maskState.status).toBe("idle");
  });

  it("does not write an obsolete Office file after the save dialog returns", async () => {
    vi.mocked(maskFile).mockResolvedValue({
      maskedContent: "preview",
      findings: [],
      fileKind: "office",
      sourceLabel: "old.docx",
      outputPath: undefined,
    });
    const dialog = deferred<string | null>();
    vi.mocked(save).mockReturnValue(dialog.promise);
    const { result } = renderHook(() => useRedact(), { wrapper: I18nProvider });
    act(() => result.current.input.applySelectedFile("/old.docx"));
    await act(() => result.current.workspace.runMask());
    let saving!: Promise<void>;
    act(() => {
      saving = result.current.workspace.saveMaskedFile();
    });
    act(() => result.current.workspace.resetResult());
    await act(async () => {
      dialog.resolve("/output.docx");
      await saving;
    });
    expect(maskFile).toHaveBeenCalledTimes(1);
    expect(result.current.workspace.saving).toBe(false);
  });
});

function usePseudo() {
  const input = useMaskInput({ extensions: ["txt"] });
  return {
    input,
    workspace: usePseudonymizeWorkspace({
      projectPath: "/project",
      active: true,
      input,
      onNotice: noticeMock,
    }),
  };
}

describe("pseudonymization confirmation lifecycle", () => {
  it.each(["resolve", "reject"] as const)(
    "ignores stale path-copy %s after resetting the workspace",
    async (outcome) => {
      const pending = deferred<void>();
      clipboardMock.mockReturnValue(pending.promise);
      const { result } = renderHook(usePseudo, { wrapper: I18nProvider });
      let copying!: Promise<void>;
      act(() => {
        copying = result.current.workspace.copyPath("/old/output.csv");
      });
      act(() => result.current.workspace.reset());
      await act(async () => {
        if (outcome === "resolve") pending.resolve();
        else pending.reject(new Error("old clipboard failure"));
        await copying;
      });
      expect(result.current.workspace.copiedPath).toBeNull();
      expect(noticeMock).not.toHaveBeenCalled();
    },
  );
  it("discards a key status response after reset without opening a stale confirmation", async () => {
    const key = deferred<Awaited<ReturnType<typeof pseudonymizeKeyStatus>>>();
    vi.mocked(pseudonymizeKeyStatus).mockReturnValue(key.promise);
    const { result } = renderHook(usePseudo, { wrapper: I18nProvider });
    act(() => result.current.input.setInputText("text"));
    let run!: Promise<void>;
    act(() => {
      run = result.current.workspace.run();
    });
    act(() => result.current.workspace.reset());
    await act(async () => {
      key.resolve({ exists: false, backend: "keyring", unavailableReason: null });
      await run;
    });
    expect(result.current.workspace.keyDialog.open).toBe(false);
    expect(result.current.workspace.preparing).toBe(false);
    expect(pseudonymizeRun).not.toHaveBeenCalled();
  });

  it("resolves an abandoned confirmation and prevents duplicate key lookups", async () => {
    vi.mocked(pseudonymizeKeyStatus).mockResolvedValue({
      exists: false,
      backend: "keyring",
      unavailableReason: null,
    });
    const { result } = renderHook(usePseudo, { wrapper: I18nProvider });
    act(() => result.current.input.setInputText("text"));
    let run!: Promise<void>;
    act(() => {
      run = result.current.workspace.run();
      void result.current.workspace.run();
    });
    await waitFor(() => expect(result.current.workspace.keyDialog.open).toBe(true));
    act(() => result.current.workspace.reset());
    await act(async () => {
      await run;
    });
    expect(pseudonymizeKeyStatus).toHaveBeenCalledTimes(1);
    expect(pseudonymizeRun).not.toHaveBeenCalled();
    expect(result.current.workspace.keyDialog.open).toBe(false);
    expect(result.current.workspace.preparing).toBe(false);
  });
});
