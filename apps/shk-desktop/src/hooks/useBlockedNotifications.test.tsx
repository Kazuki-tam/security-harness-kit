// @vitest-environment jsdom
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { BlockedNotificationEvent, BlockedNotificationLabels } from "../notifications";
import { DEFAULT_NOTIFICATION_SETTINGS, NOTIFICATION_DEBOUNCE_MS } from "../notifications";
import { useBlockedNotifications } from "./useBlockedNotifications";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn().mockResolvedValue(undefined),
  listen: vi.fn(),
  sendNotification: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: mocks.invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: mocks.listen }));
vi.mock("@tauri-apps/plugin-notification", () => ({
  sendNotification: mocks.sendNotification,
}));

const labels: BlockedNotificationLabels = {
  singleProjectTitle: "Blocked in {{project}}",
  multiProjectTitle: "{{count}} actions blocked",
  moreCount: "+{{count}} more",
  unknownReason: "Blocked",
  unknownProject: "a project",
  reasonLabels: { action_guard: "Risky action blocked" },
  actionCategories: {},
  toolNames: { cursor: "Cursor" },
};

describe("useBlockedNotifications", () => {
  let emit: ((event: { payload: BlockedNotificationEvent[] }) => void) | undefined;

  beforeEach(() => {
    vi.useFakeTimers();
    mocks.invoke.mockClear();
    mocks.sendNotification.mockReset();
    mocks.listen.mockReset();
    mocks.listen.mockImplementation(
      (_eventName: string, handler: (event: { payload: BlockedNotificationEvent[] }) => void) => {
        emit = handler;
        return Promise.resolve(() => undefined);
      },
    );
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    emit = undefined;
  });

  it("contains synchronous notification transport failures", () => {
    const warning = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    mocks.sendNotification.mockImplementation(() => {
      throw new Error("notification service unavailable");
    });

    const { unmount } = renderHook(() =>
      useBlockedNotifications({
        projects: [{ id: "p1", name: "api", path: "/work/api", addedAt: "2026-08-11" }],
        settings: DEFAULT_NOTIFICATION_SETTINGS,
        labels,
      }),
    );

    expect(emit).toBeTypeOf("function");
    act(() => {
      emit?.({
        payload: [{ project_path: "/work/api", reason: "action_guard", tool: "cursor" }],
      });
      vi.advanceTimersByTime(NOTIFICATION_DEBOUNCE_MS);
    });

    expect(mocks.sendNotification).toHaveBeenCalledOnce();
    expect(warning).toHaveBeenCalledWith(
      "failed to send blocked activity notification",
      expect.any(Error),
    );
    unmount();
  });
});
