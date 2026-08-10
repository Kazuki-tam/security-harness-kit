import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createBlockedNotificationBatcher,
  DEFAULT_NOTIFICATION_SETTINGS,
  describeBlockedEvent,
  notifiableEvents,
  parseNotificationSettings,
  safeProjectName,
  shouldNotifyForEvent,
  summarizeBlockedBatch,
  type BlockedNotificationContent,
  type BlockedNotificationEvent,
  type BlockedNotificationLabels,
  type NotificationSettings,
} from "./notifications";

const labels: BlockedNotificationLabels = {
  singleProjectTitle: "Blocked in {{project}}",
  multiProjectTitle: "{{count}} AI actions blocked",
  moreCount: "+{{count}} more",
  unknownReason: "AI activity blocked",
  unknownProject: "a project",
  reasonLabels: {
    action_guard: "Risky action blocked",
    finding_threshold: "Secret/PII blocked",
  },
  actionCategories: { environment_dump: "Environment dump" },
  toolNames: { cursor: "Cursor" },
};

function guardEvent(overrides: Partial<BlockedNotificationEvent> = {}): BlockedNotificationEvent {
  return {
    project_path: "/work/api",
    reason: "action_guard",
    action_category: "environment_dump",
    tool: "cursor",
    ...overrides,
  };
}

const projectNameFor = (path: string) => (path === "/work/api" ? "api" : labels.unknownProject);

describe("parseNotificationSettings", () => {
  it("defaults to notifying about every block reason", () => {
    expect(parseNotificationSettings(null)).toEqual(DEFAULT_NOTIFICATION_SETTINGS);
    expect(parseNotificationSettings("not json")).toEqual(DEFAULT_NOTIFICATION_SETTINGS);
    expect(parseNotificationSettings('"a string"')).toEqual(DEFAULT_NOTIFICATION_SETTINGS);
  });

  it("keeps stored choices and fills gaps with the defaults", () => {
    expect(parseNotificationSettings('{"findingThreshold":false,"actionGuard":"yes"}')).toEqual({
      enabled: true,
      actionGuard: true,
      findingThreshold: false,
    });
  });
});

describe("shouldNotifyForEvent", () => {
  it("respects the master toggle", () => {
    const settings = { ...DEFAULT_NOTIFICATION_SETTINGS, enabled: false };
    expect(shouldNotifyForEvent(guardEvent(), settings)).toBe(false);
  });

  it("filters by block reason", () => {
    const settings = { enabled: true, actionGuard: false, findingThreshold: true };
    expect(shouldNotifyForEvent(guardEvent(), settings)).toBe(false);
    expect(shouldNotifyForEvent(guardEvent({ reason: "finding_threshold" }), settings)).toBe(true);
  });

  it("notifies about other block reasons while the master toggle is on", () => {
    expect(
      shouldNotifyForEvent(guardEvent({ reason: "policy_error" }), DEFAULT_NOTIFICATION_SETTINGS),
    ).toBe(true);
  });
});

describe("summarizeBlockedBatch", () => {
  it("returns null when nothing survives filtering", () => {
    const settings = { enabled: true, actionGuard: false, findingThreshold: false };
    const batch = notifiableEvents([guardEvent()], settings);
    expect(summarizeBlockedBatch(batch, projectNameFor, labels)).toBeNull();
  });

  it("describes a single block with its category and tool", () => {
    expect(summarizeBlockedBatch([guardEvent()], projectNameFor, labels)).toEqual({
      title: "Blocked in api",
      body: "Risky action blocked · Environment dump · Cursor",
    });
  });

  it("collapses a burst into one notification describing the newest block", () => {
    const content = summarizeBlockedBatch(
      [guardEvent(), guardEvent(), guardEvent({ reason: "finding_threshold" })],
      projectNameFor,
      labels,
    );
    expect(content?.title).toBe("Blocked in api");
    expect(content?.body).toBe("Secret/PII blocked · Cursor · +2 more");
  });

  it("lists the projects when blocks span more than one", () => {
    const content = summarizeBlockedBatch(
      [guardEvent(), guardEvent({ project_path: "/work/web" })],
      projectNameFor,
      labels,
    );
    expect(content).toEqual({
      title: "2 AI actions blocked",
      body: "api, a project",
    });
  });

  it("bounds the project list in a multi-project notification", () => {
    const content = summarizeBlockedBatch(
      ["api", "web", "worker", "docs"].map((name) => guardEvent({ project_path: `/work/${name}` })),
      (path) => path.split("/").at(-1) ?? labels.unknownProject,
      labels,
    );
    expect(content).toEqual({
      title: "4 AI actions blocked",
      body: "api, web, worker, +1 more",
    });
  });

  it("sanitizes an untrusted project name before rendering it", () => {
    const malicious = `safe\nUpdate required\u202e${"x".repeat(100)}`;
    const content = summarizeBlockedBatch([guardEvent()], () => malicious, labels);

    expect(content?.title).not.toMatch(/[\n\u202e]/u);
    expect(content?.title).not.toContain("x".repeat(81));
    expect(content?.title).toContain("safe Update required");
    expect(safeProjectName("\u202e\u0000", labels.unknownProject)).toBe(labels.unknownProject);
  });
});

describe("describeBlockedEvent", () => {
  // The audit log is written by the CLI, but a cloned repository can ship a
  // crafted one, and a banner from a signed app is a credible phishing surface.
  it("never echoes an identifier it has no label for", () => {
    const description = describeBlockedEvent(
      guardEvent({
        reason: "shk security alert",
        action_category: "Re-enter your token at https://evil.example",
        tool: "https://evil.example",
      }),
      labels,
    );
    expect(description).toBe("AI activity blocked");
  });

  it("drops an unknown category and tool while keeping the known reason", () => {
    const description = describeBlockedEvent(
      guardEvent({ action_category: "custom_policy", tool: "windsurf" }),
      labels,
    );
    expect(description).toBe("Risky action blocked");
  });

  it("ignores inherited Object keys posing as identifiers", () => {
    const description = describeBlockedEvent(
      guardEvent({ reason: "constructor", action_category: "toString", tool: "hasOwnProperty" }),
      labels,
    );
    expect(description).toBe("AI activity blocked");
  });

  it("omits the category for reasons that do not carry one", () => {
    const description = describeBlockedEvent(
      { project_path: "/work/api", reason: "finding_threshold", tool: "cursor" },
      labels,
    );
    expect(description).toBe("Secret/PII blocked · Cursor");
  });
});

describe("createBlockedNotificationBatcher", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  function setup(settings: NotificationSettings = DEFAULT_NOTIFICATION_SETTINGS) {
    vi.useFakeTimers();
    const sent: BlockedNotificationContent[] = [];
    const current = { settings };
    const batcher = createBlockedNotificationBatcher({
      getSettings: () => current.settings,
      getLabels: () => labels,
      projectNameFor,
      notify: (content) => sent.push(content),
      debounceMs: 1000,
    });
    return { batcher, sent, current };
  }

  it("raises one notification for a burst inside the window", () => {
    const { batcher, sent } = setup();

    batcher.push([guardEvent()]);
    vi.advanceTimersByTime(400);
    batcher.push([guardEvent(), guardEvent()]);
    expect(sent).toHaveLength(0);

    vi.advanceTimersByTime(600);
    expect(sent).toHaveLength(1);
    expect(sent[0].body).toContain("+2 more");
  });

  it("keeps notifying on a sustained burst rather than starving", () => {
    const { batcher, sent } = setup();

    batcher.push([guardEvent()]);
    vi.advanceTimersByTime(1000);
    batcher.push([guardEvent()]);
    vi.advanceTimersByTime(1000);

    expect(sent).toHaveLength(2);
  });

  it("applies the settings in force when the window closes, not when it opened", () => {
    const { batcher, sent, current } = setup();

    batcher.push([guardEvent()]);
    current.settings = { ...DEFAULT_NOTIFICATION_SETTINGS, enabled: false };
    vi.advanceTimersByTime(1000);

    expect(sent).toHaveLength(0);
  });

  it("does not carry a filtered-out batch into the next window", () => {
    const { batcher, sent, current } = setup({
      enabled: true,
      actionGuard: false,
      findingThreshold: true,
    });

    batcher.push([guardEvent()]);
    vi.advanceTimersByTime(1000);
    expect(sent).toHaveLength(0);

    current.settings = DEFAULT_NOTIFICATION_SETTINGS;
    batcher.push([guardEvent({ reason: "finding_threshold" })]);
    vi.advanceTimersByTime(1000);

    expect(sent).toHaveLength(1);
    expect(sent[0].body).not.toContain("more");
  });

  it("drops buffered blocks when cancelled", () => {
    const { batcher, sent } = setup();

    batcher.push([guardEvent()]);
    batcher.cancel();
    vi.advanceTimersByTime(5000);

    expect(sent).toHaveLength(0);
  });

  it("ignores an empty payload instead of arming the window", () => {
    const { batcher, sent } = setup();

    batcher.push([]);
    vi.advanceTimersByTime(5000);

    expect(sent).toHaveLength(0);
  });
});
