import { describe, expect, it } from "vitest";
import {
  DEFAULT_NOTIFICATION_SETTINGS,
  describeBlockedEvent,
  notifiableEvents,
  parseNotificationSettings,
  shouldNotifyForEvent,
  summarizeBlockedBatch,
  type BlockedNotificationEvent,
  type BlockedNotificationLabels,
} from "./notifications";

const labels: BlockedNotificationLabels = {
  singleProjectTitle: "Blocked in {{project}}",
  multiProjectTitle: "{{count}} AI actions blocked",
  moreCount: "+{{count}} more",
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

const projectNameFor = (path: string) => (path === "/work/api" ? "api" : path);

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
    const content = summarizeBlockedBatch([guardEvent()], projectNameFor, labels);
    expect(content).toEqual({
      title: "Blocked in api",
      body: "Risky action blocked · Environment dump · Cursor",
      projectPath: "/work/api",
    });
  });

  it("collapses a burst into one notification describing the newest block", () => {
    const content = summarizeBlockedBatch(
      [
        guardEvent(),
        guardEvent(),
        guardEvent({ reason: "finding_threshold", display_path: "src/.env" }),
      ],
      projectNameFor,
      labels,
    );
    expect(content?.title).toBe("Blocked in api");
    expect(content?.body).toBe("Secret/PII blocked · src/.env · Cursor · +2 more");
  });

  it("lists the projects when blocks span more than one", () => {
    const content = summarizeBlockedBatch(
      [guardEvent(), guardEvent({ project_path: "/work/web" })],
      projectNameFor,
      labels,
    );
    expect(content).toEqual({
      title: "2 AI actions blocked",
      body: "api, /work/web",
    });
    // Ambiguous origin, so clicking must not jump to an arbitrary project.
    expect(content?.projectPath).toBeUndefined();
  });
});

describe("describeBlockedEvent", () => {
  it("falls back to raw identifiers when a label is missing", () => {
    const description = describeBlockedEvent(
      guardEvent({ action_category: "custom_policy", tool: "windsurf" }),
      labels,
    );
    expect(description).toBe("Risky action blocked · custom_policy · windsurf");
  });

  it("omits the placeholder detail when there is nothing to show", () => {
    const description = describeBlockedEvent(
      { project_path: "/work/api", reason: "policy_error", tool: "cursor" },
      labels,
    );
    expect(description).toBe("policy_error · Cursor");
  });
});
