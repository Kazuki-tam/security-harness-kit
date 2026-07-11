import { describe, expect, it } from "vitest";
import { createRequestTracker } from "./requestTracker";

describe("createRequestTracker", () => {
  it("ignores stale responses for the same key", () => {
    const tracker = createRequestTracker();
    const first = tracker.begin("scan:project-a");
    const second = tracker.begin("scan:project-a");

    expect(tracker.isLatest("scan:project-a", first)).toBe(false);
    expect(tracker.isLatest("scan:project-a", second)).toBe(true);
  });

  it("tracks different keys independently", () => {
    const tracker = createRequestTracker();
    const scan = tracker.begin("scan:project-a");
    const status = tracker.begin("status:project-b");

    expect(tracker.isLatest("scan:project-a", scan)).toBe(true);
    expect(tracker.isLatest("status:project-b", status)).toBe(true);
  });
});
