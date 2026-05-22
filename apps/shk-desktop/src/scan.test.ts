import { describe, expect, it } from "vitest";
import type { ScanReport, ScanResultSnapshot } from "./scan";
import { visibleScanResult } from "./scan";

const report: ScanReport = {
  version: 1,
  scanned_paths: ["/workspace"],
  findings: [],
  summary: {
    total: 0,
    by_severity: {},
  },
  exit_threshold: "high",
  suppressed: 0,
  deduplicated: 0,
  color_mode: "never",
};

const snapshot: ScanResultSnapshot = {
  report,
  finishedAt: "2026-05-22T02:35:00.000Z",
};

describe("visibleScanResult", () => {
  it("returns the completed scan result", () => {
    expect(visibleScanResult({ status: "done", ...snapshot })).toEqual(snapshot);
  });

  it("keeps previous results visible while scanning or after an error", () => {
    expect(
      visibleScanResult({
        status: "running",
        startedAt: "2026-05-22T02:36:00.000Z",
        previous: snapshot,
      }),
    ).toBe(snapshot);
    expect(visibleScanResult({ status: "error", message: "failed", previous: snapshot })).toBe(
      snapshot,
    );
  });

  it("returns no result before the first successful scan", () => {
    expect(visibleScanResult({ status: "idle" })).toBeUndefined();
    expect(
      visibleScanResult({ status: "running", startedAt: "2026-05-22T02:36:00.000Z" }),
    ).toBeUndefined();
  });
});
