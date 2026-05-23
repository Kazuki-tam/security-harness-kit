import { describe, expect, it } from "vitest";
import {
  auditEventDetail,
  auditHasBlockedEvents,
  blockedRecentRows,
  formatActionCategory,
  formatAuditTimestamp,
  formatToolName,
  hiddenBlockedCount,
  highestBlockedSeverity,
  isBlockedAuditReason,
  loadAuditReport,
  rowLinksToFindings,
} from "./audit";
import type { AuditReport } from "./types";

function sampleReport(overrides: Partial<AuditReport> = {}): AuditReport {
  return {
    version: 1,
    log_path: ".shk/audit.log",
    log_exists: true,
    parse_errors: 0,
    filters: { limit: 10 },
    summary: {
      total_entries: 2,
      blocked_events: 1,
      hook_audit_events: 1,
      secrets_push_events: 0,
    },
    by_rule: [],
    by_tool: [],
    by_reason: [],
    by_action_category: [],
    recent: [
      {
        ts: "2026-05-23T02:31:00Z",
        tool: "cursor",
        hook: "pre",
        reason: "finding_threshold",
        max_severity: "high",
        display_path: "secret.txt",
        finding_count: 2,
      },
      {
        ts: "2026-05-23T02:30:00Z",
        tool: "cursor",
        hook: "pre",
        reason: "hook_audit",
        finding_count: 1,
      },
    ],
    ...overrides,
  };
}

describe("isBlockedAuditReason", () => {
  it("accepts blocked-event reasons only", () => {
    expect(isBlockedAuditReason("finding_threshold")).toBe(true);
    expect(isBlockedAuditReason("action_guard")).toBe(true);
    expect(isBlockedAuditReason("hook_audit")).toBe(false);
    expect(isBlockedAuditReason(undefined)).toBe(false);
  });
});

describe("blockedRecentRows", () => {
  it("filters non-blocked recent rows", () => {
    const rows = blockedRecentRows(sampleReport());
    expect(rows).toHaveLength(1);
    expect(rows[0]?.reason).toBe("finding_threshold");
  });
});

describe("auditEventDetail", () => {
  it("prefers severity for finding-threshold blocks", () => {
    expect(
      auditEventDetail({
        ts: "2026-05-23T02:31:00Z",
        reason: "finding_threshold",
        max_severity: "high",
        display_path: "secret.txt",
      }),
    ).toBe("high");
  });

  it("prefers action category for action-guard blocks", () => {
    expect(
      auditEventDetail({
        ts: "2026-05-23T02:31:00Z",
        reason: "action_guard",
        action_category: "env_dump",
      }),
    ).toBe("env_dump");
  });

  it("falls back to display path and dash", () => {
    expect(
      auditEventDetail({
        ts: "2026-05-23T02:31:00Z",
        display_path: "secret.txt",
      }),
    ).toBe("secret.txt");
    expect(auditEventDetail({ ts: "2026-05-23T02:31:00Z" })).toBe("—");
  });
});

describe("formatAuditTimestamp", () => {
  it("formats valid RFC3339 timestamps", () => {
    expect(formatAuditTimestamp("2026-05-23T02:31:00Z", "en-US")).toMatch(/May/);
  });

  it("truncates invalid timestamps", () => {
    expect(formatAuditTimestamp("not-a-date")).toBe("not-a-date");
  });
});

describe("auditHasBlockedEvents", () => {
  it("reflects summary blocked count", () => {
    expect(auditHasBlockedEvents(sampleReport())).toBe(true);
    expect(
      auditHasBlockedEvents(
        sampleReport({
          summary: {
            total_entries: 0,
            blocked_events: 0,
            hook_audit_events: 0,
            secrets_push_events: 0,
          },
        }),
      ),
    ).toBe(false);
  });
});

describe("formatToolName", () => {
  it("localizes known tool ids", () => {
    expect(formatToolName("cursor", { cursor: "Cursor", codex: "Codex" })).toBe("Cursor");
  });
  it("falls back to raw id for unknown tools", () => {
    expect(formatToolName("mystery", { cursor: "Cursor" })).toBe("mystery");
  });
  it("returns a dash for missing tool", () => {
    expect(formatToolName(undefined, {})).toBe("—");
  });
});

describe("formatActionCategory", () => {
  it("localizes known categories", () => {
    expect(formatActionCategory("env_dump", { env_dump: "Env dump" })).toBe("Env dump");
  });
  it("falls back to raw id", () => {
    expect(formatActionCategory("unknown_thing", {})).toBe("unknown_thing");
  });
  it("returns a dash for missing category", () => {
    expect(formatActionCategory(undefined, {})).toBe("—");
  });
});

describe("highestBlockedSeverity", () => {
  it("returns the highest severity among blocked rows", () => {
    expect(
      highestBlockedSeverity(
        sampleReport({
          recent: [
            {
              ts: "2026-05-23T02:31:00Z",
              tool: "cursor",
              reason: "finding_threshold",
              max_severity: "medium",
            },
            {
              ts: "2026-05-23T02:32:00Z",
              tool: "cursor",
              reason: "finding_threshold",
              max_severity: "critical",
            },
            {
              ts: "2026-05-23T02:33:00Z",
              tool: "cursor",
              reason: "hook_audit",
              max_severity: "high",
            },
          ],
        }),
      ),
    ).toBe("critical");
  });

  it("falls back to summary max severity", () => {
    expect(
      highestBlockedSeverity(
        sampleReport({
          recent: [],
          summary: {
            total_entries: 0,
            blocked_events: 0,
            hook_audit_events: 0,
            secrets_push_events: 0,
            max_severity: "high",
          },
        }),
      ),
    ).toBe("high");
  });

  it("returns undefined when no severity is available", () => {
    expect(
      highestBlockedSeverity(
        sampleReport({
          recent: [],
          summary: {
            total_entries: 0,
            blocked_events: 0,
            hook_audit_events: 0,
            secrets_push_events: 0,
          },
        }),
      ),
    ).toBeUndefined();
  });
});

describe("rowLinksToFindings", () => {
  it("links only finding-threshold rows", () => {
    expect(rowLinksToFindings({ ts: "x", reason: "finding_threshold" })).toBe(true);
    expect(rowLinksToFindings({ ts: "x", reason: "action_guard" })).toBe(false);
    expect(rowLinksToFindings({ ts: "x" })).toBe(false);
  });
});

describe("hiddenBlockedCount", () => {
  it("returns positive count when summary exceeds visible rows", () => {
    expect(
      hiddenBlockedCount(
        sampleReport({
          summary: {
            total_entries: 12,
            blocked_events: 12,
            hook_audit_events: 0,
            secrets_push_events: 0,
          },
        }),
      ),
    ).toBe(11);
  });

  it("clamps to zero when visible exceeds summary", () => {
    expect(hiddenBlockedCount(sampleReport())).toBe(0);
  });
});

describe("loadAuditReport", () => {
  it("returns done state with fetched report", async () => {
    const report = sampleReport();
    const state = await loadAuditReport("/tmp/project", async () => report);
    expect(state.status).toBe("done");
    if (state.status === "done") {
      expect(state.data).toBe(report);
      expect(state.loadedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    }
  });

  it("returns error state when fetch fails", async () => {
    const state = await loadAuditReport("/tmp/project", async () => {
      throw new Error("audit failed");
    });
    expect(state).toEqual({ status: "error", message: "audit failed" });
  });
});
