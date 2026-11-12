// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n";
import type { AuditReport, AuditState } from "../types";
import { AuditPanel } from "./AuditPanel";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

function report(overrides: Partial<AuditReport> = {}): AuditReport {
  return {
    version: 1,
    log_path: ".shk/audit.log",
    log_exists: true,
    parse_errors: 0,
    filters: { limit: 10 },
    summary: {
      total_entries: 1,
      blocked_events: 1,
      hook_audit_events: 0,
      secrets_push_events: 0,
    },
    by_rule: [],
    by_tool: [],
    by_reason: [],
    by_action_category: [],
    recent: [],
    ...overrides,
  };
}

function renderPanel(data: AuditReport) {
  const auditState: AuditState = { status: "done", data, loadedAt: new Date().toISOString() };
  render(
    <I18nProvider>
      <AuditPanel projectPath="/tmp/demo" auditState={auditState} onRefresh={vi.fn()} />
    </I18nProvider>,
  );
}

describe("AuditPanel", () => {
  beforeEach(() => {
    window.localStorage.setItem("shk.desktop.locale.v1", "en");
  });

  it("renders identifiers that name prototype members as plain text", () => {
    renderPanel(
      report({
        by_reason: [{ label: "finding_threshold", count: 1 }],
        by_action_category: [{ label: "__proto__", count: 1 }],
        recent: [
          {
            ts: "2026-05-23T02:31:00Z",
            event: "blocked",
            tool: "__proto__",
            hook: "pre",
            reason: "__proto__",
            action_category: "__proto__",
          },
        ],
      }),
    );

    expect(screen.getByRole("list", { name: "Recent blocks" })).toHaveTextContent("__proto__");
  });

  it("lists a policy-error block with its label", () => {
    renderPanel(
      report({
        by_reason: [{ label: "policy_error", count: 1 }],
        recent: [
          {
            ts: "2026-05-23T02:31:00Z",
            event: "blocked",
            tool: "cursor",
            hook: "pre",
            reason: "policy_error",
          },
        ],
      }),
    );

    expect(screen.getByRole("list", { name: "Recent blocks" })).toHaveTextContent(
      "Policy error blocked",
    );
    expect(screen.queryByText(/more event/)).not.toBeInTheDocument();
  });
});
