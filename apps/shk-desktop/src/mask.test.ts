import { describe, expect, it } from "vitest";
import {
  maskFileBasename,
  maskFileKind,
  maskOfficeSuggestedName,
  findingsBySeverity,
} from "./mask";
import type { Finding } from "./scan";

function finding(severity: Finding["severity"]): Finding {
  return {
    rule_id: "pii.email",
    severity,
    kind: "pii",
    file: "<input>",
    line: 1,
    column: 1,
    message: "demo",
    redacted_value: "[REDACTED]",
    confidence: 0.9,
  };
}

describe("mask helpers", () => {
  it("extracts basename from file path", () => {
    expect(maskFileBasename("/tmp/demo/prompt.txt")).toBe("prompt.txt");
    expect(maskFileBasename("C:\\docs\\report.docx")).toBe("report.docx");
  });

  it("builds masked office filename", () => {
    expect(maskOfficeSuggestedName("notes.docx")).toBe("notes.masked.docx");
    expect(maskOfficeSuggestedName("DATA.XLSX")).toBe("DATA.masked.XLSX");
  });

  it("classifies supported document paths", () => {
    expect(maskFileKind("/tmp/report.PDF")).toBe("pdf");
    expect(maskFileKind("C:\\docs\\report.docx")).toBe("office");
    expect(maskFileKind("/tmp/contacts.csv")).toBe("text");
  });
});

describe("findingsBySeverity", () => {
  it("counts findings by severity bucket", () => {
    const counts = findingsBySeverity([
      finding("high"),
      finding("medium"),
      finding("medium"),
      finding("unknown"),
    ]);

    expect(counts.high).toBe(1);
    expect(counts.medium).toBe(2);
    expect(counts.info).toBe(1);
    expect(counts.critical).toBe(0);
  });
});
