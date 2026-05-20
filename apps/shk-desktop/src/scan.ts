export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Finding = {
  rule_id: string;
  severity: Severity | string;
  kind: string;
  file: string;
  line: number;
  column: number;
  message: string;
  redacted_value: string;
  confidence: number;
};

export type ScanReport = {
  version: number;
  scanned_paths: string[];
  findings: Finding[];
  summary: {
    total: number;
    by_severity: Record<string, number>;
  };
  exit_threshold: string;
  policy_path?: string;
  suppressed: number;
  deduplicated: number;
  color_mode: string;
};

export type ScanState =
  | { status: "idle" }
  | { status: "running" }
  | { status: "done"; report: ScanReport }
  | { status: "error"; message: string };

export const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export const severityLabels: Record<Severity, string> = {
  critical: "緊急対応",
  high: "対応が必要",
  medium: "確認推奨",
  low: "低リスク",
  info: "情報",
};

export const severityText: Record<Severity, string> = {
  critical: "text-red-700",
  high: "text-orange-700",
  medium: "text-amber-700",
  low: "text-blue-700",
  info: "text-slate-600",
};

export const severityDot: Record<Severity, string> = {
  critical: "bg-red-700",
  high: "bg-orange-700",
  medium: "bg-amber-600",
  low: "bg-blue-700",
  info: "bg-slate-500",
};

export function asSeverity(value: string): Severity {
  return severityOrder.includes(value as Severity) ? (value as Severity) : "info";
}
