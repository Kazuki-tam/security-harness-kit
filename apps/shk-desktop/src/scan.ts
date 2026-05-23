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

export type ScanResultSnapshot = {
  report: ScanReport;
  finishedAt: string;
};

export type ScanState =
  | { status: "idle" }
  | {
      status: "running";
      startedAt: string;
      previous?: ScanResultSnapshot;
    }
  | { status: "done"; report: ScanReport; finishedAt: string }
  | { status: "error"; message: string; previous?: ScanResultSnapshot };

export function visibleScanResult(state: ScanState): ScanResultSnapshot | undefined {
  if (state.status === "done") {
    return { report: state.report, finishedAt: state.finishedAt };
  }
  if (state.status === "running" || state.status === "error") {
    return state.previous;
  }
  return undefined;
}

export const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export const severityText: Record<Severity, string> = {
  critical: "text-red-400",
  high: "text-orange-300",
  medium: "text-amber-300",
  low: "text-sky-300",
  info: "text-slate-300",
};

export const severityDot: Record<Severity, string> = {
  critical: "bg-red-500",
  high: "bg-orange-400",
  medium: "bg-amber-400",
  low: "bg-sky-400",
  info: "bg-slate-400",
};

export const severityRing: Record<Severity, string> = {
  critical: "ring-red-500/40",
  high: "ring-orange-400/40",
  medium: "ring-amber-400/40",
  low: "ring-sky-400/40",
  info: "ring-slate-400/30",
};

export const severityBadge: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-300 ring-1 ring-inset ring-red-500/30",
  high: "bg-orange-500/15 text-orange-300 ring-1 ring-inset ring-orange-500/30",
  medium: "bg-amber-500/15 text-amber-300 ring-1 ring-inset ring-amber-500/30",
  low: "bg-sky-500/15 text-sky-300 ring-1 ring-inset ring-sky-500/30",
  info: "bg-slate-500/15 text-slate-300 ring-1 ring-inset ring-slate-500/30",
};

export function asSeverity(value: string): Severity {
  return severityOrder.includes(value as Severity) ? (value as Severity) : "info";
}

export function actionableCount(
  by: Partial<Record<Severity, number>> | Record<string, number> | undefined,
): number {
  if (!by) return 0;
  return (by.critical ?? 0) + (by.high ?? 0);
}
