import type { Severity } from "./scan";

export type ProjectSummary = {
  total: number;
  bySeverity: Partial<Record<Severity, number>>;
  scannedAt: string;
};

export type Project = {
  id: string;
  name: string;
  path: string;
  addedAt: string;
  lastScannedAt?: string;
  summary?: ProjectSummary;
};
