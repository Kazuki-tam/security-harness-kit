import { invoke } from "@tauri-apps/api/core";
import type { Messages } from "./i18n/types";
import { basenameOf, dirnameOf } from "./utils";

export type PseudonymizeKindChoice = "email" | "phone" | "name" | "custom" | "none";
export type PseudonymizeColumnSource = "config" | "cli" | "inferred" | "rule" | "none";
export type PseudonymizeInputKind = "table-csv" | "table-xlsx" | "text" | "text-office";
export type PseudonymizeMode = "table" | "text";
export type PseudonymizeFormat = "csv" | "tsv";

export type PseudonymizeColumnChoiceDto = {
  name: string;
  kind: PseudonymizeKindChoice;
  customLabel?: string | null;
};

export type PseudonymizeInspectOptions = {
  inputPath?: string;
  inlineText?: string;
  mode?: PseudonymizeMode;
  format?: PseudonymizeFormat;
  sheet?: string;
  noHeader?: boolean;
  columns?: PseudonymizeColumnChoiceDto[];
};

export type PseudonymizeColumnPlan = {
  index: number;
  name: string;
  kind: PseudonymizeKindChoice;
  customLabel: string | null;
  source: PseudonymizeColumnSource;
  matchRate: number | null;
};

export type PseudonymizeTablePreview = {
  hasHeader: boolean;
  delimiter: string;
  headers: string[];
  sampleRows: string[][];
  rowCount: number;
  columns: PseudonymizeColumnPlan[];
  sheets: string[];
  selectedSheet: string | null;
};

export type PseudonymizeInspectResult = {
  inputKind: PseudonymizeInputKind;
  sourceLabel: string;
  table: PseudonymizeTablePreview | null;
};

export type PseudonymizeKeyStatus = {
  exists: boolean;
  backend: string;
  fingerprint: string | null;
  unavailableReason: string | null;
};

export type PseudonymizeRunOptions = PseudonymizeInspectOptions & {
  outputPath?: string;
  mapPath?: string;
  createKey?: boolean;
  checkRemaining?: boolean;
};

export type PseudonymizeRunResult = {
  mode: string;
  rowsProcessed: number;
  replaced: Record<string, number>;
  unparsed: Record<string, number>;
  columns: PseudonymizeColumnPlan[];
  keyFingerprint: string | null;
  outputPath: string | null;
  metaPath: string | null;
  mapPath: string | null;
  inlineOutput: string | null;
  remainingRuleIds: string[];
  remainingCheckError: string | null;
};

export type PseudonymizeRestoreResult = {
  outputPath: string;
  replacements: number;
  ambiguousTokens: number;
};

export function pseudonymizeInspect(
  projectPath: string,
  options: PseudonymizeInspectOptions,
): Promise<PseudonymizeInspectResult> {
  return invoke<PseudonymizeInspectResult>("pseudonymize_inspect", { projectPath, options });
}

export function pseudonymizeKeyStatus(projectPath: string): Promise<PseudonymizeKeyStatus> {
  return invoke<PseudonymizeKeyStatus>("pseudonymize_key_status", { projectPath });
}

export function pseudonymizeRun(
  projectPath: string,
  options: PseudonymizeRunOptions,
): Promise<PseudonymizeRunResult> {
  return invoke<PseudonymizeRunResult>("pseudonymize_run", { projectPath, options });
}

export function pseudonymizeRestore(
  projectPath: string,
  inputPath: string,
  mapPath: string,
  outputPath: string,
): Promise<PseudonymizeRestoreResult> {
  return invoke<PseudonymizeRestoreResult>("pseudonymize_restore", {
    projectPath,
    inputPath,
    mapPath,
    outputPath,
  });
}

export const PSEUDONYMIZE_FILE_EXTENSIONS = [
  "csv",
  "tsv",
  "xlsx",
  "txt",
  "md",
  "docx",
  "pptx",
] as const;

const TABLE_EXTENSIONS = new Set(["csv", "tsv", "xlsx"]);
const CUSTOM_LABEL_PATTERN = /^[a-z][a-z0-9_]{0,32}$/;
const RESERVED_LABELS = new Set(["email", "phone", "name"]);
const FALLBACK_CUSTOM_LABEL = "value";

/** Lower-case extension without the dot, or an empty string. */
export function fileExtension(path: string): string {
  const base = basenameOf(path);
  const dot = base.lastIndexOf(".");
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : "";
}

export function isPseudonymizableFile(path: string): boolean {
  return (PSEUDONYMIZE_FILE_EXTENSIONS as readonly string[]).includes(fileExtension(path));
}

export function isTableFile(path: string): boolean {
  return TABLE_EXTENSIONS.has(fileExtension(path));
}

export function isTableInputKind(kind: PseudonymizeInputKind): boolean {
  return kind === "table-csv" || kind === "table-xlsx";
}

/** `orders.csv` → `orders.pseudo.csv`; the original extension is kept so restore maps stay valid. */
export function pseudonymizeSuggestedOutputName(path: string): string {
  const base = basenameOf(path);
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return `${base}.pseudo`;
  return `${base.slice(0, dot)}.pseudo${base.slice(dot)}`;
}

export function pseudonymizeSuggestedOutputPath(path: string): string {
  const dir = dirnameOf(path);
  const name = pseudonymizeSuggestedOutputName(path);
  if (!dir || dir === path) return name;
  const separator = path.includes("\\") && !path.includes("/") ? "\\" : "/";
  return `${dir}${separator}${name}`;
}

/** The restore map sits next to the output: `orders.pseudo.csv` → `orders.shk-map`. */
export function restoreMapSuggestedPath(outputPath: string): string {
  const base = basenameOf(outputPath);
  const dot = base.lastIndexOf(".");
  let stem = dot > 0 ? base.slice(0, dot) : base;
  if (stem.endsWith(".pseudo")) stem = stem.slice(0, -".pseudo".length);
  const mapName = `${stem}.shk-map`;
  const dir = dirnameOf(outputPath);
  if (!dir || dir === outputPath) return mapName;
  const separator = outputPath.includes("\\") && !outputPath.includes("/") ? "\\" : "/";
  return `${dir}${separator}${mapName}`;
}

/** Save-dialog filter that pins the output to the input's extension. */
export function outputFilterFor(path: string): { name: string; extensions: string[] } {
  const ext = fileExtension(path);
  return { name: ext ? ext.toUpperCase() : "File", extensions: ext ? [ext] : ["*"] };
}

export type CustomLabelValidity = "ok" | "invalid" | "reserved";

export function validateCustomLabel(label: string): CustomLabelValidity {
  if (!CUSTOM_LABEL_PATTERN.test(label)) return "invalid";
  if (RESERVED_LABELS.has(label)) return "reserved";
  return "ok";
}

/** Turn a header such as `Member ID` into a valid custom label (`member_id`). */
export function suggestCustomLabel(header: string): string {
  const slug = header
    .normalize("NFKD")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^[^a-z]+/, "")
    .replace(/_+$/, "")
    .slice(0, 33);
  if (!slug || validateCustomLabel(slug) !== "ok") return FALLBACK_CUSTOM_LABEL;
  return slug;
}

/** Friendly name for a kind as the engine reports it (`email`, `custom:member_id`, …). */
export function kindDisplayLabel(kind: string, m: Messages["mask"]["pseudonymize"]): string {
  if (kind === "email" || kind === "phone" || kind === "name") return m.kinds[kind];
  if (kind.startsWith("custom:")) {
    return m.kindCustomDisplay.replace("{{label}}", kind.slice("custom:".length));
  }
  return kind;
}
