import { invoke } from "@tauri-apps/api/core";
import type { Finding } from "./scan";
import { asSeverity, severityOrder, type Severity } from "./scan";

export type MaskJsonOutput = {
  masked_content: string;
  findings: Finding[];
};

export type MaskFileResult = {
  maskedContent: string;
  findings: Finding[];
  fileKind: "text" | "office" | string;
  sourceLabel: string;
  outputPath?: string;
};

export type MaskState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "done"; result: MaskJsonOutput; source: "text" | "file"; fileMeta?: MaskFileMeta }
  | { status: "error"; message: string };

export type MaskFileMeta = {
  inputPath: string;
  fileKind: "text" | "office" | string;
  sourceLabel: string;
  outputPath?: string;
};

export function maskContent(projectPath: string | null, content: string): Promise<MaskJsonOutput> {
  return invoke<MaskJsonOutput>("mask_content", { projectPath, content });
}

export function maskFile(
  projectPath: string | null,
  inputPath: string,
  outputPath?: string | null,
): Promise<MaskFileResult> {
  return invoke<MaskFileResult>("mask_file", {
    projectPath,
    inputPath,
    outputPath: outputPath ?? null,
  });
}

export function maskFileBasename(path: string): string {
  return path.split(/[/\\]/).pop() ?? path;
}

export function maskOfficeSuggestedName(sourceLabel: string): string {
  return sourceLabel.replace(/\.(docx|xlsx|pptx)$/i, ".masked.$1");
}

export function findingsBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts = Object.fromEntries(severityOrder.map((level) => [level, 0])) as Record<
    Severity,
    number
  >;
  for (const finding of findings) {
    const level = asSeverity(String(finding.severity));
    counts[level] += 1;
  }
  return counts;
}
