import { invoke } from "@tauri-apps/api/core";

export const PREFERRED_AI_TOOL_KEY = "shk.preferredAiTool";
export const DEFAULT_PREFERRED_AI_TOOL = "claude-desktop";

export const AI_TOOL_OPTIONS = ["claude-desktop", "chatgpt-desktop", "cursor", "vscode"] as const;

export type PreferredAiTool = (typeof AI_TOOL_OPTIONS)[number];

export function isPreferredAiTool(value: string | null): value is PreferredAiTool {
  return AI_TOOL_OPTIONS.includes(value as PreferredAiTool);
}

export function readPreferredAiTool(): PreferredAiTool {
  if (typeof window === "undefined") return DEFAULT_PREFERRED_AI_TOOL;
  try {
    const stored = window.localStorage.getItem(PREFERRED_AI_TOOL_KEY);
    return isPreferredAiTool(stored) ? stored : DEFAULT_PREFERRED_AI_TOOL;
  } catch (error) {
    console.warn("failed to read preferred AI tool", error);
    return DEFAULT_PREFERRED_AI_TOOL;
  }
}

export async function openAiTool(tool: PreferredAiTool): Promise<void> {
  await invoke<void>("open_ai_tool", { tool });
}
