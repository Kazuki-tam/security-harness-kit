import { invoke } from "@tauri-apps/api/core";

export const PREFERRED_PROJECT_APP_KEY = "shk.preferredProjectApp";
export const LEGACY_PREFERRED_IDE_KEY = "shk.preferredIde";
export const DEFAULT_PREFERRED_PROJECT_APP = "cursor";

export const EDITOR_OPTIONS = ["cursor", "vscode", "antigravity"] as const;
export const AI_APP_OPTIONS = ["claude-desktop", "chatgpt-desktop"] as const;
export const PROJECT_APP_OPTIONS = [...EDITOR_OPTIONS, ...AI_APP_OPTIONS] as const;

export const PROJECT_APP_SECTIONS = [
  { labelKey: "editorSection", options: EDITOR_OPTIONS },
  { labelKey: "aiAppSection", options: AI_APP_OPTIONS },
] as const;

export type EditorApp = (typeof EDITOR_OPTIONS)[number];
export type AiApp = (typeof AI_APP_OPTIONS)[number];
export type ProjectApp = (typeof PROJECT_APP_OPTIONS)[number];
export type ProjectAppSectionLabelKey = (typeof PROJECT_APP_SECTIONS)[number]["labelKey"];

export function isProjectApp(value: string | null): value is ProjectApp {
  return PROJECT_APP_OPTIONS.includes(value as ProjectApp);
}

export function isEditorApp(app: ProjectApp): app is EditorApp {
  return EDITOR_OPTIONS.includes(app as EditorApp);
}

function persistPreferredProjectApp(app: ProjectApp): void {
  try {
    window.localStorage.setItem(PREFERRED_PROJECT_APP_KEY, app);
  } catch (error) {
    console.warn("failed to persist preferred project app", error);
  }
}

export function readPreferredProjectApp(): ProjectApp {
  if (typeof window === "undefined") return DEFAULT_PREFERRED_PROJECT_APP;
  try {
    const stored = window.localStorage.getItem(PREFERRED_PROJECT_APP_KEY);
    if (isProjectApp(stored)) return stored;

    const legacy = window.localStorage.getItem(LEGACY_PREFERRED_IDE_KEY);
    if (isProjectApp(legacy)) {
      persistPreferredProjectApp(legacy);
      return legacy;
    }
  } catch (error) {
    console.warn("failed to read preferred project app", error);
  }
  return DEFAULT_PREFERRED_PROJECT_APP;
}

export async function openProjectInApp(path: string, app: ProjectApp): Promise<void> {
  await invoke<void>("open_project_in_app", { path, app });
}
