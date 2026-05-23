import { invoke } from "@tauri-apps/api/core";

export const PREFERRED_IDE_KEY = "shk.preferredIde";
export const DEFAULT_PREFERRED_IDE = "cursor";

export const IDE_OPTIONS = ["cursor", "vscode", "antigravity"] as const;

export type PreferredIde = (typeof IDE_OPTIONS)[number];

export function isPreferredIde(value: string | null): value is PreferredIde {
  return IDE_OPTIONS.includes(value as PreferredIde);
}

export function readPreferredIde(): PreferredIde {
  if (typeof window === "undefined") return DEFAULT_PREFERRED_IDE;
  try {
    const stored = window.localStorage.getItem(PREFERRED_IDE_KEY);
    return isPreferredIde(stored) ? stored : DEFAULT_PREFERRED_IDE;
  } catch (error) {
    console.warn("failed to read preferred IDE", error);
    return DEFAULT_PREFERRED_IDE;
  }
}

export async function openInIde(path: string, ide: PreferredIde): Promise<void> {
  await invoke<void>("open_in_ide", { path, ide });
}
