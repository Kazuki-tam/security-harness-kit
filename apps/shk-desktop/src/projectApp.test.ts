import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  isEditorApp,
  isProjectApp,
  readPreferredProjectApp,
  LEGACY_PREFERRED_IDE_KEY,
  PREFERRED_PROJECT_APP_KEY,
} from "./projectApp";

class MemoryStorage {
  private store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}

describe("project app preferences", () => {
  beforeEach(() => {
    vi.stubGlobal("window", { localStorage: new MemoryStorage() });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("validates known project app ids", () => {
    expect(isProjectApp("cursor")).toBe(true);
    expect(isProjectApp("vscode")).toBe(true);
    expect(isProjectApp("antigravity")).toBe(true);
    expect(isProjectApp("claude-desktop")).toBe(true);
    expect(isProjectApp("chatgpt-desktop")).toBe(true);
    expect(isProjectApp("emacs")).toBe(false);
    expect(isProjectApp(null)).toBe(false);
  });

  it("classifies editor apps", () => {
    expect(isEditorApp("cursor")).toBe(true);
    expect(isEditorApp("claude-desktop")).toBe(false);
  });

  it("reads the new preference key first", () => {
    window.localStorage.setItem(PREFERRED_PROJECT_APP_KEY, "chatgpt-desktop");
    window.localStorage.setItem(LEGACY_PREFERRED_IDE_KEY, "vscode");
    expect(readPreferredProjectApp()).toBe("chatgpt-desktop");
  });

  it("migrates legacy IDE preference into the new key", () => {
    window.localStorage.removeItem(PREFERRED_PROJECT_APP_KEY);
    window.localStorage.setItem(LEGACY_PREFERRED_IDE_KEY, "antigravity");
    expect(readPreferredProjectApp()).toBe("antigravity");
    expect(window.localStorage.getItem(PREFERRED_PROJECT_APP_KEY)).toBe("antigravity");
  });

  it("defaults to cursor when no preference is stored", () => {
    window.localStorage.removeItem(PREFERRED_PROJECT_APP_KEY);
    window.localStorage.removeItem(LEGACY_PREFERRED_IDE_KEY);
    expect(readPreferredProjectApp()).toBe("cursor");
  });
});
