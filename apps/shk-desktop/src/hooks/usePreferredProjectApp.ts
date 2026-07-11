import { useCallback, useState } from "react";
import { type ProjectApp, PREFERRED_PROJECT_APP_KEY, readPreferredProjectApp } from "../projectApp";

export function usePreferredProjectApp() {
  const [preferredProjectApp, setPreferredProjectAppState] =
    useState<ProjectApp>(readPreferredProjectApp);

  const setPreferredProjectApp = useCallback((next: ProjectApp) => {
    setPreferredProjectAppState(next);
    try {
      window.localStorage.setItem(PREFERRED_PROJECT_APP_KEY, next);
    } catch (error) {
      console.warn("failed to save preferred project app", error);
    }
  }, []);

  return { preferredProjectApp, setPreferredProjectApp };
}
