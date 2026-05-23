import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Project, ProjectSummary } from "../types";
import { basenameOf, generateId } from "../utils";

const PROJECTS_KEY = "shk.desktop.projects.v1";
const SELECTED_KEY = "shk.desktop.selectedProjectId.v1";

type PersistedState = {
  projects: Project[];
  selectedId: string | null;
};

function loadPersisted(): PersistedState {
  if (typeof window === "undefined") {
    return { projects: [], selectedId: null };
  }
  try {
    const raw = window.localStorage.getItem(PROJECTS_KEY);
    const projects: Project[] = raw ? JSON.parse(raw) : [];
    const selectedId = window.localStorage.getItem(SELECTED_KEY);
    return {
      projects: Array.isArray(projects) ? projects : [],
      selectedId: selectedId && projects.some((p) => p.id === selectedId) ? selectedId : null,
    };
  } catch {
    return { projects: [], selectedId: null };
  }
}

export function useProjects() {
  const [state, setState] = useState<PersistedState>(() => loadPersisted());
  const stateRef = useRef(state);
  const { projects, selectedId } = state;

  const updateState = useCallback((updater: (prev: PersistedState) => PersistedState) => {
    const next = updater(stateRef.current);
    stateRef.current = next;
    setState(next);
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(PROJECTS_KEY, JSON.stringify(projects));
    } catch {
      /* ignore quota errors */
    }
  }, [projects]);

  useEffect(() => {
    try {
      if (selectedId) {
        window.localStorage.setItem(SELECTED_KEY, selectedId);
      } else {
        window.localStorage.removeItem(SELECTED_KEY);
      }
    } catch {
      /* ignore */
    }
  }, [selectedId]);

  const addProject = useCallback((path: string): Project => {
    const trimmed = path.trim();
    const existing = stateRef.current.projects.find((p) => p.path === trimmed);
    if (existing) {
      updateState((prev) => ({ projects: prev.projects, selectedId: existing.id }));
      return existing;
    }

    const created: Project = {
      id: generateId(),
      name: basenameOf(trimmed) || trimmed,
      path: trimmed,
      addedAt: new Date().toISOString(),
    };

    updateState((prev) => {
      const existing = prev.projects.find((p) => p.path === trimmed);
      if (existing) {
        return { projects: prev.projects, selectedId: existing.id };
      }
      return {
        projects: [created, ...prev.projects],
        selectedId: created.id,
      };
    });

    return created;
  }, [updateState]);

  const removeProject = useCallback((id: string) => {
    updateState((prev) => {
      const projects = prev.projects.filter((p) => p.id !== id);
      const selectedId = prev.selectedId === id ? (projects[0]?.id ?? null) : prev.selectedId;
      return { projects, selectedId };
    });
  }, [updateState]);

  const selectProject = useCallback((id: string | null) => {
    updateState((prev) => ({ ...prev, selectedId: id }));
  }, [updateState]);

  const updateProjectSummary = useCallback((id: string, summary: ProjectSummary) => {
    updateState((prev) => ({
      ...prev,
      projects: prev.projects.map((p) =>
        p.id === id
          ? {
              ...p,
              summary,
              lastScannedAt: summary.scannedAt,
            }
          : p,
      ),
    }));
  }, [updateState]);

  const renameProject = useCallback((id: string, name: string) => {
    const next = name.trim();
    if (!next) return;
    updateState((prev) => ({
      ...prev,
      projects: prev.projects.map((p) => (p.id === id ? { ...p, name: next } : p)),
    }));
  }, [updateState]);

  const selectedProject = useMemo(
    () => projects.find((p) => p.id === selectedId) ?? null,
    [projects, selectedId],
  );

  return {
    projects,
    selectedId,
    selectedProject,
    addProject,
    removeProject,
    selectProject,
    updateProjectSummary,
    renameProject,
  };
}
