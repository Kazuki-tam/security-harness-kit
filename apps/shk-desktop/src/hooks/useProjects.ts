import { useCallback, useEffect, useMemo, useState } from "react";
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
  const [{ projects, selectedId }, setState] = useState<PersistedState>(() => loadPersisted());

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
    const created: Project = {
      id: generateId(),
      name: basenameOf(trimmed) || trimmed,
      path: trimmed,
      addedAt: new Date().toISOString(),
    };

    setState((prev) => {
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
  }, []);

  const removeProject = useCallback((id: string) => {
    setState((prev) => {
      const projects = prev.projects.filter((p) => p.id !== id);
      const selectedId = prev.selectedId === id ? (projects[0]?.id ?? null) : prev.selectedId;
      return { projects, selectedId };
    });
  }, []);

  const selectProject = useCallback((id: string | null) => {
    setState((prev) => ({ ...prev, selectedId: id }));
  }, []);

  const updateProjectSummary = useCallback((id: string, summary: ProjectSummary) => {
    setState((prev) => ({
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
  }, []);

  const renameProject = useCallback((id: string, name: string) => {
    const next = name.trim();
    if (!next) return;
    setState((prev) => ({
      ...prev,
      projects: prev.projects.map((p) => (p.id === id ? { ...p, name: next } : p)),
    }));
  }, []);

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
