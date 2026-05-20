import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { WelcomeScreen } from "./components/WelcomeScreen";
import { ScanWorkspace } from "./components/ScanWorkspace";
import { useProjects } from "./hooks/useProjects";
import { useI18n } from "./i18n";
import {
  applyNpmHardening,
  applyRecommendedFixes,
  fetchProjectStatus,
  fixDoctorIgnore,
  initPolicy,
  installAiHooks,
  installPreCommitHook,
  installSkills,
} from "./project";
import { asSeverity, type ScanReport, type ScanState, type Severity } from "./scan";
import type { ActionState, ProjectStatusState } from "./types";

const APP_VERSION = "0.3.4";

function App() {
  const { messages } = useI18n();
  const {
    projects,
    selectedId,
    selectedProject,
    addProject,
    removeProject,
    selectProject,
    updateProjectSummary,
    renameProject,
  } = useProjects();

  const [scanStates, setScanStates] = useState<Record<string, ScanState>>({});
  const [projectStatusStates, setProjectStatusStates] = useState<
    Record<string, ProjectStatusState>
  >({});
  const [actionState, setActionState] = useState<ActionState>({ status: "idle" });

  const currentScanState: ScanState = selectedId
    ? (scanStates[selectedId] ?? { status: "idle" })
    : { status: "idle" };

  const currentProjectStatus: ProjectStatusState = selectedId
    ? (projectStatusStates[selectedId] ?? { status: "idle" })
    : { status: "idle" };

  const setScanStateFor = useCallback((id: string, state: ScanState) => {
    setScanStates((prev) => ({ ...prev, [id]: state }));
  }, []);

  const refreshProjectStatus = useCallback(async (projectId: string, path: string) => {
    setProjectStatusStates((prev) => ({ ...prev, [projectId]: { status: "loading" } }));
    try {
      const data = await fetchProjectStatus(path);
      setProjectStatusStates((prev) => ({
        ...prev,
        [projectId]: { status: "done", data, loadedAt: new Date().toISOString() },
      }));
    } catch (error) {
      setProjectStatusStates((prev) => ({
        ...prev,
        [projectId]: {
          status: "error",
          message: error instanceof Error ? error.message : String(error),
        },
      }));
    }
  }, []);

  useEffect(() => {
    if (!selectedProject) return;
    void refreshProjectStatus(selectedProject.id, selectedProject.path);
  }, [selectedProject?.id, selectedProject?.path, refreshProjectStatus]);

  const runSetupAction = useCallback(
    async (runner: () => Promise<{ success: boolean; message: string; details: string[] }>) => {
      if (!selectedProject) return;
      setActionState({ status: "running" });
      try {
        const result = await runner();
        setActionState({ status: "done", result });
        await refreshProjectStatus(selectedProject.id, selectedProject.path);
      } catch (error) {
        setActionState({
          status: "error",
          message: error instanceof Error ? error.message : String(error),
        });
      }
    },
    [refreshProjectStatus, selectedProject],
  );

  const openFolder = useCallback(async () => {
    try {
      const path = await open({
        directory: true,
        multiple: false,
        title: messages.app.selectFolder,
      });
      if (typeof path === "string" && path) {
        addProject(path);
      }
    } catch (error) {
      console.error("failed to open folder:", error);
    }
  }, [addProject, messages.app.selectFolder]);

  const runScan = useCallback(async () => {
    if (!selectedProject) return;
    if (currentScanState.status === "running") return;

    const projectId = selectedProject.id;
    setScanStateFor(projectId, { status: "running" });
    try {
      const report = await invoke<ScanReport>("scan_path", {
        path: selectedProject.path,
      });
      const finishedAt = new Date().toISOString();
      setScanStateFor(projectId, { status: "done", report, finishedAt });

      const bySeverity: Partial<Record<Severity, number>> = {};
      for (const [key, value] of Object.entries(report.summary.by_severity)) {
        bySeverity[asSeverity(key)] = value;
      }
      updateProjectSummary(projectId, {
        total: report.summary.total,
        bySeverity,
        scannedAt: finishedAt,
      });
    } catch (error) {
      setScanStateFor(projectId, {
        status: "error",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }, [currentScanState.status, selectedProject, setScanStateFor, updateProjectSummary]);

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const cmdOrCtrl = event.metaKey || event.ctrlKey;
      if (cmdOrCtrl && event.key.toLowerCase() === "o") {
        event.preventDefault();
        void openFolder();
      }
      if (cmdOrCtrl && event.key.toLowerCase() === "r") {
        event.preventDefault();
        void runScan();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openFolder, runScan]);

  const handleRemove = useCallback(
    (id: string) => {
      setScanStates((prev) => {
        if (!(id in prev)) return prev;
        const next = { ...prev };
        delete next[id];
        return next;
      });
      setProjectStatusStates((prev) => {
        if (!(id in prev)) return prev;
        const next = { ...prev };
        delete next[id];
        return next;
      });
      removeProject(id);
    },
    [removeProject],
  );

  const setupHandlers = selectedProject
    ? {
        onInitPolicy: (strict: boolean) =>
          runSetupAction(() =>
            initPolicy(selectedProject.path, {
              strict,
              force:
                strict ||
                (currentProjectStatus.status === "done" && currentProjectStatus.data.policy.exists),
            }),
          ),
        onApplyRecommendedFixes: (fixIds: string[], ignoreTargets: string[]) =>
          runSetupAction(() =>
            applyRecommendedFixes(selectedProject.path, { fixIds, ignoreTargets }),
          ),
        onFixDoctorIgnore: (targets: string[]) =>
          runSetupAction(() => fixDoctorIgnore(selectedProject.path, { targets })),
        onInstallPreCommit: () => runSetupAction(() => installPreCommitHook(selectedProject.path)),
        onInstallAiHooks: () =>
          runSetupAction(() =>
            installAiHooks(selectedProject.path, {
              audit: false,
              dryRun: false,
              global: false,
              failClosed: false,
              applyDeny: false,
              applySandbox: false,
            }),
          ),
        onInstallClaudeDeny: () =>
          runSetupAction(() =>
            installAiHooks(selectedProject.path, {
              audit: false,
              dryRun: false,
              global: false,
              tool: "claude-code",
              failClosed: false,
              applyDeny: true,
              applySandbox: false,
            }),
          ),
        onInstallCodexSandbox: () =>
          runSetupAction(() =>
            installAiHooks(selectedProject.path, {
              audit: false,
              dryRun: false,
              global: false,
              tool: "codex",
              failClosed: false,
              applyDeny: false,
              applySandbox: true,
            }),
          ),
        onApplyNpmHardening: () => runSetupAction(() => applyNpmHardening(selectedProject.path)),
        onInstallSkills: () =>
          runSetupAction(() =>
            installSkills(selectedProject.path, {
              global: false,
              dryRun: false,
              force: true,
            }),
          ),
      }
    : undefined;

  const recentForWelcome = projects.slice(0, 6);
  const showSidebar = projects.length > 0;

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-transparent text-text">
      {showSidebar && (
        <Sidebar
          projects={projects}
          selectedId={selectedId}
          onSelect={selectProject}
          onAdd={openFolder}
          onRemove={handleRemove}
          onRename={renameProject}
          appVersion={APP_VERSION}
        />
      )}

      <main className="flex min-w-0 flex-1 flex-col">
        <TopBar
          project={selectedProject}
          reserveWindowControls={!showSidebar}
          onOpenFolder={openFolder}
        />

        {selectedProject ? (
          <ScanWorkspace
            key={selectedProject.id}
            project={selectedProject}
            scanState={currentScanState}
            projectStatus={currentProjectStatus}
            actionState={actionState}
            onScan={runScan}
            setupHandlers={setupHandlers}
          />
        ) : (
          <WelcomeScreen
            recentProjects={recentForWelcome}
            totalProjects={projects.length}
            onOpenFolder={openFolder}
            onSelect={selectProject}
          />
        )}
      </main>
    </div>
  );
}

export default App;
