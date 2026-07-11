import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { HelpModal } from "./components/HelpModal";
import { MaskWorkspace } from "./components/MaskWorkspace";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { WelcomeScreen } from "./components/WelcomeScreen";
import { ScanWorkspace } from "./components/ScanWorkspace";
import { usePreferredAiTool } from "./hooks/usePreferredAiTool";
import { usePreferredIde } from "./hooks/usePreferredIde";
import { useProjects } from "./hooks/useProjects";
import { openInIde, type PreferredIde } from "./ide";
import { useI18n } from "./i18n";
import packageInfo from "../package.json";
import {
  applyAiHookSettings,
  applyNpmHardening,
  applyRecommendedFixes,
  cloneRepository,
  fetchProjectStatus,
  fixDoctorIgnore,
  initPolicy,
  installPreCommitHook,
  installSkills,
} from "./project";
import { defaultRecommendedFixIds } from "./setup/plan";
import { asSeverity, type ScanReport, type ScanState, type Severity } from "./scan";
import type { ActionResult, ActionState, AiHookSetupSelection, ProjectStatusState } from "./types";

const APP_VERSION = packageInfo.version;

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

  const [currentView, setCurrentView] = useState<"welcome" | "project" | "mask">(() =>
    selectedProject ? "project" : "welcome",
  );
  const [scanStates, setScanStates] = useState<Record<string, ScanState>>({});
  const [projectStatusStates, setProjectStatusStates] = useState<
    Record<string, ProjectStatusState>
  >({});
  const [actionState, setActionState] = useState<ActionState>({ status: "idle" });
  const [helpOpen, setHelpOpen] = useState(false);
  const { preferredIde, setPreferredIde } = usePreferredIde();
  const { preferredAiTool, setPreferredAiTool } = usePreferredAiTool();
  const activeProject = currentView === "project" ? selectedProject : null;
  const maskProjectPath = selectedProject?.path ?? null;

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
    if (!activeProject) return;
    void refreshProjectStatus(activeProject.id, activeProject.path);
  }, [activeProject?.id, activeProject?.path, refreshProjectStatus]);

  const dismissActionFeedback = useCallback(() => {
    setActionState({ status: "idle" });
  }, []);

  const runSetupAction = useCallback(
    async (runner: () => Promise<{ success: boolean; message: string; details: string[] }>) => {
      if (!activeProject) return;
      setActionState({ status: "running" });
      try {
        const result = await runner();
        setActionState({ status: "done", result });
        await refreshProjectStatus(activeProject.id, activeProject.path);
      } catch (error) {
        setActionState({
          status: "error",
          message: error instanceof Error ? error.message : String(error),
        });
      }
    },
    [activeProject, refreshProjectStatus],
  );

  const showWelcome = useCallback(() => {
    setCurrentView("welcome");
  }, []);

  const showMask = useCallback(() => {
    setCurrentView("mask");
  }, []);

  const showProject = useCallback(
    (id: string) => {
      selectProject(id);
      setCurrentView("project");
    },
    [selectProject],
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
        setCurrentView("project");
      }
    } catch (error) {
      console.error("failed to open folder:", error);
    }
  }, [addProject, messages.app.selectFolder]);

  const cloneGitRepository = useCallback(
    async (remoteUrl: string): Promise<boolean> => {
      const destinationParent = await open({
        directory: true,
        multiple: false,
        title: messages.app.selectCloneDestination,
      });
      if (typeof destinationParent !== "string" || !destinationParent) return false;

      const result = await cloneRepository(remoteUrl, destinationParent);
      addProject(result.path);
      setCurrentView("project");
      return true;
    },
    [addProject, messages.app.selectCloneDestination],
  );

  const openProjectInIde = useCallback(
    async (ide: PreferredIde) => {
      setPreferredIde(ide);
      try {
        let path = activeProject?.path;
        if (!path) {
          const picked = await open({
            directory: true,
            multiple: false,
            title: messages.app.selectFolderForIde,
          });
          if (typeof picked !== "string" || !picked) return;
          path = picked;
          addProject(path);
          setCurrentView("project");
        }
        await openInIde(path, ide);
      } catch (error) {
        console.error("failed to open project in IDE:", error);
      }
    },
    [activeProject?.path, addProject, messages.app.selectFolderForIde, setPreferredIde],
  );

  const runScan = useCallback(async () => {
    if (!activeProject) return;
    if (currentScanState.status === "running") return;

    const projectId = activeProject.id;
    const previousResult =
      currentScanState.status === "done"
        ? { report: currentScanState.report, finishedAt: currentScanState.finishedAt }
        : currentScanState.status === "error"
          ? currentScanState.previous
          : undefined;
    setScanStateFor(projectId, {
      status: "running",
      startedAt: new Date().toISOString(),
      previous: previousResult,
    });
    try {
      const report = await invoke<ScanReport>("scan_path", {
        path: activeProject.path,
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
        previous: previousResult,
      });
    }
  }, [activeProject, currentScanState, setScanStateFor, updateProjectSummary]);

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      const isEditing =
        target?.isContentEditable ||
        target?.tagName === "INPUT" ||
        target?.tagName === "TEXTAREA" ||
        target?.tagName === "SELECT";
      if (event.defaultPrevented || isEditing || document.querySelector('[aria-modal="true"]')) {
        return;
      }

      const cmdOrCtrl = event.metaKey || event.ctrlKey;
      if (cmdOrCtrl && event.key.toLowerCase() === "o") {
        event.preventDefault();
        void openFolder();
      }
      if (cmdOrCtrl && event.key.toLowerCase() === "r") {
        event.preventDefault();
        void runScan();
      }
      if (cmdOrCtrl && event.shiftKey && event.key.toLowerCase() === "n") {
        event.preventDefault();
        showWelcome();
      }
      if (cmdOrCtrl && event.key.toLowerCase() === "m") {
        event.preventDefault();
        showMask();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openFolder, runScan, showMask, showWelcome]);

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

  const setupHandlers = activeProject
    ? {
        onQuickSetup: (fixIds: string[], ignoreTargets: string[]) =>
          runSetupAction(async (): Promise<ActionResult> => {
            const path = activeProject.path;
            let status = await fetchProjectStatus(path);
            const hadPolicy = Boolean(status?.policy.exists);

            if (!hadPolicy) {
              const policyResult = await initPolicy(path, { strict: false, force: false });
              if (!policyResult.success) return policyResult;
              status = await fetchProjectStatus(path);
            }

            const ids =
              hadPolicy && fixIds.length > 0 ? fixIds : defaultRecommendedFixIds(status, true);
            if (ids.length === 0) {
              return {
                success: true,
                message: "No changes were required for the selected fixes",
                details: [],
              };
            }
            return applyRecommendedFixes(path, { fixIds: ids, ignoreTargets });
          }),
        onInitPolicy: (request: { strict: boolean; force: boolean }) =>
          runSetupAction(() => initPolicy(activeProject.path, request)),
        onFixDoctorIgnore: (targets: string[]) =>
          runSetupAction(() => fixDoctorIgnore(activeProject.path, { targets })),
        onInstallPreCommit: () => runSetupAction(() => installPreCommitHook(activeProject.path)),
        onInstallAiHooks: (selection: AiHookSetupSelection) =>
          runSetupAction(() => applyAiHookSettings(activeProject.path, selection)),
        onApplyNpmHardening: (enabled: boolean) =>
          runSetupAction(() => applyNpmHardening(activeProject.path, { enabled })),
        onInstallSkills: () =>
          runSetupAction(() =>
            installSkills(activeProject.path, {
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
          selectedId={activeProject?.id ?? null}
          maskActive={currentView === "mask"}
          onSelect={showProject}
          onShowWelcome={showWelcome}
          onShowMask={showMask}
          onAdd={openFolder}
          onRemove={handleRemove}
          onRename={renameProject}
          appVersion={APP_VERSION}
        />
      )}

      <main className="flex min-w-0 flex-1 flex-col">
        <TopBar
          view={currentView}
          project={activeProject}
          reserveWindowControls={!showSidebar}
          preferredIde={preferredIde}
          onOpenInIde={openProjectInIde}
          onShowHelp={() => setHelpOpen(true)}
        />

        {currentView === "mask" ? (
          <MaskWorkspace
            projectPath={maskProjectPath}
            preferredAiTool={preferredAiTool}
            onPreferredAiToolChange={setPreferredAiTool}
          />
        ) : activeProject ? (
          <ScanWorkspace
            key={activeProject.id}
            project={activeProject}
            scanState={currentScanState}
            projectStatus={currentProjectStatus}
            actionState={actionState}
            onDismissActionFeedback={dismissActionFeedback}
            onScan={runScan}
            setupHandlers={setupHandlers}
          />
        ) : (
          <WelcomeScreen
            recentProjects={recentForWelcome}
            totalProjects={projects.length}
            onOpenFolder={openFolder}
            onCloneRepository={cloneGitRepository}
            onSelect={showProject}
            onShowMask={showMask}
          />
        )}
      </main>
      <HelpModal open={helpOpen} onClose={() => setHelpOpen(false)} />
    </div>
  );
}

export default App;
