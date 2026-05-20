import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { WelcomeScreen } from "./components/WelcomeScreen";
import { ScanWorkspace } from "./components/ScanWorkspace";
import { useProjects } from "./hooks/useProjects";
import { asSeverity, type ScanReport, type ScanState, type Severity } from "./scan";

const APP_VERSION = "0.3.4";

function App() {
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

  const currentScanState: ScanState = selectedId
    ? (scanStates[selectedId] ?? { status: "idle" })
    : { status: "idle" };

  const setScanStateFor = useCallback((id: string, state: ScanState) => {
    setScanStates((prev) => ({ ...prev, [id]: state }));
  }, []);

  const openFolder = useCallback(async () => {
    try {
      const path = await open({
        directory: true,
        multiple: false,
        title: "スキャンするフォルダを選択",
      });
      if (typeof path === "string" && path) {
        addProject(path);
      }
    } catch (error) {
      console.error("failed to open folder:", error);
    }
  }, [addProject]);

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
      removeProject(id);
    },
    [removeProject],
  );

  const recentForWelcome = projects.slice(0, 6);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-transparent text-[var(--color-text)]">
      <Sidebar
        projects={projects}
        selectedId={selectedId}
        onSelect={selectProject}
        onAdd={openFolder}
        onRemove={handleRemove}
        onRename={renameProject}
        appVersion={APP_VERSION}
      />

      <main className="flex min-w-0 flex-1 flex-col">
        <TopBar project={selectedProject} onOpenFolder={openFolder} />

        {selectedProject ? (
          <ScanWorkspace
            key={selectedProject.id}
            project={selectedProject}
            scanState={currentScanState}
            onScan={runScan}
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
