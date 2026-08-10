import { useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  isPermissionGranted,
  onAction,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import {
  BLOCKED_EVENT,
  NOTIFICATION_DEBOUNCE_MS,
  notifiableEvents,
  summarizeBlockedBatch,
  type BlockedNotificationEvent,
  type BlockedNotificationLabels,
  type NotificationSettings,
} from "../notifications";
import type { Project } from "../types";

/** Marks our own notifications so a click can be routed back to a project. */
const PROJECT_PATH_EXTRA_KEY = "shkProjectPath";

type Options = {
  projects: Project[];
  settings: NotificationSettings;
  labels: BlockedNotificationLabels;
  /** Focus a project in the UI when its notification is clicked. */
  onOpenProject: (projectId: string) => void;
};

/**
 * Tails every registered project's audit log while the app runs and raises an
 * OS notification when the hooks block AI activity.
 */
export function useBlockedNotifications({ projects, settings, labels, onOpenProject }: Options) {
  // Kept in refs so changing a preference or the project list never tears down
  // the event listener, which would drop blocks buffered for the next flush.
  const settingsRef = useRef(settings);
  const labelsRef = useRef(labels);
  const projectsRef = useRef(projects);
  const onOpenProjectRef = useRef(onOpenProject);
  settingsRef.current = settings;
  labelsRef.current = labels;
  projectsRef.current = projects;
  onOpenProjectRef.current = onOpenProject;

  const pendingRef = useRef<BlockedNotificationEvent[]>([]);
  const flushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const permissionGrantedRef = useRef(false);

  // Serialized so the effect re-runs only when membership actually changes,
  // and so paths containing spaces survive the round trip.
  const watchedPaths = JSON.stringify(projects.map((project) => project.path));

  useEffect(() => {
    const paths = JSON.parse(watchedPaths) as string[];
    void invoke("watch_blocked_projects", { paths }).catch(() => {
      // Watching is best-effort: the audit panel still shows blocks on refresh.
    });
  }, [watchedPaths]);

  useEffect(() => {
    let disposed = false;

    async function flush() {
      flushTimerRef.current = null;
      const batch = notifiableEvents(pendingRef.current, settingsRef.current);
      pendingRef.current = [];
      const content = summarizeBlockedBatch(
        batch,
        (path) => projectNameFor(projectsRef.current, path),
        labelsRef.current,
      );
      if (!content || disposed) return;

      if (!(await ensurePermission(permissionGrantedRef))) return;
      if (disposed) return;

      sendNotification({
        title: content.title,
        body: content.body,
        extra: content.projectPath ? { [PROJECT_PATH_EXTRA_KEY]: content.projectPath } : undefined,
      });
    }

    const unlistenPromise = listen<BlockedNotificationEvent[]>(BLOCKED_EVENT, (event) => {
      if (!Array.isArray(event.payload) || event.payload.length === 0) return;
      pendingRef.current.push(...event.payload);
      if (flushTimerRef.current !== null) return;
      flushTimerRef.current = setTimeout(() => void flush(), NOTIFICATION_DEBOUNCE_MS);
    });

    return () => {
      disposed = true;
      if (flushTimerRef.current !== null) {
        clearTimeout(flushTimerRef.current);
        flushTimerRef.current = null;
      }
      void unlistenPromise.then((unlisten) => unlisten()).catch(() => {});
    };
  }, []);

  useEffect(() => {
    // Click-to-open is best-effort: platforms that do not report notification
    // clicks simply never invoke this listener.
    let listener: { unregister: () => void } | null = null;
    let disposed = false;

    void onAction((notification) => {
      const path = notification.extra?.[PROJECT_PATH_EXTRA_KEY];
      if (typeof path !== "string") return;
      const project = projectsRef.current.find((candidate) => candidate.path === path);
      if (!project) return;
      void focusMainWindow();
      onOpenProjectRef.current(project.id);
    })
      .then((registered) => {
        listener = registered;
        if (disposed) registered.unregister();
      })
      .catch(() => {});

    return () => {
      disposed = true;
      listener?.unregister();
    };
  }, []);
}

function projectNameFor(projects: Project[], path: string): string {
  return projects.find((project) => project.path === path)?.name ?? path;
}

/**
 * Ask the OS once per denial. A granted result is cached; a denial is not, so
 * enabling notifications in system settings takes effect without a restart.
 */
async function ensurePermission(granted: { current: boolean }): Promise<boolean> {
  if (granted.current) return true;
  try {
    const allowed = (await isPermissionGranted()) || (await requestPermission()) === "granted";
    granted.current = allowed;
    return allowed;
  } catch {
    return false;
  }
}

async function focusMainWindow(): Promise<void> {
  try {
    const window = getCurrentWindow();
    await window.unminimize();
    await window.setFocus();
  } catch {
    /* focusing is a nicety; never let it break notification handling */
  }
}
