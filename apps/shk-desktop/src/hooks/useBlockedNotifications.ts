import { useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { sendNotification } from "@tauri-apps/plugin-notification";
import {
  BLOCKED_EVENT,
  createBlockedNotificationBatcher,
  type BlockedNotificationEvent,
  type BlockedNotificationLabels,
  type NotificationSettings,
} from "../notifications";
import type { Project } from "../types";

type Options = {
  projects: Project[];
  settings: NotificationSettings;
  labels: BlockedNotificationLabels;
};

/**
 * Tails every registered project's audit log while the app runs and raises an
 * OS notification when the hooks block AI activity.
 *
 * Notifications are display-only: the plugin's click callback is mobile-only,
 * so there is nothing to route back into the app.
 */
export function useBlockedNotifications({ projects, settings, labels }: Options) {
  // Read through refs at flush time so changing a preference or renaming a
  // project never tears down the subscription, which would drop buffered
  // blocks.
  const settingsRef = useRef(settings);
  const labelsRef = useRef(labels);
  const projectsRef = useRef(projects);
  useEffect(() => {
    settingsRef.current = settings;
    labelsRef.current = labels;
    projectsRef.current = projects;
  });

  // Serialized so the effect re-runs only when membership actually changes,
  // and so paths containing spaces survive the round trip.
  const watchedPaths = JSON.stringify(projects.map((project) => project.path));

  useEffect(() => {
    const paths = JSON.parse(watchedPaths) as string[];
    void invoke("watch_blocked_projects", { paths }).catch((error: unknown) => {
      console.warn("failed to watch projects for blocked activity", error);
    });
  }, [watchedPaths]);

  useEffect(() => {
    // Built per subscription so a remount cannot flush through a batcher whose
    // listener is already gone.
    const batcher = createBlockedNotificationBatcher({
      getSettings: () => settingsRef.current,
      getLabels: () => labelsRef.current,
      projectNameFor: (path) => projectNameFor(projectsRef.current, path, labelsRef.current),
      // No permission gate. On desktop the plugin's `isPermissionGranted` /
      // `requestPermission` delegate to the WebView's `window.Notification`,
      // which WKWebView does not implement — so they report "denied" and would
      // suppress every notification. The Rust side reports `Granted`
      // unconditionally on desktop and `notify` performs no permission check;
      // macOS itself prompts on the first banner and owns the answer.
      notify: sendNotification,
    });

    const unlistenPromise = listen<BlockedNotificationEvent[]>(BLOCKED_EVENT, (event) => {
      if (Array.isArray(event.payload)) batcher.push(event.payload);
    });

    return () => {
      batcher.cancel();
      void unlistenPromise
        .then((unlisten) => unlisten())
        .catch((error: unknown) => {
          console.warn("failed to stop listening for blocked activity", error);
        });
    };
  }, []);
}

function projectNameFor(
  projects: Project[],
  path: string,
  labels: BlockedNotificationLabels,
): string {
  // Never fall back to the raw path: it would put a filesystem location on the
  // lock screen, which is exactly what the payload avoids carrying.
  return projects.find((project) => project.path === path)?.name ?? labels.unknownProject;
}
