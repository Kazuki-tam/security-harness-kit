import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { loadAuditReport } from "../audit";
import { BLOCKED_EVENT, type BlockedNotificationEvent } from "../notifications";
import type { AuditState } from "../types";

export type RefreshAuditOptions = {
  /** Keep the current report visible while reloading (avoids full-panel flicker). */
  silent?: boolean;
};

/**
 * How long live blocks are collected before the panel reloads. A refresh
 * re-reads and parses the whole audit log (including rotated archives), which
 * costs hundreds of milliseconds on a mature project, so a burst of blocks must
 * not turn into a refresh every couple of seconds.
 */
const LIVE_REFRESH_DEBOUNCE_MS = 10_000;

export function useAuditReport(projectPath: string, refreshToken?: string | null) {
  const [auditState, setAuditState] = useState<AuditState>({ status: "idle" });
  const requestIdRef = useRef(0);

  const refreshAudit = useCallback(
    async (options: RefreshAuditOptions = {}) => {
      const requestId = requestIdRef.current + 1;
      requestIdRef.current = requestId;
      if (!options.silent) {
        setAuditState({ status: "loading" });
      }
      const nextState = await loadAuditReport(projectPath);
      if (requestId === requestIdRef.current) {
        setAuditState(nextState);
      }
    },
    [projectPath],
  );

  useEffect(() => {
    void refreshAudit();
  }, [refreshAudit, refreshToken]);

  // Keep the panel in step with the notifications: a block that raised a banner
  // should be listed by the time the user comes back to the window.
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | null = null;

    const unlistenPromise = listen<BlockedNotificationEvent[]>(BLOCKED_EVENT, (event) => {
      if (!event.payload?.some((blocked) => blocked.project_path === projectPath)) return;
      timer ??= setTimeout(() => {
        timer = null;
        // Nothing to keep in step with while the window is hidden; the panel
        // reloads anyway when the project is next opened.
        if (document.visibilityState === "hidden") return;
        void refreshAudit({ silent: true });
      }, LIVE_REFRESH_DEBOUNCE_MS);
    });

    return () => {
      if (timer !== null) clearTimeout(timer);
      void unlistenPromise.then((unlisten) => unlisten()).catch(() => {});
    };
  }, [projectPath, refreshAudit]);

  return { auditState, refreshAudit };
}
