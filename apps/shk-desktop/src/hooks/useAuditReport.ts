import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { loadAuditReport } from "../audit";
import { BLOCKED_EVENT, type BlockedNotificationEvent } from "../notifications";
import type { AuditState } from "../types";

export type RefreshAuditOptions = {
  /** Keep the current report visible while reloading (avoids full-panel flicker). */
  silent?: boolean;
};

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

  // Keep the panel in step with the notification: a block that raised a banner
  // should already be listed by the time the user comes back to the window.
  useEffect(() => {
    const unlistenPromise = listen<BlockedNotificationEvent[]>(BLOCKED_EVENT, (event) => {
      if (!event.payload?.some((blocked) => blocked.project_path === projectPath)) return;
      void refreshAudit({ silent: true });
    });
    return () => {
      void unlistenPromise.then((unlisten) => unlisten()).catch(() => {});
    };
  }, [projectPath, refreshAudit]);

  return { auditState, refreshAudit };
}
