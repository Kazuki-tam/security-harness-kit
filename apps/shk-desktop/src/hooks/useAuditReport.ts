import { useCallback, useEffect, useRef, useState } from "react";
import { loadAuditReport } from "../audit";
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

  return { auditState, refreshAudit };
}
