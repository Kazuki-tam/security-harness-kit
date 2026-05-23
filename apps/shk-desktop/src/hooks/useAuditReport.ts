import { useCallback, useEffect, useRef, useState } from "react";
import { loadAuditReport } from "../audit";
import type { AuditState } from "../types";

export function useAuditReport(projectPath: string, refreshToken?: string | null) {
  const [auditState, setAuditState] = useState<AuditState>({ status: "idle" });
  const requestIdRef = useRef(0);

  const refreshAudit = useCallback(async () => {
    const requestId = requestIdRef.current + 1;
    requestIdRef.current = requestId;
    setAuditState({ status: "loading" });
    const nextState = await loadAuditReport(projectPath);
    if (requestId === requestIdRef.current) {
      setAuditState(nextState);
    }
  }, [projectPath]);

  useEffect(() => {
    void refreshAudit();
  }, [refreshAudit, refreshToken]);

  return { auditState, refreshAudit };
}
