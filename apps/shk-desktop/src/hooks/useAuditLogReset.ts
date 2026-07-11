import { useCallback, useState } from "react";
import { clearAuditLog } from "../project";

export type AuditLogResetOutcome = { ok: true } | { ok: false; message: string };

export type AuditLogResetState = {
  confirming: boolean;
  busy: boolean;
  error: string | null;
  requestConfirm: () => void;
  cancelConfirm: () => void;
  confirmAndReset: () => Promise<boolean>;
};

/** Invoke clear_audit_log and normalize success/error for the UI. */
export async function performAuditLogReset(
  projectPath: string,
  fallbackError: string,
): Promise<AuditLogResetOutcome> {
  try {
    const result = await clearAuditLog(projectPath);
    if (!result.success) {
      return { ok: false, message: result.message || fallbackError };
    }
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      message: err instanceof Error ? err.message : String(err) || fallbackError,
    };
  }
}

/** Confirmation + invoke flow for clearing `.shk/audit.log`. */
export function useAuditLogReset(projectPath: string, fallbackError: string): AuditLogResetState {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const requestConfirm = useCallback(() => {
    setError(null);
    setConfirming(true);
  }, []);

  const cancelConfirm = useCallback(() => {
    setConfirming(false);
  }, []);

  const confirmAndReset = useCallback(async () => {
    setConfirming(false);
    setBusy(true);
    setError(null);
    try {
      const outcome = await performAuditLogReset(projectPath, fallbackError);
      if (!outcome.ok) {
        setError(outcome.message);
        return false;
      }
      return true;
    } finally {
      setBusy(false);
    }
  }, [fallbackError, projectPath]);

  return {
    confirming,
    busy,
    error,
    requestConfirm,
    cancelConfirm,
    confirmAndReset,
  };
}
