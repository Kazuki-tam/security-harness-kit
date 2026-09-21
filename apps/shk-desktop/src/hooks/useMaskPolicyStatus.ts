import { useEffect, useState } from "react";
import { useI18n } from "../i18n";
import { fetchMaskPolicyStatus, type MaskPolicyStatus } from "../mask";
import type { Project } from "../types";

type PolicyStatusState =
  | { status: "loading"; projectPath: string }
  | { status: "done"; projectPath: string | null; data: MaskPolicyStatus }
  | { status: "error"; projectPath: string; message: string };

export type PolicyTone = "default" | "loading" | "error" | "project";

const NO_PROJECT: PolicyStatusState = {
  status: "done",
  projectPath: null,
  data: { usesProjectPolicy: false },
};

/** Whether the selected project actually carries an shk.toml, with display labels. */
export function useMaskPolicyStatus(policyProject: Project | undefined) {
  const { messages, t } = useI18n();
  const m = messages.mask;
  const projectPath = policyProject?.path ?? null;
  const [policyStatus, setPolicyStatus] = useState<PolicyStatusState>(NO_PROJECT);

  useEffect(() => {
    if (!projectPath) {
      setPolicyStatus(NO_PROJECT);
      return;
    }

    let disposed = false;
    setPolicyStatus({ status: "loading", projectPath });
    void fetchMaskPolicyStatus(projectPath)
      .then((data) => {
        if (!disposed) {
          setPolicyStatus({ status: "done", projectPath, data });
        }
      })
      .catch((error) => {
        if (!disposed) {
          setPolicyStatus({
            status: "error",
            projectPath,
            message: error instanceof Error ? error.message : String(error),
          });
        }
      });
    return () => {
      disposed = true;
    };
  }, [projectPath]);

  const current: PolicyStatusState =
    policyStatus.projectPath === projectPath
      ? policyStatus
      : projectPath
        ? { status: "loading", projectPath }
        : NO_PROJECT;

  const usesProjectPolicy = current.status === "done" && current.data.usesProjectPolicy;
  const policyLabel = !policyProject
    ? undefined
    : current.status === "loading"
      ? t(m.policyChecking, { project: policyProject.name })
      : current.status === "error"
        ? t(m.policyError, { project: policyProject.name })
        : current.data.usesProjectPolicy
          ? t(m.policyProject, { project: policyProject.name })
          : t(m.policyProjectFallback, { project: policyProject.name });
  const policyPath = current.status === "done" ? current.data.policyPath : undefined;
  const policyTone: PolicyTone = !policyProject
    ? "default"
    : current.status === "loading"
      ? "loading"
      : current.status === "error"
        ? "error"
        : current.data.usesProjectPolicy
          ? "project"
          : "default";

  return {
    status: current.status,
    usesProjectPolicy,
    policyLabel,
    policyPath,
    policyTone,
  };
}
