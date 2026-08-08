import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { envEncryptTargets } from "../setup/plan";
import type { ProjectStatus } from "../types";

export function useEnvTargetSelection(status: ProjectStatus) {
  const eligibleTargets = useMemo(() => envEncryptTargets(status), [status]);
  const [selectedTargets, setSelectedTargets] = useState<string[]>(eligibleTargets);
  const projectPathRef = useRef(status.path);

  useEffect(() => {
    if (projectPathRef.current !== status.path) {
      projectPathRef.current = status.path;
      setSelectedTargets(eligibleTargets);
    }
  }, [status.path, eligibleTargets]);

  // Keep deliberate opt-outs while dropping files that are no longer eligible.
  useEffect(() => {
    setSelectedTargets((current) => current.filter((name) => eligibleTargets.includes(name)));
  }, [eligibleTargets]);

  const toggleTarget = useCallback((name: string) => {
    setSelectedTargets((current) =>
      current.includes(name) ? current.filter((target) => target !== name) : [...current, name],
    );
  }, []);

  return { eligibleTargets, selectedTargets, toggleTarget };
}
