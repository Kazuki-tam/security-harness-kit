import { useCallback, useState } from "react";
import { type PreferredAiTool, PREFERRED_AI_TOOL_KEY, readPreferredAiTool } from "../aiTool";

export function usePreferredAiTool() {
  const [preferredAiTool, setPreferredAiToolState] = useState<PreferredAiTool>(() =>
    readPreferredAiTool(),
  );

  const setPreferredAiTool = useCallback((next: PreferredAiTool) => {
    setPreferredAiToolState(next);
    try {
      window.localStorage.setItem(PREFERRED_AI_TOOL_KEY, next);
    } catch (error) {
      console.warn("failed to save preferred AI tool", error);
    }
  }, []);

  return { preferredAiTool, setPreferredAiTool };
}
