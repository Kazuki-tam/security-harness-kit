import { useCallback, useState } from "react";
import { type PreferredIde, readPreferredIde, PREFERRED_IDE_KEY } from "../ide";

export function usePreferredIde() {
  const [preferredIde, setPreferredIdeState] = useState<PreferredIde>(() => readPreferredIde());

  const setPreferredIde = useCallback((next: PreferredIde) => {
    setPreferredIdeState(next);
    try {
      window.localStorage.setItem(PREFERRED_IDE_KEY, next);
    } catch (error) {
      console.warn("failed to save preferred IDE", error);
    }
  }, []);

  return { preferredIde, setPreferredIde };
}
