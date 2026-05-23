import { useState } from "react";
import { relaunch } from "@tauri-apps/plugin-process";
import { check } from "@tauri-apps/plugin-updater";
import { useI18n } from "../i18n";

type UpdateState = "idle" | "checking" | "installing";

export function UpdateButton() {
  const { messages } = useI18n();
  const [state, setState] = useState<UpdateState>("idle");
  const m = messages.topBar.updates;

  if (import.meta.env.DEV) {
    return null;
  }

  const busy = state !== "idle";

  async function checkForUpdate() {
    setState("checking");
    try {
      const update = await check();
      if (!update) {
        window.alert(m.upToDate);
        return;
      }

      const confirmed = window.confirm(m.available.replace("{{version}}", update.version));
      if (!confirmed) {
        return;
      }

      setState("installing");
      await update.downloadAndInstall();
      await relaunch();
    } catch (err) {
      window.alert(
        m.failed.replace("{{message}}", err instanceof Error ? err.message : String(err)),
      );
    } finally {
      setState("idle");
    }
  }

  return (
    <button
      type="button"
      className="rounded-md border border-border bg-surface px-2 py-1 text-[12px] font-medium text-muted transition hover:border-accent/50 hover:text-text disabled:cursor-not-allowed disabled:opacity-60"
      disabled={busy}
      onClick={checkForUpdate}
    >
      {state === "checking" ? m.checking : state === "installing" ? m.installing : m.check}
    </button>
  );
}
