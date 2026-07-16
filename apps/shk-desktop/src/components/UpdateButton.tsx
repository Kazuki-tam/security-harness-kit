import { useMemo, useState } from "react";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { useI18n } from "../i18n";
import { ConfirmDialog } from "./ConfirmDialog";

type UpdateState = "idle" | "checking" | "installing";

type DialogState =
  | { kind: "closed" }
  | { kind: "upToDate" }
  | { kind: "available"; version: string; update: Update }
  | { kind: "failed"; message: string };

export function UpdateButton() {
  const { messages, t } = useI18n();
  const [state, setState] = useState<UpdateState>("idle");
  const [dialog, setDialog] = useState<DialogState>({ kind: "closed" });
  const m = messages.topBar.updates;

  const activeDialog = useMemo(() => {
    switch (dialog.kind) {
      case "upToDate":
        return {
          title: m.upToDateTitle,
          description: m.upToDate,
          confirmLabel: messages.common.close,
          hideCancel: true,
        };
      case "available":
        return {
          title: m.availableTitle,
          description: t(m.available, { version: dialog.version }),
          confirmLabel: m.confirmInstall,
          hideCancel: false,
        };
      case "failed":
        return {
          title: m.failedTitle,
          description: t(m.failed, { message: dialog.message }),
          confirmLabel: messages.common.close,
          hideCancel: true,
        };
      default:
        return null;
    }
  }, [dialog, m, messages.common.close, t]);

  if (import.meta.env.DEV && !import.meta.env.VITEST) {
    return null;
  }

  const busy = state !== "idle";

  async function checkForUpdate() {
    setState("checking");
    try {
      const update = await check();
      if (!update) {
        setDialog({ kind: "upToDate" });
        return;
      }

      setDialog({ kind: "available", version: update.version, update });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setDialog({ kind: "failed", message });
    } finally {
      setState("idle");
    }
  }

  async function installUpdate(update: Update) {
    setDialog({ kind: "closed" });
    setState("installing");
    try {
      await update.downloadAndInstall();
      await relaunch();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setDialog({ kind: "failed", message });
    } finally {
      setState("idle");
    }
  }

  function handleDialogConfirm() {
    if (dialog.kind === "available") {
      void installUpdate(dialog.update);
      return;
    }
    setDialog({ kind: "closed" });
  }

  return (
    <>
      <button
        type="button"
        className="inline-flex h-7 items-center rounded-md border border-border bg-surface px-2 text-[11px] font-medium text-muted transition hover:border-accent/50 hover:text-text disabled:cursor-not-allowed disabled:opacity-60"
        disabled={busy}
        onClick={checkForUpdate}
        aria-live="polite"
      >
        {state === "checking" ? m.checking : state === "installing" ? m.installing : m.check}
      </button>

      {activeDialog && (
        <ConfirmDialog
          open
          title={activeDialog.title}
          description={activeDialog.description}
          confirmLabel={activeDialog.confirmLabel}
          hideCancel={activeDialog.hideCancel}
          onConfirm={handleDialogConfirm}
          onCancel={() => setDialog({ kind: "closed" })}
        />
      )}
    </>
  );
}
