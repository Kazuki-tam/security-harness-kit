import { CircleHelp } from "lucide-react";
import { useI18n } from "../i18n";
import type { ProjectApp } from "../projectApp";
import type { Project } from "../types";
import { LanguageSwitcher } from "./LanguageSwitcher";
import { OpenInAppMenu } from "./OpenInAppMenu";
import { UpdateButton } from "./UpdateButton";

type Props = {
  view: "welcome" | "project" | "mask";
  project: Project | null;
  reserveWindowControls?: boolean;
  preferredApp: ProjectApp;
  onOpenInApp: (app: ProjectApp) => void;
  onShowHelp: () => void;
};

export function TopBar({
  view,
  project,
  reserveWindowControls = false,
  preferredApp,
  onOpenInApp,
  onShowHelp,
}: Props) {
  const { messages } = useI18n();
  const m = messages.topBar;

  return (
    <div className="shk-drag relative z-30 flex h-11 shrink-0 items-center justify-between border-b border-border bg-surface/60 px-4 backdrop-blur">
      <div
        className={`flex min-w-0 items-center gap-2 text-[12px] text-muted ${
          reserveWindowControls ? "pl-16" : ""
        }`}
      >
        {view === "mask" ? (
          <span className="font-medium text-text">{m.maskWorkspace}</span>
        ) : project ? (
          <>
            <span className="text-faint">{m.projectBreadcrumb}</span>
            <span className="truncate font-medium text-text">{project.name}</span>
          </>
        ) : (
          <span className="text-faint">{m.welcome}</span>
        )}
      </div>
      <div className="shk-no-drag flex items-center gap-1.5">
        <button
          type="button"
          onClick={onShowHelp}
          aria-label={messages.help.title}
          title={messages.help.title}
          className="grid h-7 w-7 place-items-center rounded-md text-muted transition hover:bg-surface-2 hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70"
        >
          <CircleHelp size={15} aria-hidden="true" />
        </button>
        <UpdateButton />
        <LanguageSwitcher />
        <OpenInAppMenu preferredApp={preferredApp} onSelect={onOpenInApp} />
      </div>
    </div>
  );
}
