import { useI18n } from "../i18n";
import type { PreferredIde } from "../ide";
import type { Project } from "../types";
import { LanguageSwitcher } from "./LanguageSwitcher";
import { OpenInIdeMenu } from "./OpenInIdeMenu";
import { UpdateButton } from "./UpdateButton";

type Props = {
  project: Project | null;
  reserveWindowControls?: boolean;
  preferredIde: PreferredIde;
  onOpenInIde: (ide: PreferredIde) => void;
};

export function TopBar({
  project,
  reserveWindowControls = false,
  preferredIde,
  onOpenInIde,
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
        {project ? (
          <>
            <span className="text-faint">{m.projectBreadcrumb}</span>
            <span className="truncate font-medium text-text">{project.name}</span>
          </>
        ) : (
          <span className="text-faint">{m.welcome}</span>
        )}
      </div>
      <div className="shk-no-drag flex items-center gap-1.5">
        <UpdateButton />
        <LanguageSwitcher />
        <OpenInIdeMenu preferredIde={preferredIde} onSelect={onOpenInIde} />
      </div>
    </div>
  );
}
