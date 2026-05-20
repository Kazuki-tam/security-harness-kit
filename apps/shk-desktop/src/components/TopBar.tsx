import { FolderOpen } from "lucide-react";
import { useI18n } from "../i18n";
import type { Project } from "../types";
import { Button } from "./Button";
import { LanguageSwitcher } from "./LanguageSwitcher";

type Props = {
  project: Project | null;
  reserveWindowControls?: boolean;
  onOpenFolder: () => void;
};

export function TopBar({ project, reserveWindowControls = false, onOpenFolder }: Props) {
  const { messages } = useI18n();
  const m = messages.topBar;

  return (
    <div className="shk-drag flex h-11 shrink-0 items-center justify-between border-b border-border bg-surface/60 px-4 backdrop-blur">
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
        <LanguageSwitcher />
        <Button
          variant="secondary"
          size="sm"
          onClick={onOpenFolder}
          icon={<FolderOpen size={12} aria-hidden="true" className="shrink-0" />}
        >
          {m.openFolder}
        </Button>
      </div>
    </div>
  );
}
