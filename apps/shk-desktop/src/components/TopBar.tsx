import { FolderOpen } from "lucide-react";
import { useI18n } from "../i18n";
import type { Project } from "../types";
import { Button } from "./Button";
import { LanguageSwitcher } from "./LanguageSwitcher";

type Props = {
  project: Project | null;
  onOpenFolder: () => void;
};

export function TopBar({ project, onOpenFolder }: Props) {
  const { messages } = useI18n();
  const m = messages.topBar;

  return (
    <div className="shk-drag flex h-11 shrink-0 items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-surface)]/60 px-4 backdrop-blur">
      <div className="flex min-w-0 items-center gap-2 pl-16 text-[12px] text-[var(--color-muted)]">
        {project ? (
          <>
            <span className="text-[var(--color-faint)]">{m.projectBreadcrumb}</span>
            <span className="truncate font-medium text-[var(--color-text)]">{project.name}</span>
          </>
        ) : (
          <span className="text-[var(--color-faint)]">{m.welcome}</span>
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
