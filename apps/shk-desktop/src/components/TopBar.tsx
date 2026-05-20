import { FolderOpen } from "lucide-react";
import type { Project } from "../types";

type Props = {
  project: Project | null;
  onOpenFolder: () => void;
};

export function TopBar({ project, onOpenFolder }: Props) {
  return (
    <div className="shk-drag flex h-11 shrink-0 items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-surface)]/60 px-4 backdrop-blur">
      <div className="flex min-w-0 items-center gap-2 pl-16 text-[12px] text-[var(--color-muted)]">
        {project ? (
          <>
            <span className="text-[var(--color-faint)]">プロジェクト /</span>
            <span className="truncate font-medium text-[var(--color-text)]">{project.name}</span>
          </>
        ) : (
          <span className="text-[var(--color-faint)]">ようこそ</span>
        )}
      </div>
      <div className="shk-no-drag flex items-center gap-1.5">
        <button
          type="button"
          onClick={onOpenFolder}
          className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2.5 py-1 text-[11px] font-medium text-[var(--color-text)] transition hover:border-sky-400/40 hover:text-white"
        >
          <FolderOpen size={12} aria-hidden="true" />
          フォルダを開く
        </button>
      </div>
    </div>
  );
}
