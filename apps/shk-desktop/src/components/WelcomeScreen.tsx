import { Eraser, FolderOpen, GitFork } from "lucide-react";
import { useState, type ReactNode } from "react";
import { useI18n } from "../i18n";
import type { Project } from "../types";
import { actionableCount } from "../scan";
import { formatRelativeTime, shortenPath } from "../utils";
import { BrandLogo } from "./BrandLogo";
import { CloneRepositoryModal } from "./CloneRepositoryModal";

type Props = {
  recentProjects: Project[];
  totalProjects: number;
  onOpenFolder: () => void;
  onCloneRepository: (remoteUrl: string) => Promise<boolean>;
  onSelect: (id: string) => void;
  onShowMask: () => void;
};

export function WelcomeScreen({
  recentProjects,
  totalProjects,
  onOpenFolder,
  onCloneRepository,
  onSelect,
  onShowMask,
}: Props) {
  const { messages, t } = useI18n();
  const m = messages.welcome;
  const [cloneOpen, setCloneOpen] = useState(false);

  return (
    <div className="shk-scroll shk-fade-in min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto flex min-h-full w-full max-w-[640px] flex-col justify-center px-8 py-12">
        <section className="mb-10 flex flex-col items-center text-center" aria-label={m.title}>
          <BrandLogo className="h-20 w-20 drop-shadow-[0_14px_32px_rgba(3,112,248,0.28)]" />
          <h1 className="mt-4 max-w-sm text-[26px] leading-tight font-semibold tracking-tight text-white">
            {m.title}
          </h1>
          <p className="mt-2 max-w-md text-[12.5px] text-[var(--color-muted)]">{m.subtitle}</p>
        </section>

        <section className="grid grid-cols-1 gap-3 sm:grid-cols-3" aria-label={m.actions}>
          <ActionCard
            icon={<FolderOpen size={18} aria-hidden="true" />}
            label={m.openProject}
            onClick={onOpenFolder}
            primary
          />
          <ActionCard
            icon={<GitFork size={18} aria-hidden="true" />}
            label={messages.cloneRepository.action}
            onClick={() => setCloneOpen(true)}
          />
          <ActionCard
            icon={<Eraser size={18} aria-hidden="true" />}
            label={m.maskWorkspace}
            onClick={onShowMask}
          />
        </section>

        {recentProjects.length > 0 && (
          <section className="mt-10" aria-label={m.recentProjects}>
            <div className="mb-2 flex items-baseline justify-between px-1">
              <h2 className="text-[12px] font-medium text-[var(--color-muted)]">
                {m.recentProjects}
              </h2>
              <span className="text-[12px] text-[var(--color-faint)]">
                {t(m.showAll, { count: totalProjects })}
              </span>
            </div>
            <ul className="grid">
              {recentProjects.map((project) => (
                <li key={project.id}>
                  <RecentRow project={project} onSelect={() => onSelect(project.id)} />
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>

      <CloneRepositoryModal
        open={cloneOpen}
        onClose={() => setCloneOpen(false)}
        onClone={onCloneRepository}
      />
    </div>
  );
}

function ActionCard({
  icon,
  label,
  onClick,
  primary,
}: {
  icon: ReactNode;
  label: string;
  onClick: () => void;
  primary?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`group flex flex-col items-start gap-3 rounded-xl border bg-[var(--color-surface-2)] px-4 py-4 text-left transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70 ${
        primary
          ? "border-sky-400/30 hover:border-sky-400/60 hover:bg-sky-500/10"
          : "border-[var(--color-border)] hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-3)]"
      }`}
    >
      <span
        className={`grid h-8 w-8 place-items-center rounded-lg transition ${
          primary
            ? "bg-sky-400/15 text-sky-300 group-hover:bg-sky-400/25"
            : "bg-[var(--color-surface-3)] text-[var(--color-muted)] group-hover:text-[var(--color-text)]"
        }`}
      >
        {icon}
      </span>
      <span className="text-[13px] font-medium text-white">{label}</span>
    </button>
  );
}

function RecentRow({ project, onSelect }: { project: Project; onSelect: () => void }) {
  const { messages, t } = useI18n();
  const actionable = actionableCount(project.summary?.bySeverity);
  const displayPath = shortenPath(project.path);

  return (
    <button
      type="button"
      onClick={onSelect}
      className="group grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-3 rounded-md px-2 py-2 text-left transition hover:bg-[var(--color-surface-2)] focus:outline-none focus-visible:bg-[var(--color-surface-2)]"
    >
      <span className="flex min-w-0 items-center gap-2">
        <span className="truncate text-[13px] font-medium text-white">{project.name}</span>
        {actionable > 0 && (
          <span
            className="inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500/20 px-1 text-[10px] font-semibold text-red-300 ring-1 ring-inset ring-red-500/40"
            title={t(messages.sidebar.actionableCount, { count: actionable })}
          >
            {actionable}
          </span>
        )}
        <span className="text-[10px] text-[var(--color-faint)]">
          · {formatRelativeTime(project.lastScannedAt, messages.time)}
        </span>
      </span>
      <span
        className="truncate text-right font-mono text-[12px] text-[var(--color-muted)] group-hover:text-[var(--color-text)]"
        title={project.path}
      >
        {displayPath}
      </span>
    </button>
  );
}
