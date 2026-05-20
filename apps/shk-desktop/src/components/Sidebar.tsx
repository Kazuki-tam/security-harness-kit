import { FolderOpen, MoreHorizontal, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { Project } from "../types";
import { actionableCount } from "../scan";
import { dirnameOf, formatRelativeTime } from "../utils";

type Props = {
  projects: Project[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onAdd: () => void;
  onRemove: (id: string) => void;
  appVersion: string;
};

export function Sidebar({ projects, selectedId, onSelect, onAdd, onRemove, appVersion }: Props) {
  return (
    <aside className="flex h-full w-[268px] shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface)]/80 backdrop-blur">
      <div className="shk-drag flex items-center gap-3 px-5 pt-6 pb-5">
        <div className="grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-sky-400/30 to-violet-400/20 text-sky-200 ring-1 ring-inset ring-sky-300/30">
          <ShieldCheck size={18} aria-hidden="true" />
        </div>
        <div className="leading-tight">
          <h1 className="text-[15px] font-semibold tracking-tight text-white">shk</h1>
          <p className="text-[11px] text-[var(--color-muted)]">Security Harness Kit</p>
        </div>
      </div>

      <div className="shk-no-drag px-3">
        <button
          type="button"
          onClick={onAdd}
          className="group flex w-full items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2 text-left text-sm font-medium text-[var(--color-text)] transition hover:border-sky-400/40 hover:bg-[var(--color-surface-3)] hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/60"
        >
          <span className="grid h-6 w-6 place-items-center rounded-md bg-sky-400/15 text-sky-300 transition group-hover:bg-sky-400/25">
            <Plus size={14} aria-hidden="true" />
          </span>
          <span>新しいプロジェクト</span>
          <kbd className="ml-auto rounded border border-[var(--color-border)] bg-[var(--color-canvas)] px-1.5 py-0.5 text-[10px] font-mono text-[var(--color-muted)]">
            ⌘O
          </kbd>
        </button>
      </div>

      <div className="mt-5 flex items-center justify-between px-5 pb-2">
        <span className="text-[10px] font-semibold tracking-[0.14em] text-[var(--color-faint)] uppercase">
          プロジェクト
        </span>
        <span className="text-[10px] font-medium text-[var(--color-faint)]">{projects.length}</span>
      </div>

      <nav
        className="shk-scroll min-h-0 flex-1 overflow-y-auto px-2 pb-4"
        aria-label="プロジェクト一覧"
      >
        {projects.length === 0 ? (
          <EmptyState onAdd={onAdd} />
        ) : (
          <ul className="grid gap-1">
            {projects.map((project) => (
              <li key={project.id}>
                <ProjectRow
                  project={project}
                  active={project.id === selectedId}
                  onSelect={() => onSelect(project.id)}
                  onRemove={() => onRemove(project.id)}
                />
              </li>
            ))}
          </ul>
        )}
      </nav>

      <footer className="border-t border-[var(--color-border)] px-5 py-3 text-[11px] text-[var(--color-faint)]">
        <div className="flex items-center justify-between">
          <span>v{appVersion}</span>
          <span className="rounded-full bg-emerald-400/10 px-2 py-0.5 text-[10px] font-medium text-emerald-300 ring-1 ring-inset ring-emerald-400/20">
            ローカル動作
          </span>
        </div>
      </footer>
    </aside>
  );
}

function EmptyState({ onAdd }: { onAdd: () => void }) {
  return (
    <div className="grid gap-3 rounded-xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface-2)]/50 px-4 py-6 text-center">
      <FolderOpen className="mx-auto text-[var(--color-faint)]" size={22} aria-hidden="true" />
      <p className="text-xs text-[var(--color-muted)]">
        プロジェクトを追加すると
        <br />
        ここに表示されます。
      </p>
      <button
        type="button"
        onClick={onAdd}
        className="mx-auto inline-flex items-center gap-1.5 rounded-md bg-sky-500/15 px-3 py-1.5 text-xs font-semibold text-sky-300 ring-1 ring-inset ring-sky-400/30 hover:bg-sky-500/25"
      >
        <Plus size={12} aria-hidden="true" />
        フォルダを開く
      </button>
    </div>
  );
}

function ProjectRow({
  project,
  active,
  onSelect,
  onRemove,
}: {
  project: Project;
  active: boolean;
  onSelect: () => void;
  onRemove: () => void;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) return;
    function handle(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    }
    window.addEventListener("mousedown", handle);
    return () => window.removeEventListener("mousedown", handle);
  }, [menuOpen]);

  const actionable = actionableCount(project.summary?.bySeverity as Record<string, number>);
  const parent = dirnameOf(project.path);

  return (
    <div
      className={`group relative flex items-center gap-2 rounded-lg px-2.5 py-2 transition ${
        active
          ? "bg-sky-500/10 ring-1 ring-inset ring-sky-400/30"
          : "hover:bg-[var(--color-surface-2)]"
      }`}
    >
      <button
        type="button"
        onClick={onSelect}
        className="flex min-w-0 flex-1 items-center gap-2.5 text-left focus:outline-none"
      >
        <span
          className={`grid h-8 w-8 shrink-0 place-items-center rounded-md text-[11px] font-bold uppercase ${
            active
              ? "bg-sky-400/20 text-sky-200 ring-1 ring-inset ring-sky-400/40"
              : "bg-[var(--color-surface-3)] text-[var(--color-muted)] group-hover:text-[var(--color-text)]"
          }`}
          aria-hidden="true"
        >
          {initials(project.name)}
        </span>
        <span className="min-w-0 flex-1">
          <span
            className={`flex items-center gap-1.5 text-sm font-medium ${
              active ? "text-white" : "text-[var(--color-text)]"
            }`}
          >
            <span className="truncate">{project.name}</span>
            {actionable > 0 && (
              <span
                className="inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500/20 px-1 text-[10px] font-bold text-red-300 ring-1 ring-inset ring-red-500/40"
                title={`${actionable} 件の要対応`}
              >
                {actionable}
              </span>
            )}
          </span>
          <span
            className="block truncate text-[11px] text-[var(--color-faint)]"
            title={project.path}
          >
            {parent || project.path}
          </span>
          <span className="block text-[10px] text-[var(--color-faint)]">
            {formatRelativeTime(project.lastScannedAt)}
          </span>
        </span>
      </button>

      <div ref={menuRef} className="relative">
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            setMenuOpen((prev) => !prev);
          }}
          aria-label={`${project.name} のメニュー`}
          className={`grid h-7 w-7 place-items-center rounded-md text-[var(--color-faint)] opacity-0 transition hover:bg-[var(--color-surface-3)] hover:text-[var(--color-text)] focus:opacity-100 focus:outline-none group-hover:opacity-100 ${
            menuOpen ? "opacity-100" : ""
          }`}
        >
          <MoreHorizontal size={14} aria-hidden="true" />
        </button>

        {menuOpen && (
          <div
            role="menu"
            className="shk-fade-in absolute right-0 z-20 mt-1 w-44 overflow-hidden rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-3)] shadow-xl shadow-black/40"
          >
            <button
              type="button"
              role="menuitem"
              onClick={() => {
                setMenuOpen(false);
                onRemove();
              }}
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs text-red-300 hover:bg-red-500/15"
            >
              <Trash2 size={12} aria-hidden="true" />
              プロジェクトを削除
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function initials(name: string): string {
  if (!name) return "·";
  const stripped = name.replace(/[\s._-]+/g, " ").trim();
  if (!stripped) return name.slice(0, 2).toUpperCase();
  const words = stripped.split(" ");
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}
