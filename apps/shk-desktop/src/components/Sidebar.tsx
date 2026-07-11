import { Copy, Eraser, FolderOpen, MoreHorizontal, Pencil, Plus, Trash2 } from "lucide-react";
import {
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
  useEffect,
  useRef,
  useState,
} from "react";
import { useI18n } from "../i18n";
import { operationErrorMessage } from "../i18n/interpolate";
import type { Project } from "../types";
import { actionableCount } from "../scan";
import { formatRelativeTime, shortenPath } from "../utils";
import { BrandLogo } from "./BrandLogo";
import { Button } from "./Button";

type Props = {
  projects: Project[];
  selectedId: string | null;
  maskActive?: boolean;
  onSelect: (id: string) => void;
  onShowWelcome: () => void;
  onShowMask: () => void;
  onAdd: () => void;
  onRemove: (id: string) => void;
  onRename: (id: string, name: string) => void;
  appVersion: string;
  onNotice?: (message: string) => void;
};

export function Sidebar({
  projects,
  selectedId,
  maskActive = false,
  onSelect,
  onShowWelcome,
  onShowMask,
  onAdd,
  onRemove,
  onRename,
  appVersion,
  onNotice,
}: Props) {
  const { messages } = useI18n();
  const m = messages.sidebar;

  return (
    <aside className="flex h-full w-[268px] shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface)]/80 backdrop-blur">
      <div className="shk-drag h-11 shrink-0" aria-hidden="true" />
      <div className="shk-drag px-3 pt-1 pb-3">
        <button
          type="button"
          onClick={onShowWelcome}
          aria-label={messages.topBar.welcome}
          className="shk-no-drag flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left transition hover:bg-surface-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70"
        >
          <BrandLogo className="h-9 w-9" />
          <span className="leading-tight">
            <span className="block text-[15px] font-semibold tracking-tight text-white">shk</span>
            <span className="text-muted block text-[11px]">Security Harness Kit</span>
          </span>
        </button>
      </div>

      {projects.length > 0 && (
        <div className="shk-no-drag px-3">
          <button
            type="button"
            onClick={onShowMask}
            className={`group mb-2 flex w-full items-center gap-2 rounded-lg border px-3 py-2 text-left text-sm font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70 ${
              maskActive
                ? "border-sky-400/40 bg-sky-500/10 text-white"
                : "border-[var(--color-border)] bg-[var(--color-surface-2)] text-[var(--color-text)] hover:border-sky-300/60 hover:bg-[var(--color-surface-3)] hover:text-white"
            }`}
          >
            <span className="grid h-6 w-6 place-items-center rounded-md bg-sky-400/15 text-sky-300 transition group-hover:bg-sky-400/25">
              <Eraser size={14} aria-hidden="true" />
            </span>
            <span>{m.maskWorkspace}</span>
            <kbd className="ml-auto rounded border border-[var(--color-border)] bg-[var(--color-canvas)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-muted)]">
              ⌘M
            </kbd>
          </button>
          <button
            type="button"
            onClick={onAdd}
            className="group flex w-full items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2 text-left text-sm font-medium text-[var(--color-text)] transition hover:border-sky-300/60 hover:bg-[var(--color-surface-3)] hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70"
          >
            <span className="grid h-6 w-6 place-items-center rounded-md bg-sky-400/15 text-sky-300 transition group-hover:bg-sky-400/25">
              <Plus size={14} aria-hidden="true" />
            </span>
            <span>{m.newProject}</span>
            <kbd className="ml-auto rounded border border-[var(--color-border)] bg-[var(--color-canvas)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-muted)]">
              ⌘O
            </kbd>
          </button>
        </div>
      )}

      {projects.length > 0 && (
        <div className="mt-5 flex items-center justify-between px-5 pb-2">
          <span className="text-[10px] font-semibold tracking-[0.14em] text-[var(--color-faint)] uppercase">
            {m.projects}
          </span>
          <span className="text-[10px] font-medium text-[var(--color-faint)]">
            {projects.length}
          </span>
        </div>
      )}

      <nav
        className={`shk-scroll min-h-0 flex-1 overflow-y-auto px-2 pb-4 ${
          projects.length === 0 ? "pt-2" : ""
        }`}
        aria-label={m.projectsAria}
      >
        {projects.length === 0 ? (
          <EmptyState onAdd={onAdd} />
        ) : (
          <ul className="grid gap-0.5">
            {projects.map((project) => (
              <li key={project.id}>
                <ProjectRow
                  project={project}
                  active={project.id === selectedId}
                  onSelect={() => onSelect(project.id)}
                  onRemove={() => onRemove(project.id)}
                  onRename={(name) => onRename(project.id, name)}
                  onNotice={onNotice}
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
            {m.runsLocally}
          </span>
        </div>
      </footer>
    </aside>
  );
}

function EmptyState({ onAdd }: { onAdd: () => void }) {
  const { messages } = useI18n();
  const m = messages.sidebar;

  return (
    <div className="grid gap-3 rounded-xl border border-dashed border-[var(--color-border)] bg-[var(--color-surface-2)]/50 px-4 py-6 text-center">
      <FolderOpen className="mx-auto text-[var(--color-faint)]" size={22} aria-hidden="true" />
      <p className="text-xs text-[var(--color-muted)]">
        {m.emptyHintLine1}
        <br />
        {m.emptyHintLine2}
      </p>
      <Button
        variant="primary"
        size="sm"
        onClick={onAdd}
        className="mx-auto"
        icon={<Plus size={12} aria-hidden="true" className="shrink-0" />}
      >
        {m.openFolder}
      </Button>
    </div>
  );
}

type ProjectRowProps = {
  project: Project;
  active: boolean;
  onSelect: () => void;
  onRemove: () => void;
  onRename: (name: string) => void;
  onNotice?: (message: string) => void;
};

function ProjectRow({ project, active, onSelect, onRemove, onRename, onNotice }: ProjectRowProps) {
  const { messages, t } = useI18n();
  const m = messages.sidebar;
  const [menuOpen, setMenuOpen] = useState(false);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(project.name);
  const [confirmingRemove, setConfirmingRemove] = useState(false);
  const rowRef = useRef<HTMLDivElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const removeTimer = useRef<number | null>(null);

  useEffect(() => {
    if (!menuOpen) return;
    function handleDown(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    }
    function handleKey(event: KeyboardEvent) {
      if (event.key === "Escape") setMenuOpen(false);
    }
    window.addEventListener("mousedown", handleDown);
    window.addEventListener("keydown", handleKey);
    return () => {
      window.removeEventListener("mousedown", handleDown);
      window.removeEventListener("keydown", handleKey);
    };
  }, [menuOpen]);

  useEffect(() => {
    if (editing) {
      setDraft(project.name);
      requestAnimationFrame(() => {
        inputRef.current?.focus();
        inputRef.current?.select();
      });
    }
  }, [editing, project.name]);

  useEffect(() => {
    return () => {
      if (removeTimer.current !== null) {
        window.clearTimeout(removeTimer.current);
      }
    };
  }, []);

  function commitRename() {
    const next = draft.trim();
    if (next && next !== project.name) {
      onRename(next);
    }
    setEditing(false);
  }

  function startRename() {
    setMenuOpen(false);
    setEditing(true);
  }

  async function copyPath() {
    setMenuOpen(false);
    try {
      await navigator.clipboard.writeText(project.path);
    } catch (error) {
      onNotice?.(operationErrorMessage(messages.app.clipboardFailed, error));
    }
  }

  function requestRemove() {
    if (confirmingRemove) {
      if (removeTimer.current !== null) {
        window.clearTimeout(removeTimer.current);
        removeTimer.current = null;
      }
      setConfirmingRemove(false);
      setMenuOpen(false);
      onRemove();
      return;
    }
    setConfirmingRemove(true);
    removeTimer.current = window.setTimeout(() => {
      setConfirmingRemove(false);
      removeTimer.current = null;
    }, 2500);
  }

  function openMenuAt() {
    setMenuOpen(true);
  }

  function onContext(event: ReactMouseEvent<HTMLDivElement>) {
    event.preventDefault();
    openMenuAt();
  }

  function onKeyDown(event: ReactKeyboardEvent<HTMLButtonElement>) {
    if (event.key === "F2") {
      event.preventDefault();
      startRename();
    }
    if (event.key === "Delete" || event.key === "Backspace") {
      if (event.metaKey || event.ctrlKey) {
        event.preventDefault();
        onRemove();
      }
    }
  }

  const actionable = actionableCount(project.summary?.bySeverity);
  const shortPath = shortenPath(project.path);

  return (
    <div
      ref={rowRef}
      onContextMenu={onContext}
      className={`group relative grid grid-cols-[32px_minmax(0,1fr)_24px] items-center gap-2 rounded-lg px-2 py-2 transition ${
        active
          ? "bg-sky-500/10 ring-1 ring-inset ring-sky-400/30"
          : "hover:bg-[var(--color-surface-2)]"
      }`}
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

      {editing ? (
        <input
          ref={inputRef}
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onBlur={commitRename}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              commitRename();
            }
            if (event.key === "Escape") {
              event.preventDefault();
              setEditing(false);
            }
          }}
          className="min-w-0 rounded-md border border-sky-400/50 bg-[var(--color-canvas)] px-2 py-1 text-sm text-white outline-none focus:border-sky-300/80"
          aria-label={m.renameAria}
        />
      ) : (
        <button
          type="button"
          onClick={onSelect}
          onDoubleClick={startRename}
          onKeyDown={onKeyDown}
          className="grid min-w-0 grid-rows-[auto_auto] gap-0.5 text-left focus:outline-none"
          title={project.path}
        >
          <span
            className={`flex min-w-0 items-center gap-1.5 text-[13px] font-medium leading-tight ${
              active ? "text-white" : "text-[var(--color-text)]"
            }`}
          >
            <span className="min-w-0 flex-1 truncate">{project.name}</span>
            {actionable > 0 && (
              <span
                className="inline-flex h-4 min-w-4 shrink-0 items-center justify-center rounded-full bg-red-500/20 px-1 text-[10px] font-bold text-red-300 ring-1 ring-inset ring-red-500/40"
                title={t(m.actionableCount, { count: actionable })}
              >
                {actionable}
              </span>
            )}
          </span>
          <span className="flex min-w-0 items-center gap-1 text-[10px] leading-tight text-[var(--color-faint)]">
            <span className="min-w-0 flex-1 truncate font-mono" title={project.path}>
              {shortPath}
            </span>
            <span className="shrink-0">
              · {formatRelativeTime(project.lastScannedAt, messages.time)}
            </span>
          </span>
        </button>
      )}

      <div ref={menuRef} className="relative">
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            setMenuOpen((prev) => !prev);
          }}
          aria-label={t(m.menuAria, { name: project.name })}
          aria-haspopup="menu"
          aria-expanded={menuOpen}
          className={`grid h-6 w-6 place-items-center rounded-md text-[var(--color-muted)] transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70 ${
            menuOpen
              ? "bg-[var(--color-surface-3)] text-white opacity-100"
              : "opacity-60 hover:bg-[var(--color-surface-3)] hover:text-white hover:opacity-100 group-hover:opacity-100"
          }`}
        >
          <MoreHorizontal size={14} aria-hidden="true" />
        </button>

        {menuOpen && (
          <div
            role="menu"
            className="shk-fade-in absolute right-0 z-20 mt-1 w-48 overflow-hidden rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-3)] py-1 shadow-xl shadow-black/40"
          >
            <MenuItem icon={<Pencil size={12} aria-hidden="true" />} onClick={startRename}>
              {m.rename}
            </MenuItem>
            <MenuItem icon={<Copy size={12} aria-hidden="true" />} onClick={copyPath}>
              {m.copyPath}
            </MenuItem>
            <MenuDivider />
            <MenuItem icon={<Trash2 size={12} aria-hidden="true" />} onClick={requestRemove} danger>
              {confirmingRemove ? m.removeConfirm : m.removeProject}
            </MenuItem>
          </div>
        )}
      </div>
    </div>
  );
}

function MenuItem({
  icon,
  children,
  onClick,
  danger,
}: {
  icon: ReactNode;
  children: ReactNode;
  onClick: () => void;
  danger?: boolean;
}) {
  return (
    <button
      type="button"
      role="menuitem"
      onClick={onClick}
      className={`flex w-full items-center gap-2 px-3 py-2 text-left text-xs transition ${
        danger
          ? "text-red-300 hover:bg-red-500/15 hover:text-red-200"
          : "text-[var(--color-text)] hover:bg-[var(--color-surface)]/60 hover:text-white"
      }`}
    >
      <span
        className={`grid h-5 w-5 place-items-center rounded ${
          danger ? "text-red-300" : "text-[var(--color-muted)] group-hover:text-[var(--color-text)]"
        }`}
      >
        {icon}
      </span>
      <span className="flex-1 truncate">{children}</span>
    </button>
  );
}

function MenuDivider() {
  return <div className="my-1 h-px bg-[var(--color-border)]" aria-hidden="true" />;
}

function initials(name: string): string {
  if (!name) return "·";
  const stripped = name.replace(/[\s._-]+/g, " ").trim();
  if (!stripped) return name.slice(0, 2).toUpperCase();
  const words = stripped.split(" ");
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}
