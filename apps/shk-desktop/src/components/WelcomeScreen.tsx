import { ArrowRight, FolderOpen, ShieldCheck, Sparkles } from "lucide-react";
import type { Project } from "../types";
import { actionableCount } from "../scan";
import { dirnameOf, formatRelativeTime } from "../utils";

type Props = {
  recentProjects: Project[];
  onOpenFolder: () => void;
  onSelect: (id: string) => void;
};

export function WelcomeScreen({ recentProjects, onOpenFolder, onSelect }: Props) {
  return (
    <div className="shk-scroll shk-fade-in min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto flex max-w-3xl flex-col gap-10 px-10 pt-16 pb-12">
        <section className="text-center">
          <div className="mx-auto mb-5 grid h-14 w-14 place-items-center rounded-2xl bg-gradient-to-br from-sky-400/30 via-violet-400/20 to-emerald-400/20 text-sky-200 ring-1 ring-inset ring-sky-400/30">
            <ShieldCheck size={26} aria-hidden="true" />
          </div>
          <h2 className="text-[28px] font-semibold tracking-tight text-white">shk へようこそ</h2>
          <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-[var(--color-muted)]">
            AI コーディングエージェント向けのローカルファースト・セキュリティハーネス。
            シークレットや PII をローカルで検出し、結果は外部送信しません。
          </p>

          <div className="mt-7 flex items-center justify-center gap-3">
            <button
              type="button"
              onClick={onOpenFolder}
              className="group inline-flex items-center gap-2 rounded-lg bg-sky-500 px-5 py-2.5 text-sm font-semibold text-slate-950 shadow-lg shadow-sky-500/20 transition hover:bg-sky-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70"
            >
              <FolderOpen size={16} aria-hidden="true" />
              フォルダを開く
              <ArrowRight
                size={14}
                aria-hidden="true"
                className="transition group-hover:translate-x-0.5"
              />
            </button>
            <a
              href="https://agents.md"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-2)] px-4 py-2.5 text-sm font-medium text-[var(--color-text)] transition hover:border-sky-400/40 hover:text-white"
            >
              <Sparkles size={14} aria-hidden="true" />
              ドキュメント
            </a>
          </div>
        </section>

        <section className="grid gap-3 sm:grid-cols-3">
          <FeatureCard
            title="シークレット検出"
            description="API キー / トークンなど 100+ パターンを高速にローカル走査。"
          />
          <FeatureCard
            title="PII / コンテキスト保護"
            description="個人情報や AI 文脈に流出しがちな機微データを抽出。"
          />
          <FeatureCard
            title="エージェントと連携"
            description="Cursor / Claude Code / Codex 等の Pre / Post フックに統合。"
          />
        </section>

        {recentProjects.length > 0 && (
          <section>
            <div className="mb-3 flex items-baseline justify-between">
              <h3 className="text-xs font-semibold tracking-[0.16em] text-[var(--color-faint)] uppercase">
                最近のプロジェクト
              </h3>
              <span className="text-[11px] text-[var(--color-faint)]">
                {recentProjects.length} 件
              </span>
            </div>
            <ul className="grid gap-2">
              {recentProjects.map((project) => {
                const actionable = actionableCount(
                  project.summary?.bySeverity as Record<string, number>,
                );
                const parent = dirnameOf(project.path);
                return (
                  <li key={project.id}>
                    <button
                      type="button"
                      onClick={() => onSelect(project.id)}
                      className="group flex w-full items-center gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-2)]/70 px-4 py-3 text-left transition hover:-translate-y-px hover:border-sky-400/40 hover:bg-[var(--color-surface-3)] focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/60"
                    >
                      <span className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-[var(--color-surface-3)] text-[12px] font-semibold text-sky-200 ring-1 ring-inset ring-sky-400/20">
                        {project.name.slice(0, 2).toUpperCase()}
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="flex items-center gap-2">
                          <span className="truncate text-sm font-medium text-white">
                            {project.name}
                          </span>
                          {actionable > 0 && (
                            <span className="inline-flex h-4 items-center rounded-full bg-red-500/20 px-1.5 text-[10px] font-bold text-red-300 ring-1 ring-inset ring-red-500/40">
                              {actionable} 件の要対応
                            </span>
                          )}
                        </span>
                        <span
                          className="block truncate text-[11px] text-[var(--color-faint)]"
                          title={project.path}
                        >
                          {parent || project.path}
                        </span>
                      </span>
                      <span className="shrink-0 text-[11px] text-[var(--color-faint)]">
                        {formatRelativeTime(project.lastScannedAt)}
                      </span>
                      <ArrowRight
                        size={14}
                        aria-hidden="true"
                        className="ml-1 text-[var(--color-faint)] transition group-hover:translate-x-0.5 group-hover:text-sky-300"
                      />
                    </button>
                  </li>
                );
              })}
            </ul>
          </section>
        )}
      </div>
    </div>
  );
}

function FeatureCard({ title, description }: { title: string; description: string }) {
  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-2)]/60 p-4">
      <h4 className="text-sm font-semibold text-white">{title}</h4>
      <p className="mt-1.5 text-[12px] leading-relaxed text-[var(--color-muted)]">{description}</p>
    </div>
  );
}
