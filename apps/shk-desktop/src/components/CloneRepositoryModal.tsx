import { GitFork, X } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { isSupportedGitRemote } from "../gitRemote";
import { useI18n } from "../i18n";
import { Button } from "./Button";

type Props = {
  open: boolean;
  onClose: () => void;
  onClone: (remoteUrl: string) => Promise<boolean>;
};

export function CloneRepositoryModal({ open, onClose, onClone }: Props) {
  const { messages } = useI18n();
  const m = messages.cloneRepository;
  const [remoteUrl, setRemoteUrl] = useState("");
  const [cloning, setCloning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) {
      setRemoteUrl("");
      setCloning(false);
      setError(null);
      return;
    }

    const previousFocus = document.activeElement as HTMLElement | null;
    const frame = requestAnimationFrame(() => inputRef.current?.focus());
    return () => {
      cancelAnimationFrame(frame);
      previousFocus?.focus();
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;

    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape" && !cloning) {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key === "Tab") {
        const focusable = Array.from(
          formRef.current?.querySelectorAll<HTMLElement>(
            'button:not(:disabled), input:not(:disabled), [tabindex]:not([tabindex="-1"])',
          ) ?? [],
        );
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [cloning, onClose, open]);

  if (!open) return null;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!remoteUrl.trim() || cloning) return;
    if (!isSupportedGitRemote(remoteUrl)) {
      setError(m.invalidUrl);
      return;
    }

    setError(null);
    setCloning(true);
    try {
      const completed = await onClone(remoteUrl.trim());
      if (completed) onClose();
    } catch {
      setError(m.failed);
    } finally {
      setCloning(false);
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="shk-clone-title"
      aria-describedby="shk-clone-description"
      className="fixed inset-0 z-50 grid place-items-center bg-black/60 px-6 backdrop-blur-sm"
      onClick={() => {
        if (!cloning) onClose();
      }}
    >
      <form
        ref={formRef}
        className="shk-fade-in w-full max-w-md overflow-hidden rounded-2xl border border-border bg-surface shadow-2xl shadow-black/60"
        onClick={(event) => event.stopPropagation()}
        onSubmit={handleSubmit}
      >
        <header className="flex items-center justify-between border-b border-border px-5 py-4">
          <div className="flex items-center gap-2.5">
            <GitFork size={16} className="text-sky-300" aria-hidden="true" />
            <h2 id="shk-clone-title" className="text-sm font-semibold text-white">
              {m.title}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={cloning}
            aria-label={messages.common.close}
            className="grid h-7 w-7 place-items-center rounded-md text-muted transition hover:bg-surface-3 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/60 disabled:opacity-50"
          >
            <X size={14} aria-hidden="true" />
          </button>
        </header>

        <div className="space-y-4 px-5 py-5">
          <p id="shk-clone-description" className="text-muted text-[12px] leading-relaxed">
            {m.description}
          </p>
          <label className="block">
            <span className="text-text mb-1.5 block text-[11px] font-medium">{m.urlLabel}</span>
            <input
              ref={inputRef}
              type="text"
              inputMode="url"
              autoComplete="url"
              value={remoteUrl}
              onChange={(event) => {
                setRemoteUrl(event.target.value);
                if (error) setError(null);
              }}
              placeholder={m.urlPlaceholder}
              disabled={cloning}
              spellCheck={false}
              autoCapitalize="none"
              autoCorrect="off"
              className="border-border bg-canvas placeholder:text-faint w-full rounded-lg border px-3 py-2 font-mono text-[12px] text-white outline-none transition focus:border-sky-400/60 focus:ring-2 focus:ring-sky-400/15 disabled:opacity-60"
            />
          </label>
          <p className="text-faint text-[11px]">{m.destinationHint}</p>
          {error && (
            <div
              role="alert"
              className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-[11px] leading-relaxed text-red-200"
            >
              {error}
            </div>
          )}
        </div>

        <footer className="border-border flex justify-end gap-2 border-t px-5 py-3.5">
          <Button onClick={onClose} disabled={cloning}>
            {messages.common.cancel}
          </Button>
          <Button type="submit" variant="primary" loading={cloning} disabled={!remoteUrl.trim()}>
            {cloning ? m.cloning : m.clone}
          </Button>
        </footer>
      </form>
    </div>
  );
}
