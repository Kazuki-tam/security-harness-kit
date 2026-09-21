import { ExternalLink, Save } from "lucide-react";
import { AI_TOOL_OPTIONS, type PreferredAiTool } from "../../aiTool";
import type { Messages } from "../../i18n/types";
import { Button } from "../Button";

type Props = {
  preferredAiTool: PreferredAiTool;
  onPreferredAiToolChange: (tool: PreferredAiTool) => void;
  saving?: boolean;
  saveMessage?: string | null;
  showOfficeSave?: boolean;
  onCopyAndOpen: () => void;
  onSave?: () => void;
  messages: Messages["mask"];
  t: (template: string, vars?: Record<string, string | number>) => string;
};

export function MaskTransferPanel({
  preferredAiTool,
  onPreferredAiToolChange,
  saving = false,
  saveMessage,
  showOfficeSave,
  onCopyAndOpen,
  onSave,
  messages: m,
  t,
}: Props) {
  return (
    <section className="overflow-hidden rounded-xl border border-sky-400/30 bg-sky-500/8 p-4 ring-1 ring-inset ring-sky-400/20">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-white">{m.transferTitle}</h2>
          <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-muted">{m.transferHint}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <label className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-border bg-canvas px-3 text-[12px] font-medium text-text transition hover:border-sky-300/60 focus-within:border-sky-300/70 focus-within:ring-2 focus-within:ring-sky-300/25">
            <span className="text-muted">{m.preferredTool}</span>
            <select
              aria-label={m.preferredTool}
              value={preferredAiTool}
              onChange={(event) => onPreferredAiToolChange(event.target.value as PreferredAiTool)}
              className="bg-transparent text-white outline-none"
            >
              {AI_TOOL_OPTIONS.map((tool) => (
                <option key={tool} value={tool}>
                  {m.toolNames[tool]}
                </option>
              ))}
            </select>
          </label>

          <Button
            variant="primary"
            icon={<ExternalLink size={14} aria-hidden="true" />}
            onClick={onCopyAndOpen}
          >
            {t(m.copyAndOpen, { tool: m.toolNames[preferredAiTool] })}
          </Button>

          {showOfficeSave && onSave && (
            <Button
              variant="secondary"
              icon={<Save size={14} aria-hidden="true" />}
              onClick={onSave}
              loading={saving}
              disabled={saving}
            >
              {saving ? m.saving : m.saveMaskedFile}
            </Button>
          )}
        </div>
      </div>

      {saveMessage && <p className="mt-3 text-[11px] text-sky-100/85">{saveMessage}</p>}
    </section>
  );
}
