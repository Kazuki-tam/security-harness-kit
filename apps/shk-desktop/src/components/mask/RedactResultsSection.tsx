import { CheckCircle2 } from "lucide-react";
import { useState } from "react";
import type { PreferredAiTool } from "../../aiTool";
import type { Messages } from "../../i18n/types";
import type { Finding } from "../../scan";
import { severityOrder, type Severity } from "../../scan";
import type { MaskFileMeta, MaskState } from "../../mask";
import { FindingList } from "../FindingList";
import { SeveritySummary } from "../SeveritySummary";
import { MaskTransferPanel } from "./MaskTransferPanel";

type Props = {
  maskState: MaskState;
  findings: Finding[];
  fileMeta?: MaskFileMeta;
  canCopy: boolean;
  saving: boolean;
  saveMessage: string | null;
  preferredAiTool: PreferredAiTool;
  onPreferredAiToolChange: (tool: PreferredAiTool) => void;
  onCopyAndOpen: () => void;
  onSave: () => void;
  messages: Messages["mask"];
  t: (template: string, vars?: Record<string, string | number>) => string;
};

/** Everything below the input/output grid in redact mode: transfer, errors, findings. */
export function RedactResultsSection({
  maskState,
  findings,
  fileMeta,
  canCopy,
  saving,
  saveMessage,
  preferredAiTool,
  onPreferredAiToolChange,
  onCopyAndOpen,
  onSave,
  messages: m,
  t,
}: Props) {
  const [findingFilter, setFindingFilter] = useState<Severity | "all">("all");

  const reportForSummary =
    maskState.status === "done"
      ? {
          version: 1,
          scanned_paths: [],
          findings,
          summary: {
            total: findings.length,
            by_severity: Object.fromEntries(
              severityOrder.map((level) => [
                level,
                findings.filter((f) => String(f.severity) === level).length,
              ]),
            ),
          },
          exit_threshold: "medium",
          suppressed: 0,
          deduplicated: 0,
          color_mode: "never",
        }
      : null;

  return (
    <>
      {canCopy && (
        <MaskTransferPanel
          preferredAiTool={preferredAiTool}
          onPreferredAiToolChange={onPreferredAiToolChange}
          saving={saving}
          saveMessage={saveMessage}
          showOfficeSave={fileMeta?.fileKind === "office"}
          onCopyAndOpen={onCopyAndOpen}
          onSave={onSave}
          messages={m}
          t={t}
        />
      )}

      {maskState.status === "error" && (
        <div
          role="alert"
          className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-[13px] text-red-200"
        >
          {m.failed}: {maskState.message}
        </div>
      )}

      {reportForSummary && findings.length > 0 && (
        <section className="grid gap-3">
          <SeveritySummary
            report={reportForSummary}
            filter={findingFilter}
            onFilterChange={setFindingFilter}
          />
          <FindingList findings={findings} filter={findingFilter} />
        </section>
      )}

      {maskState.status === "done" && findings.length === 0 && (
        <section className="overflow-hidden rounded-xl border border-emerald-500/25 bg-emerald-500/5 px-5 py-4">
          <div className="flex items-start gap-3">
            <CheckCircle2
              size={20}
              className="mt-0.5 shrink-0 text-emerald-300"
              aria-hidden="true"
            />
            <div>
              <h2 className="text-sm font-semibold text-white">{m.findingsTitle}</h2>
              <p className="mt-1 text-[12px] leading-relaxed text-emerald-100/85">{m.outputSafe}</p>
            </div>
          </div>
        </section>
      )}
    </>
  );
}
