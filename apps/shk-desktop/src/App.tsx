import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import {
  AlertTriangle,
  CheckCircle2,
  FileWarning,
  FolderOpen,
  Loader2,
  Search,
  ShieldCheck,
} from "lucide-react";
import {
  asSeverity,
  severityDot,
  severityLabels,
  severityOrder,
  severityText,
  type ScanReport,
  type ScanState,
  type Severity,
} from "./scan";

function App() {
  const [selectedPath, setSelectedPath] = useState("");
  const [scanState, setScanState] = useState<ScanState>({ status: "idle" });
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");

  const isScanning = scanState.status === "running";
  const report = scanState.status === "done" ? scanState.report : undefined;

  const visibleFindings = useMemo(() => {
    if (!report) return [];
    const sorted = [...report.findings].sort((a, b) => {
      return (
        severityOrder.indexOf(asSeverity(a.severity)) -
        severityOrder.indexOf(asSeverity(b.severity))
      );
    });
    if (severityFilter === "all") return sorted;
    return sorted.filter((finding) => asSeverity(finding.severity) === severityFilter);
  }, [report, severityFilter]);

  async function chooseFolder() {
    const path = await open({
      directory: true,
      multiple: false,
      title: "スキャンするフォルダを選択",
    });

    if (typeof path === "string") {
      setSelectedPath(path);
      setScanState({ status: "idle" });
    }
  }

  async function runScan() {
    if (!selectedPath || isScanning) return;
    setScanState({ status: "running" });
    try {
      const report = await invoke<ScanReport>("scan_path", { path: selectedPath });
      setSeverityFilter("all");
      setScanState({ status: "done", report });
    } catch (error) {
      setScanState({
        status: "error",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const total = report?.summary.total ?? 0;
  const hasActionableFindings = report?.findings.some((finding) => {
    const severity = asSeverity(finding.severity);
    return severity === "critical" || severity === "high";
  });

  return (
    <main className="grid min-h-screen min-w-[960px] grid-cols-[260px_minmax(0,1fr)] bg-slate-100 text-slate-900">
      <aside className="flex flex-col gap-8 bg-slate-900 px-5 py-7 text-slate-50">
        <div className="flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-lg bg-sky-300 text-slate-900">
            <ShieldCheck size={24} aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-[22px] font-bold leading-none">shk</h1>
            <p className="mt-1 text-[13px] text-slate-300">Security Harness Kit</p>
          </div>
        </div>

        <nav className="grid gap-2" aria-label="主な操作">
          <button
            className="flex min-h-11 items-center gap-2 rounded-lg bg-slate-700 px-3 text-left font-medium text-white"
            type="button"
          >
            <Search size={18} aria-hidden="true" />
            スキャン
          </button>
          <button
            className="flex min-h-11 items-center gap-2 rounded-lg px-3 text-left font-medium text-slate-300 opacity-45"
            type="button"
            disabled
          >
            <FileWarning size={18} aria-hidden="true" />
            ポリシー
          </button>
        </nav>
      </aside>

      <section className="flex flex-col gap-5 p-8">
        <header className="flex items-center justify-between gap-5">
          <div>
            <p className="text-[13px] font-bold text-slate-500">デスクトップスキャン</p>
            <h2 className="mt-1 text-[28px] font-bold leading-tight text-slate-950">
              フォルダ内の機密情報を確認
            </h2>
          </div>
          <button
            className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-4 text-slate-900"
            type="button"
            onClick={chooseFolder}
            disabled={isScanning}
          >
            <FolderOpen size={18} aria-hidden="true" />
            フォルダを選択
          </button>
        </header>

        <section
          className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 rounded-lg border border-slate-200 bg-white p-4"
          aria-label="スキャン対象"
        >
          <div className="flex min-h-11 min-w-0 items-center rounded-lg border border-slate-200 bg-slate-50 px-3 text-slate-600">
            <span className="truncate">{selectedPath || "まだフォルダが選択されていません"}</span>
          </div>
          <button
            className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-teal-700 bg-teal-700 px-4 font-bold text-white disabled:cursor-not-allowed disabled:opacity-55"
            type="button"
            onClick={runScan}
            disabled={!selectedPath || isScanning}
          >
            {isScanning ? (
              <Loader2 className="animate-spin" size={18} aria-hidden="true" />
            ) : (
              <Search size={18} aria-hidden="true" />
            )}
            スキャン
          </button>
        </section>

        {scanState.status === "error" && (
          <section
            className="flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 p-4 text-red-800"
            role="alert"
          >
            <AlertTriangle size={20} aria-hidden="true" />
            <div>
              <strong className="block">スキャンできませんでした</strong>
              <p className="mt-1 text-slate-600">{scanState.message}</p>
            </div>
          </section>
        )}

        {report && (
          <>
            <section
              className={`flex items-start gap-3 rounded-lg border p-4 ${hasActionableFindings ? "border-orange-200 bg-orange-50 text-orange-800" : "border-green-200 bg-green-50 text-green-800"}`}
            >
              {hasActionableFindings ? (
                <AlertTriangle size={22} aria-hidden="true" />
              ) : (
                <CheckCircle2 size={22} aria-hidden="true" />
              )}
              <div>
                <strong className="block">
                  {hasActionableFindings
                    ? "対応が必要な検出があります"
                    : "対応が必要な検出はありません"}
                </strong>
                <p className="mt-1 text-slate-600">
                  {total} 件の検出、{report.suppressed} 件の抑制、{report.deduplicated} 件の重複除外
                </p>
              </div>
            </section>

            <section className="grid grid-cols-5 gap-3" aria-label="検出サマリー">
              {severityOrder.map((severity) => (
                <button
                  key={severity}
                  className={`flex min-h-[76px] items-center justify-between rounded-lg border bg-white p-4 text-left text-slate-700 ${severityFilter === severity ? "border-sky-600 outline outline-3 outline-sky-200" : "border-slate-200"}`}
                  type="button"
                  onClick={() => setSeverityFilter(severityFilter === severity ? "all" : severity)}
                >
                  <span className="text-sm font-bold">{severityLabels[severity]}</span>
                  <strong className={`text-[26px] leading-none ${severityText[severity]}`}>
                    {report.summary.by_severity[severity] ?? 0}
                  </strong>
                </button>
              ))}
            </section>

            <section
              className="overflow-hidden rounded-lg border border-slate-200 bg-white"
              aria-label="検出一覧"
            >
              <div className="border-b border-slate-200 px-5 py-4">
                <h3 className="text-lg font-bold text-slate-950">検出一覧</h3>
                <p className="mt-1 text-[13px] text-slate-500">
                  {severityFilter === "all" ? "すべての検出" : severityLabels[severityFilter]}
                  を表示中
                </p>
              </div>

              {visibleFindings.length === 0 ? (
                <div className="grid min-h-60 place-items-center gap-2 p-8 text-center text-slate-500">
                  <CheckCircle2 size={28} aria-hidden="true" />
                  <p>この条件に一致する検出はありません。</p>
                </div>
              ) : (
                <div className="grid">
                  {visibleFindings.map((finding, index) => {
                    const severity = asSeverity(finding.severity);
                    return (
                      <article
                        className="grid grid-cols-[12px_minmax(0,1fr)] gap-3 border-b border-slate-100 px-5 py-4 last:border-b-0"
                        key={`${finding.file}:${finding.line}:${finding.column}:${finding.rule_id}:${index}`}
                      >
                        <div
                          className={`mt-1.5 h-2.5 w-2.5 rounded-full ${severityDot[severity]}`}
                          aria-hidden="true"
                        />
                        <div className="min-w-0">
                          <div className="flex items-center justify-between gap-3">
                            <strong className="text-slate-950">{finding.message}</strong>
                            <span className="shrink-0 rounded-full bg-slate-100 px-2 py-1 text-xs font-bold text-slate-700">
                              {severityLabels[severity]}
                            </span>
                          </div>
                          <p className="mt-1.5 truncate text-slate-600">{finding.file}</p>
                          <div className="mt-2.5 flex flex-wrap gap-2">
                            <span className="rounded-md bg-slate-100 px-2 py-1 text-xs text-slate-600">
                              行 {finding.line}
                            </span>
                            <span className="rounded-md bg-slate-100 px-2 py-1 text-xs text-slate-600">
                              {finding.kind}
                            </span>
                            <span className="rounded-md bg-slate-100 px-2 py-1 text-xs text-slate-600">
                              {finding.rule_id}
                            </span>
                          </div>
                        </div>
                      </article>
                    );
                  })}
                </div>
              )}
            </section>
          </>
        )}

        {!report && scanState.status !== "error" && (
          <section className="grid min-h-60 place-items-center gap-2 p-8 text-center text-slate-500">
            <ShieldCheck size={36} aria-hidden="true" />
            <h3 className="text-xl font-bold text-slate-900">まずフォルダを選択してください</h3>
            <p className="max-w-xl">
              結果には実際の値を表示せず、検出場所と対応に必要な情報だけを表示します。
            </p>
          </section>
        )}
      </section>
    </main>
  );
}

export default App;
