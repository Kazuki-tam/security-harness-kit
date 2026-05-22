import type { Messages } from "../i18n/types";
import type { ActionResult } from "../types";

type ActionMessages = Messages["setup"]["action"];

function localizeTitle(message: string, titles: Record<string, string>): string {
  if (titles[message]) return titles[message];
  for (const [key, value] of Object.entries(titles)) {
    if (message.startsWith(key)) return value;
  }
  return message;
}

export function localizeActionResult(
  result: ActionResult,
  action: ActionMessages,
): { title: string; details: string[] } {
  const title = localizeTitle(result.message, action.resultTitles);
  const details = result.details.map((line) => action.resultDetails[line] ?? line);
  return { title, details };
}

export function actionFeedbackTone(result: ActionResult): "success" | "warning" | "error" {
  if (!result.success) return "error";
  const lower = result.message.toLowerCase();
  if (
    lower.includes("partial") ||
    lower.includes("review remaining") ||
    lower.includes("no changes were required")
  ) {
    return "warning";
  }
  return "success";
}
