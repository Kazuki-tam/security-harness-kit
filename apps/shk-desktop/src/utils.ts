import type { Messages } from "./i18n/types";

export function basenameOf(path: string): string {
  if (!path) return "";
  const trimmed = path.replace(/[\\/]+$/, "");
  const parts = trimmed.split(/[\\/]/);
  return parts[parts.length - 1] || trimmed;
}

export function dirnameOf(path: string): string {
  if (!path) return "";
  const trimmed = path.replace(/[\\/]+$/, "");
  const idx = trimmed.search(/[\\/][^\\/]*$/);
  if (idx <= 0) return "";
  return trimmed.slice(0, idx);
}

export function generateId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `proj_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`;
}

export function shortenPath(path: string): string {
  if (!path) return "";
  const unix = path.match(/^(\/(?:Users|home)\/[^/]+)(\/.*)?$/);
  if (unix) {
    return `~${unix[2] ?? ""}`;
  }
  const win = path.match(/^[A-Za-z]:[\\/]Users[\\/][^\\/]+([\\/].*)?$/);
  if (win) {
    const rest = (win[1] ?? "").replace(/\\/g, "/");
    return `~${rest}`;
  }
  return path;
}

function interpolate(template: string, count: number): string {
  return template.replace(/\{\{count\}\}/g, String(count));
}

export function formatRelativeTime(iso: string | undefined, time: Messages["time"]): string {
  if (!iso) return time.notScanned;
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return time.notScanned;
  const diff = Date.now() - then;
  const sec = Math.max(0, Math.floor(diff / 1000));
  if (sec < 45) return time.justNow;
  const min = Math.floor(sec / 60);
  if (min < 60) return interpolate(time.minutesAgo, min);
  const hr = Math.floor(min / 60);
  if (hr < 24) return interpolate(time.hoursAgo, hr);
  const day = Math.floor(hr / 24);
  if (day < 7) return interpolate(time.daysAgo, day);
  const week = Math.floor(day / 7);
  if (week < 5) return interpolate(time.weeksAgo, week);
  const month = Math.floor(day / 30);
  if (month < 12) return interpolate(time.monthsAgo, month);
  const year = Math.floor(day / 365);
  return interpolate(time.yearsAgo, year);
}
