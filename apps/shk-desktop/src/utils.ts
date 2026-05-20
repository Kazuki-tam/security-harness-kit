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

export function formatRelativeTime(iso: string | undefined): string {
  if (!iso) return "未スキャン";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "未スキャン";
  const diff = Date.now() - then;
  const sec = Math.max(0, Math.floor(diff / 1000));
  if (sec < 45) return "たった今";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min} 分前`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr} 時間前`;
  const day = Math.floor(hr / 24);
  if (day < 7) return `${day} 日前`;
  const week = Math.floor(day / 7);
  if (week < 5) return `${week} 週間前`;
  const month = Math.floor(day / 30);
  if (month < 12) return `${month} ヶ月前`;
  const year = Math.floor(day / 365);
  return `${year} 年前`;
}
