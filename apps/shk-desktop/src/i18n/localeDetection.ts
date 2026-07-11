import { isLocale } from "./locales";
import type { Locale } from "./types";

const DEFAULT_LOCALE: Locale = "en";

export function detectBrowserLocale(): Locale {
  if (typeof navigator === "undefined") return DEFAULT_LOCALE;
  const languages = navigator.languages?.length ? navigator.languages : [navigator.language];
  for (const lang of languages) {
    const normalized = lang.toLowerCase();
    if (normalized.startsWith("ja")) return "ja";
    if (normalized.startsWith("en")) return "en";
  }
  return DEFAULT_LOCALE;
}

export function resolveInitialLocale(stored: string | null): Locale {
  if (stored && isLocale(stored)) return stored;
  return detectBrowserLocale();
}
