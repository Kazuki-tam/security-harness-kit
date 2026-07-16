import { Languages } from "lucide-react";
import { useI18n, type Locale } from "../i18n";
import { localeOptions } from "../i18n/locales";

export function LanguageSwitcher() {
  const { locale, setLocale, messages } = useI18n();

  return (
    <label className="inline-flex h-7 items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 text-[11px] font-medium text-[var(--color-text)] transition hover:border-sky-300/60 hover:text-white focus-within:border-sky-300/60 focus-within:ring-2 focus-within:ring-sky-300/70">
      <Languages size={12} aria-hidden="true" className="shrink-0 text-[var(--color-muted)]" />
      <span className="sr-only">{messages.common.language}</span>
      <select
        value={locale}
        onChange={(event) => setLocale(event.target.value as Locale)}
        aria-label={messages.common.language}
        className="cursor-pointer appearance-none bg-transparent pr-4 text-[11px] font-medium text-[var(--color-text)] outline-none"
      >
        {localeOptions.map(({ code, label }) => (
          <option key={code} value={code}>
            {label}
          </option>
        ))}
      </select>
    </label>
  );
}
