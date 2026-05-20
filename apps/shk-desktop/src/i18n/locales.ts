import type { Locale } from "./types";

export type LocaleOption = {
  code: Locale;
  label: string;
};

export const localeOptions: LocaleOption[] = [
  { code: "en", label: "English" },
  { code: "ja", label: "日本語" },
];

export function isLocale(value: string): value is Locale {
  return localeOptions.some((option) => option.code === value);
}
