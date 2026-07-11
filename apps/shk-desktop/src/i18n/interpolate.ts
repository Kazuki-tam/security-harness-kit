export function interpolate(template: string, params?: Record<string, string | number>): string {
  if (!params) return template;
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => String(params[key] ?? ""));
}

export function operationErrorMessage(template: string, error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return interpolate(template, { message });
}
