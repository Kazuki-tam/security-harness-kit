export function createRequestTracker() {
  const ids = new Map<string, number>();

  return {
    begin(key: string) {
      const next = (ids.get(key) ?? 0) + 1;
      ids.set(key, next);
      return next;
    },
    isLatest(key: string, requestId: number) {
      return ids.get(key) === requestId;
    },
  };
}
