/** Tauri event carrying blocks appended to a watched project's audit log. */
export const BLOCKED_EVENT = "shk://blocked";

export const NOTIFICATION_SETTINGS_KEY = "shk.desktop.blockedNotifications.v1";

/**
 * Window over which blocks are collected into a single notification. An agent
 * that trips a guard usually trips it several times in a row, and one banner
 * per attempt would bury the signal.
 */
export const NOTIFICATION_DEBOUNCE_MS = 3000;

/** Keep untrusted project labels compact enough for an OS notification. */
const MAX_PROJECT_NAME_CHARS = 80;
const MAX_PROJECTS_IN_BODY = 3;

/** Invisible/control ranges that can reorder or disguise notification text. */
const UNSAFE_NOTIFICATION_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x00, 0x1f],
  [0x7f, 0x9f],
  [0xad, 0xad],
  [0x34f, 0x34f],
  [0x61c, 0x61c],
  [0x180e, 0x180e],
  [0x200b, 0x200b],
  [0x202a, 0x202e],
  [0x2060, 0x2060],
  [0x2066, 0x2069],
  [0xfeff, 0xfeff],
  [0xe0000, 0xe007f],
  [0xe0100, 0xe01ef],
];

/**
 * A `blocked` audit entry forwarded live by the Rust watcher.
 *
 * The watcher deliberately does not forward the blocked file path: the audit
 * report can hide paths on request, and a notification renders on the lock
 * screen and is persisted by the OS.
 */
export type BlockedNotificationEvent = {
  project_path: string;
  tool?: string | null;
  reason?: string | null;
  action_category?: string | null;
};

export type NotificationSettings = {
  enabled: boolean;
  actionGuard: boolean;
  findingThreshold: boolean;
};

/** Settings plus their updater, as passed to the UI that renders the toggles. */
export type NotificationControls = {
  settings: NotificationSettings;
  onChange: (patch: Partial<NotificationSettings>) => void;
};

export const DEFAULT_NOTIFICATION_SETTINGS: NotificationSettings = {
  enabled: true,
  actionGuard: true,
  findingThreshold: true,
};

export type BlockedNotificationLabels = {
  /** Title for blocks that all came from one project. */
  singleProjectTitle: string;
  /** Title when blocks span several projects. */
  multiProjectTitle: string;
  /** Suffix naming how many further blocks the batch collapsed into this one. */
  moreCount: string;
  /** Stands in for a block whose reason has no label we recognise. */
  unknownReason: string;
  /** Stands in for a project that is no longer registered. */
  unknownProject: string;
  reasonLabels: Record<string, string>;
  actionCategories: Record<string, string>;
  toolNames: Record<string, string>;
};

/**
 * Notifications are display-only. `tauri-plugin-notification` registers just
 * `notify` / `request_permission` / `is_permission_granted` on desktop — the
 * click callback (`onAction`) exists only on iOS and Android — so there is no
 * payload to route a click back to a project.
 */
export type BlockedNotificationContent = {
  title: string;
  body: string;
};

export function parseNotificationSettings(raw: string | null): NotificationSettings {
  if (!raw) return DEFAULT_NOTIFICATION_SETTINGS;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return DEFAULT_NOTIFICATION_SETTINGS;
    const value = parsed as Partial<Record<keyof NotificationSettings, unknown>>;
    return {
      enabled: asBoolean(value.enabled, DEFAULT_NOTIFICATION_SETTINGS.enabled),
      actionGuard: asBoolean(value.actionGuard, DEFAULT_NOTIFICATION_SETTINGS.actionGuard),
      findingThreshold: asBoolean(
        value.findingThreshold,
        DEFAULT_NOTIFICATION_SETTINGS.findingThreshold,
      ),
    };
  } catch {
    return DEFAULT_NOTIFICATION_SETTINGS;
  }
}

function asBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

export function readNotificationSettings(): NotificationSettings {
  if (typeof window === "undefined") return DEFAULT_NOTIFICATION_SETTINGS;
  try {
    return parseNotificationSettings(window.localStorage.getItem(NOTIFICATION_SETTINGS_KEY));
  } catch (error) {
    console.warn("failed to read notification settings", error);
    return DEFAULT_NOTIFICATION_SETTINGS;
  }
}

export function writeNotificationSettings(next: NotificationSettings): void {
  try {
    window.localStorage.setItem(NOTIFICATION_SETTINGS_KEY, JSON.stringify(next));
  } catch (error) {
    console.warn("failed to save notification settings", error);
  }
}

export function shouldNotifyForEvent(
  event: BlockedNotificationEvent,
  settings: NotificationSettings,
): boolean {
  if (!settings.enabled) return false;
  if (event.reason === "action_guard") return settings.actionGuard;
  if (event.reason === "finding_threshold") return settings.findingThreshold;
  // Other block reasons (currently `policy_error`) follow the master toggle:
  // they are still a hook refusing to let an action through.
  return true;
}

export function notifiableEvents(
  events: BlockedNotificationEvent[],
  settings: NotificationSettings,
): BlockedNotificationEvent[] {
  return events.filter((event) => shouldNotifyForEvent(event, settings));
}

/**
 * Collapse a batch of blocks into one notification. Returns `null` when there
 * is nothing to announce.
 */
export function summarizeBlockedBatch(
  events: BlockedNotificationEvent[],
  projectNameFor: (path: string) => string,
  labels: BlockedNotificationLabels,
): BlockedNotificationContent | null {
  if (events.length === 0) return null;

  const paths = [...new Set(events.map((event) => event.project_path))];
  const projectNames = paths.map((path) =>
    safeProjectName(projectNameFor(path), labels.unknownProject),
  );

  if (paths.length > 1) {
    const visibleNames = projectNames.slice(0, MAX_PROJECTS_IN_BODY);
    if (projectNames.length > visibleNames.length) {
      visibleNames.push(
        interpolateCount(labels.moreCount, projectNames.length - visibleNames.length),
      );
    }
    return {
      title: interpolateCount(labels.multiProjectTitle, events.length),
      body: visibleNames.join(", "),
    };
  }

  const title = labels.singleProjectTitle.replace("{{project}}", projectNames[0]);

  // Newest last in the log, and the newest block is what the user just hit.
  const [latest] = events.slice(-1);
  const lines = [describeBlockedEvent(latest, labels)];
  if (events.length > 1) {
    lines.push(interpolateCount(labels.moreCount, events.length - 1));
  }

  return { title, body: lines.join(" · ") };
}

function interpolateCount(template: string, count: number): string {
  return template.replace("{{count}}", String(count));
}

/**
 * Project names may originate in cloned repository names or user-controlled
 * local storage. Strip characters that can spoof a signed app's notification,
 * normalize whitespace, and bound the result without splitting code points.
 */
export function safeProjectName(name: string, fallback: string): string {
  const safeCharacters = Array.from(name, (character) => {
    if (character === "\r" || character === "\n" || character === "\t") return " ";
    const codePoint = character.codePointAt(0);
    if (
      codePoint !== undefined &&
      UNSAFE_NOTIFICATION_RANGES.some(([start, end]) => codePoint >= start && codePoint <= end)
    ) {
      return "";
    }
    return character;
  });
  const cleaned = safeCharacters.join("").replace(/\s+/gu, " ").trim();
  if (!cleaned) return fallback;

  const characters = Array.from(cleaned);
  if (characters.length <= MAX_PROJECT_NAME_CHARS) return cleaned;
  return `${characters.slice(0, MAX_PROJECT_NAME_CHARS).join("")}…`;
}

/**
 * Describe one block for a notification body.
 *
 * Only values with a label we recognise are rendered. The audit log is written
 * by the CLI, but a cloned repository can ship a crafted one, and a banner from
 * a signed, notarized app is a credible surface for planted text — so unknown
 * identifiers are replaced rather than echoed.
 */
export function describeBlockedEvent(
  event: BlockedNotificationEvent,
  labels: BlockedNotificationLabels,
): string {
  const parts = [knownLabel(event.reason, labels.reasonLabels) ?? labels.unknownReason];

  if (event.reason === "action_guard") {
    const category = knownLabel(event.action_category, labels.actionCategories);
    if (category) parts.push(category);
  }

  const tool = knownLabel(event.tool, labels.toolNames);
  if (tool) parts.push(tool);

  return parts.join(" · ");
}

/**
 * Look up an identifier's label. Own keys only, so an id like `constructor`
 * cannot reach through to `Object.prototype`.
 */
function knownLabel(
  id: string | null | undefined,
  labels: Record<string, string>,
): string | undefined {
  if (!id || !Object.prototype.hasOwnProperty.call(labels, id)) return undefined;
  return labels[id];
}

export type BlockedNotificationBatcher = {
  /** Buffer freshly received blocks and arm the coalescing window. */
  push: (events: BlockedNotificationEvent[]) => void;
  /** Drop anything buffered and disarm, e.g. on unmount. */
  cancel: () => void;
};

/**
 * Coalesce blocks arriving within `debounceMs` into a single notification.
 *
 * Settings and labels are read through callbacks at flush time so a preference
 * the user changes mid-window takes effect, and so the caller can keep them in
 * refs without rebuilding the batcher.
 */
export function createBlockedNotificationBatcher({
  getSettings,
  getLabels,
  projectNameFor,
  notify,
  debounceMs = NOTIFICATION_DEBOUNCE_MS,
}: {
  getSettings: () => NotificationSettings;
  getLabels: () => BlockedNotificationLabels;
  projectNameFor: (path: string) => string;
  notify: (content: BlockedNotificationContent) => void;
  debounceMs?: number;
}): BlockedNotificationBatcher {
  let pending: BlockedNotificationEvent[] = [];
  let timer: ReturnType<typeof setTimeout> | null = null;

  function flush() {
    timer = null;
    const batch = notifiableEvents(pending, getSettings());
    // Cleared unconditionally: a batch the user has since filtered out, or one
    // the OS refuses to show, must not accumulate into the next window.
    pending = [];
    const content = summarizeBlockedBatch(batch, projectNameFor, getLabels());
    if (content) notify(content);
  }

  return {
    push(events) {
      if (events.length === 0) return;
      pending.push(...events);
      // Trailing edge of a fixed window, not a sliding one: a sustained burst
      // still notifies every `debounceMs` rather than staying silent.
      timer ??= setTimeout(flush, debounceMs);
    },
    cancel() {
      if (timer !== null) clearTimeout(timer);
      timer = null;
      pending = [];
    },
  };
}
