import { formatActionCategory, formatToolName } from "./audit";
import { interpolate } from "./i18n/interpolate";

/** Tauri event carrying blocks appended to a watched project's audit log. */
export const BLOCKED_EVENT = "shk://blocked";

/** A `blocked` audit entry forwarded live by the Rust watcher. */
export type BlockedNotificationEvent = {
  project_path: string;
  ts?: string | null;
  tool?: string | null;
  hook?: string | null;
  reason?: string | null;
  action_category?: string | null;
  display_path?: string | null;
  max_severity?: string | null;
};

export type NotificationSettings = {
  enabled: boolean;
  actionGuard: boolean;
  findingThreshold: boolean;
};

export const DEFAULT_NOTIFICATION_SETTINGS: NotificationSettings = {
  enabled: true,
  actionGuard: true,
  findingThreshold: true,
};

/**
 * Window over which blocks are collected into a single notification. An agent
 * that trips a guard usually trips it several times in a row, and one banner
 * per attempt would bury the signal.
 */
export const NOTIFICATION_DEBOUNCE_MS = 3000;

export type BlockedNotificationLabels = {
  /** Title for blocks that all came from one project. */
  singleProjectTitle: string;
  /** Title when blocks span several projects. */
  multiProjectTitle: string;
  /** Body for a single block: reason, what was blocked, and the AI tool. */
  moreCount: string;
  reasonLabels: Record<string, string>;
  actionCategories: Record<string, string>;
  toolNames: Record<string, string>;
};

export type BlockedNotificationContent = {
  title: string;
  body: string;
  /** Project the notification should open when clicked, if unambiguous. */
  projectPath?: string;
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

  if (paths.length > 1) {
    return {
      title: interpolate(labels.multiProjectTitle, { count: events.length }),
      body: paths.map(projectNameFor).join(", "),
    };
  }

  const projectPath = paths[0];
  const title = interpolate(labels.singleProjectTitle, {
    count: events.length,
    project: projectNameFor(projectPath),
  });

  // Newest last in the log, and the newest block is what the user just hit.
  const [latest] = events.slice(-1);
  const lines = [describeBlockedEvent(latest, labels)];
  if (events.length > 1) {
    lines.push(interpolate(labels.moreCount, { count: events.length - 1 }));
  }

  return { title, body: lines.join(" · "), projectPath };
}

export function describeBlockedEvent(
  event: BlockedNotificationEvent,
  labels: BlockedNotificationLabels,
): string {
  const reason = event.reason ?? "";
  const parts = [labels.reasonLabels[reason] ?? reason].filter(Boolean);

  const detail =
    event.reason === "action_guard"
      ? formatActionCategory(event.action_category ?? undefined, labels.actionCategories)
      : (event.display_path ?? "—");
  if (detail && detail !== "—") {
    parts.push(detail);
  }

  const tool = formatToolName(event.tool ?? undefined, labels.toolNames);
  if (tool !== "—") {
    parts.push(tool);
  }

  return parts.join(" · ");
}
