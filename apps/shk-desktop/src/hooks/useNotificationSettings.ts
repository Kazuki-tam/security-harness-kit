import { useCallback, useState } from "react";
import {
  DEFAULT_NOTIFICATION_SETTINGS,
  parseNotificationSettings,
  type NotificationSettings,
} from "../notifications";

const SETTINGS_KEY = "shk.desktop.blockedNotifications.v1";

function loadSettings(): NotificationSettings {
  if (typeof window === "undefined") return DEFAULT_NOTIFICATION_SETTINGS;
  try {
    return parseNotificationSettings(window.localStorage.getItem(SETTINGS_KEY));
  } catch {
    return DEFAULT_NOTIFICATION_SETTINGS;
  }
}

/** App-wide preferences for blocked-activity notifications. */
export function useNotificationSettings() {
  const [settings, setSettings] = useState<NotificationSettings>(loadSettings);

  const updateSettings = useCallback((patch: Partial<NotificationSettings>) => {
    setSettings((prev) => {
      const next = { ...prev, ...patch };
      try {
        window.localStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
      } catch {
        /* ignore quota errors */
      }
      return next;
    });
  }, []);

  return { notificationSettings: settings, updateNotificationSettings: updateSettings };
}
