import { useCallback, useState } from "react";
import {
  readNotificationSettings,
  writeNotificationSettings,
  type NotificationSettings,
} from "../notifications";

/**
 * App-wide preferences for blocked-activity notifications.
 *
 * Call this once, at the top of the tree: it is plain `useState`, so a second
 * call would create a copy that `useBlockedNotifications` never sees.
 */
export function useNotificationSettings() {
  const [notificationSettings, setSettings] =
    useState<NotificationSettings>(readNotificationSettings);

  const updateNotificationSettings = useCallback((patch: Partial<NotificationSettings>) => {
    setSettings((prev) => {
      const next = { ...prev, ...patch };
      writeNotificationSettings(next);
      return next;
    });
  }, []);

  return { notificationSettings, updateNotificationSettings };
}
