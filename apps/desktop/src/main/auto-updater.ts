/**
 * Auto-update integration for the OpenCred desktop application.
 *
 * Uses electron-updater to check for, download, and install updates from
 * GitHub Releases. The module exposes:
 *  - initAutoUpdater()  — call once after app is ready
 *  - getUpdateStatus()  — return the current UpdateStatus snapshot
 *  - checkForUpdates()  — manually trigger an update check
 *  - downloadUpdate()   — start downloading an available update
 *  - quitAndInstall()   — install a downloaded update and restart
 *
 * Update events are forwarded to the renderer via BrowserWindow.webContents.send
 * so the UI can display notifications and progress.
 *
 * SECURITY NOTES:
 *  - Auto-update feed is served over HTTPS from GitHub Releases.
 *  - electron-updater verifies release signatures automatically.
 *  - No key material is involved in the update flow.
 *
 * ROLLBACK:
 *  - electron-updater does not provide built-in rollback. If a bad update is
 *    published, the recommended approach is to publish a new release that
 *    reverts the changes. Users can also manually install a previous version
 *    from the GitHub Releases page.
 */

import pkg from "electron-updater";
const { autoUpdater } = pkg;
import type { UpdateInfo, ProgressInfo } from "electron-updater";
import { BrowserWindow } from "electron";
import { createLogger } from "./logger.js";

const logger = createLogger("updater");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UpdateStatus {
  checking: boolean;
  available: boolean;
  downloading: boolean;
  downloaded: boolean;
  version?: string;
  releaseNotes?: string;
  progress?: {
    percent: number;
    bytesPerSecond: number;
    total: number;
    transferred: number;
  };
  error?: string;
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

let status: UpdateStatus = {
  checking: false,
  available: false,
  downloading: false,
  downloaded: false,
};

let periodicCheckInterval: ReturnType<typeof setInterval> | null = null;

/** Delay (ms) before the first automatic check after app start. */
const INITIAL_CHECK_DELAY_MS = 10_000; // 10 seconds

/** Interval (ms) between periodic update checks. */
const PERIODIC_CHECK_INTERVAL_MS = 4 * 60 * 60 * 1_000; // 4 hours

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Send the current update status to all open renderer windows.
 */
function broadcastStatus(): void {
  const windows = BrowserWindow.getAllWindows();
  for (const win of windows) {
    if (!win.isDestroyed()) {
      win.webContents.send("update:status", { ...status });
    }
  }
}

function resetStatus(): void {
  status = {
    checking: false,
    available: false,
    downloading: false,
    downloaded: false,
  };
}

function extractReleaseNotes(info: UpdateInfo): string | undefined {
  if (!info.releaseNotes) return undefined;
  if (typeof info.releaseNotes === "string") return info.releaseNotes;
  // Array of { version, note } — concatenate
  if (Array.isArray(info.releaseNotes)) {
    return info.releaseNotes
      .map((n) => (typeof n === "string" ? n : n.note))
      .filter(Boolean)
      .join("\n\n");
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Initialise the auto-updater. Call once after `app.whenReady()`.
 *
 * Configures electron-updater, registers event handlers, and schedules
 * periodic update checks.
 */
export function initAutoUpdater(): void {
  // Do not auto-download — let the user decide.
  autoUpdater.autoDownload = false;
  autoUpdater.autoInstallOnAppQuit = true;

  // --- Event handlers ---------------------------------------------------

  autoUpdater.on("checking-for-update", () => {
    logger.info("Checking for updates");
    status.checking = true;
    status.error = undefined;
    broadcastStatus();
  });

  autoUpdater.on("update-available", (info: UpdateInfo) => {
    logger.info("Update available", { version: info.version });
    status.checking = false;
    status.available = true;
    status.version = info.version;
    status.releaseNotes = extractReleaseNotes(info);
    broadcastStatus();
  });

  autoUpdater.on("update-not-available", () => {
    logger.info("No update available");
    status.checking = false;
    status.available = false;
    broadcastStatus();
  });

  autoUpdater.on("download-progress", (progress: ProgressInfo) => {
    status.downloading = true;
    status.progress = {
      percent: progress.percent,
      bytesPerSecond: progress.bytesPerSecond,
      total: progress.total,
      transferred: progress.transferred,
    };
    broadcastStatus();
  });

  autoUpdater.on("update-downloaded", (info: UpdateInfo) => {
    logger.info("Update downloaded", { version: info.version });
    status.downloading = false;
    status.downloaded = true;
    status.version = info.version;
    status.releaseNotes = extractReleaseNotes(info);
    status.progress = undefined;
    broadcastStatus();
  });

  autoUpdater.on("error", (err: Error) => {
    logger.error("Auto-updater error", { error: err.message });
    status.checking = false;
    status.downloading = false;
    status.error = err.message;
    broadcastStatus();
  });

  // --- Schedule checks ---------------------------------------------------

  // Initial check after a short delay so the window has time to load.
  setTimeout(() => {
    void checkForUpdates();
  }, INITIAL_CHECK_DELAY_MS);

  // Periodic checks every 4 hours. `.unref()` (Anand's P2-06) so the
  // interval never keeps the Electron main process alive past `app.quit()`.
  // `cleanupAutoUpdater` is still wired to `before-quit` for the
  // cooperative-shutdown path — this just guarantees that if that wiring
  // ever regresses the app won't hang on exit for up to 4 hours.
  periodicCheckInterval = setInterval(() => {
    void checkForUpdates();
  }, PERIODIC_CHECK_INTERVAL_MS);
  periodicCheckInterval.unref?.();
}

/**
 * Manually check for updates.
 */
export async function checkForUpdates(): Promise<UpdateStatus> {
  try {
    await autoUpdater.checkForUpdates();
  } catch {
    // Error is handled by the "error" event listener.
  }
  return { ...status };
}

/**
 * Start downloading an available update.
 */
export async function downloadUpdate(): Promise<UpdateStatus> {
  if (!status.available) {
    return { ...status };
  }
  try {
    status.downloading = true;
    broadcastStatus();
    await autoUpdater.downloadUpdate();
  } catch {
    // Error is handled by the "error" event listener.
  }
  return { ...status };
}

/**
 * Install the downloaded update and restart the application.
 */
export function quitAndInstall(): void {
  if (status.downloaded) {
    autoUpdater.quitAndInstall();
  }
}

/**
 * Return the current update status snapshot.
 */
export function getUpdateStatus(): UpdateStatus {
  return { ...status };
}

/**
 * Clean up the auto-updater. Call during app shutdown.
 */
export function cleanupAutoUpdater(): void {
  if (periodicCheckInterval) {
    clearInterval(periodicCheckInterval);
    periodicCheckInterval = null;
  }
  resetStatus();
}
