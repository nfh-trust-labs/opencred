/**
 * Tests for the auto-updater module.
 *
 * Mocks electron-updater's autoUpdater and Electron's BrowserWindow to verify:
 *  - Initialisation configures autoUpdater correctly
 *  - checkForUpdates triggers the update check flow
 *  - Download progress events update status
 *  - Install-on-quit triggers quitAndInstall
 *  - Error handling propagates to status
 *  - Update status tracking across lifecycle
 *  - Cleanup stops periodic checks
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// Capture event handlers registered on autoUpdater
// eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
const eventHandlers = new Map<string, Function>();

const mockAutoUpdater = {
  autoDownload: true,
  autoInstallOnAppQuit: false,
  // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
  on: vi.fn((event: string, handler: Function) => {
    eventHandlers.set(event, handler);
  }),
  checkForUpdates: vi.fn(),
  downloadUpdate: vi.fn(),
  quitAndInstall: vi.fn(),
};

vi.mock("electron-updater", () => ({
  default: { autoUpdater: mockAutoUpdater },
  autoUpdater: mockAutoUpdater,
}));

const mockWebContents = {
  send: vi.fn(),
};

const mockBrowserWindow = {
  isDestroyed: vi.fn().mockReturnValue(false),
  webContents: mockWebContents,
};

vi.mock("electron", () => ({
  BrowserWindow: {
    getAllWindows: vi.fn().mockReturnValue([mockBrowserWindow]),
  },
}));

// Import after mocking
const {
  initAutoUpdater,
  checkForUpdates,
  downloadUpdate,
  quitAndInstall,
  getUpdateStatus,
  cleanupAutoUpdater,
} = await import("../main/auto-updater");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("auto-updater", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    eventHandlers.clear();
    cleanupAutoUpdater();
  });

  afterEach(() => {
    vi.useRealTimers();
    cleanupAutoUpdater();
  });

  describe("initAutoUpdater", () => {
    it("should configure autoUpdater settings", () => {
      initAutoUpdater();

      expect(mockAutoUpdater.autoDownload).toBe(false);
      expect(mockAutoUpdater.autoInstallOnAppQuit).toBe(true);
    });

    it("should register event handlers for all update events", () => {
      initAutoUpdater();

      expect(mockAutoUpdater.on).toHaveBeenCalledWith("checking-for-update", expect.any(Function));
      expect(mockAutoUpdater.on).toHaveBeenCalledWith("update-available", expect.any(Function));
      expect(mockAutoUpdater.on).toHaveBeenCalledWith("update-not-available", expect.any(Function));
      expect(mockAutoUpdater.on).toHaveBeenCalledWith("download-progress", expect.any(Function));
      expect(mockAutoUpdater.on).toHaveBeenCalledWith("update-downloaded", expect.any(Function));
      expect(mockAutoUpdater.on).toHaveBeenCalledWith("error", expect.any(Function));
    });

    it("should schedule an initial update check after 10 seconds", () => {
      initAutoUpdater();

      expect(mockAutoUpdater.checkForUpdates).not.toHaveBeenCalled();

      vi.advanceTimersByTime(10_000);

      expect(mockAutoUpdater.checkForUpdates).toHaveBeenCalledTimes(1);
    });

    it("should schedule periodic checks every 4 hours", () => {
      initAutoUpdater();

      // Skip past the initial check delay
      vi.advanceTimersByTime(10_000);
      expect(mockAutoUpdater.checkForUpdates).toHaveBeenCalledTimes(1);

      // Advance by 4 hours
      vi.advanceTimersByTime(4 * 60 * 60 * 1_000);
      expect(mockAutoUpdater.checkForUpdates).toHaveBeenCalledTimes(2);

      // Another 4 hours
      vi.advanceTimersByTime(4 * 60 * 60 * 1_000);
      expect(mockAutoUpdater.checkForUpdates).toHaveBeenCalledTimes(3);
    });
  });

  describe("checkForUpdates", () => {
    it("should call autoUpdater.checkForUpdates", async () => {
      initAutoUpdater();
      mockAutoUpdater.checkForUpdates.mockResolvedValue(undefined);

      await checkForUpdates();

      expect(mockAutoUpdater.checkForUpdates).toHaveBeenCalled();
    });

    it("should return current status", async () => {
      initAutoUpdater();
      mockAutoUpdater.checkForUpdates.mockResolvedValue(undefined);

      const status = await checkForUpdates();

      expect(status).toHaveProperty("checking");
      expect(status).toHaveProperty("available");
      expect(status).toHaveProperty("downloading");
      expect(status).toHaveProperty("downloaded");
    });

    it("should handle errors gracefully", async () => {
      initAutoUpdater();
      mockAutoUpdater.checkForUpdates.mockRejectedValue(new Error("Network error"));

      // Should not throw
      const status = await checkForUpdates();
      expect(status).toBeDefined();
    });
  });

  describe("event: checking-for-update", () => {
    it("should set checking to true and broadcast", () => {
      initAutoUpdater();
      const handler = eventHandlers.get("checking-for-update");
      expect(handler).toBeDefined();

      handler!();

      const status = getUpdateStatus();
      expect(status.checking).toBe(true);
      expect(status.error).toBeUndefined();
      expect(mockWebContents.send).toHaveBeenCalledWith(
        "update:status",
        expect.objectContaining({ checking: true }),
      );
    });
  });

  describe("event: update-available", () => {
    it("should set available to true with version info", () => {
      initAutoUpdater();
      const handler = eventHandlers.get("update-available");
      expect(handler).toBeDefined();

      handler!({
        version: "1.2.0",
        releaseNotes: "Bug fixes and improvements",
      });

      const status = getUpdateStatus();
      expect(status.checking).toBe(false);
      expect(status.available).toBe(true);
      expect(status.version).toBe("1.2.0");
      expect(status.releaseNotes).toBe("Bug fixes and improvements");
    });

    it("should handle array-style release notes", () => {
      initAutoUpdater();
      const handler = eventHandlers.get("update-available");

      handler!({
        version: "1.3.0",
        releaseNotes: [
          { version: "1.3.0", note: "First note" },
          { version: "1.2.1", note: "Second note" },
        ],
      });

      const status = getUpdateStatus();
      expect(status.releaseNotes).toBe("First note\n\nSecond note");
    });

    it("should broadcast status to windows", () => {
      initAutoUpdater();
      const handler = eventHandlers.get("update-available");

      handler!({ version: "1.2.0", releaseNotes: null });

      expect(mockWebContents.send).toHaveBeenCalledWith(
        "update:status",
        expect.objectContaining({ available: true, version: "1.2.0" }),
      );
    });
  });

  describe("event: update-not-available", () => {
    it("should reset checking and available", () => {
      initAutoUpdater();
      const handler = eventHandlers.get("update-not-available");

      handler!();

      const status = getUpdateStatus();
      expect(status.checking).toBe(false);
      expect(status.available).toBe(false);
    });
  });

  describe("event: download-progress", () => {
    it("should track download progress", () => {
      initAutoUpdater();
      const handler = eventHandlers.get("download-progress");

      handler!({
        percent: 45.5,
        bytesPerSecond: 1024000,
        total: 50000000,
        transferred: 22750000,
      });

      const status = getUpdateStatus();
      expect(status.downloading).toBe(true);
      expect(status.progress).toEqual({
        percent: 45.5,
        bytesPerSecond: 1024000,
        total: 50000000,
        transferred: 22750000,
      });
    });

    it("should broadcast progress to windows", () => {
      initAutoUpdater();
      const handler = eventHandlers.get("download-progress");

      handler!({
        percent: 50,
        bytesPerSecond: 1000,
        total: 100,
        transferred: 50,
      });

      expect(mockWebContents.send).toHaveBeenCalledWith(
        "update:status",
        expect.objectContaining({
          downloading: true,
          progress: expect.objectContaining({ percent: 50 }),
        }),
      );
    });
  });

  describe("event: update-downloaded", () => {
    it("should set downloaded to true and clear progress", () => {
      initAutoUpdater();

      // Simulate download progress first
      const progressHandler = eventHandlers.get("download-progress");
      progressHandler!({
        percent: 100,
        bytesPerSecond: 1000,
        total: 100,
        transferred: 100,
      });

      const downloadedHandler = eventHandlers.get("update-downloaded");
      downloadedHandler!({
        version: "1.2.0",
        releaseNotes: "Done",
      });

      const status = getUpdateStatus();
      expect(status.downloading).toBe(false);
      expect(status.downloaded).toBe(true);
      expect(status.version).toBe("1.2.0");
      expect(status.progress).toBeUndefined();
    });
  });

  describe("event: error", () => {
    it("should set error message and reset checking/downloading", () => {
      initAutoUpdater();
      const handler = eventHandlers.get("error");

      handler!(new Error("Certificate verification failed"));

      const status = getUpdateStatus();
      expect(status.checking).toBe(false);
      expect(status.downloading).toBe(false);
      expect(status.error).toBe("Certificate verification failed");
    });
  });

  describe("downloadUpdate", () => {
    it("should call autoUpdater.downloadUpdate when update is available", async () => {
      initAutoUpdater();
      mockAutoUpdater.downloadUpdate.mockResolvedValue(undefined);

      // Set available state
      const availableHandler = eventHandlers.get("update-available");
      availableHandler!({ version: "2.0.0", releaseNotes: null });

      await downloadUpdate();

      expect(mockAutoUpdater.downloadUpdate).toHaveBeenCalled();
    });

    it("should not download when no update is available", async () => {
      initAutoUpdater();

      await downloadUpdate();

      expect(mockAutoUpdater.downloadUpdate).not.toHaveBeenCalled();
    });

    it("should handle download errors gracefully", async () => {
      initAutoUpdater();
      mockAutoUpdater.downloadUpdate.mockRejectedValue(new Error("Download failed"));

      const availableHandler = eventHandlers.get("update-available");
      availableHandler!({ version: "2.0.0", releaseNotes: null });

      // Should not throw
      const status = await downloadUpdate();
      expect(status).toBeDefined();
    });
  });

  describe("quitAndInstall", () => {
    it("should call autoUpdater.quitAndInstall when update is downloaded", () => {
      initAutoUpdater();

      // Set downloaded state
      const downloadedHandler = eventHandlers.get("update-downloaded");
      downloadedHandler!({ version: "2.0.0", releaseNotes: null });

      quitAndInstall();

      expect(mockAutoUpdater.quitAndInstall).toHaveBeenCalled();
    });

    it("should not install when update is not downloaded", () => {
      initAutoUpdater();

      quitAndInstall();

      expect(mockAutoUpdater.quitAndInstall).not.toHaveBeenCalled();
    });
  });

  describe("getUpdateStatus", () => {
    it("should return initial status when no events have fired", () => {
      const status = getUpdateStatus();

      expect(status).toEqual({
        checking: false,
        available: false,
        downloading: false,
        downloaded: false,
      });
    });

    it("should return a copy (not a reference) of the status", () => {
      const status1 = getUpdateStatus();
      const status2 = getUpdateStatus();

      expect(status1).toEqual(status2);
      expect(status1).not.toBe(status2);
    });
  });

  describe("cleanupAutoUpdater", () => {
    it("should stop periodic checks", () => {
      initAutoUpdater();

      // Let the initial delayed check fire first, then clean up
      vi.advanceTimersByTime(10_000);
      expect(mockAutoUpdater.checkForUpdates).toHaveBeenCalledTimes(1);

      cleanupAutoUpdater();
      mockAutoUpdater.checkForUpdates.mockClear();

      // Advance past when the next periodic check would have fired
      vi.advanceTimersByTime(5 * 60 * 60 * 1_000);

      expect(mockAutoUpdater.checkForUpdates).not.toHaveBeenCalled();
    });

    it("should reset status", () => {
      initAutoUpdater();

      const availableHandler = eventHandlers.get("update-available");
      availableHandler!({ version: "2.0.0", releaseNotes: null });

      cleanupAutoUpdater();

      const status = getUpdateStatus();
      expect(status.available).toBe(false);
      expect(status.version).toBeUndefined();
    });
  });

  describe("broadcast behaviour", () => {
    it("should not send to destroyed windows", () => {
      initAutoUpdater();
      mockBrowserWindow.isDestroyed.mockReturnValue(true);

      const handler = eventHandlers.get("update-available");
      handler!({ version: "1.0.0", releaseNotes: null });

      expect(mockWebContents.send).not.toHaveBeenCalled();

      // Reset for other tests
      mockBrowserWindow.isDestroyed.mockReturnValue(false);
    });
  });
});
