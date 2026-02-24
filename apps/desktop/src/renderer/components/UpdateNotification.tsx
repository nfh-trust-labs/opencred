/**
 * UpdateNotification — banner/toast that appears when a new version is available.
 *
 * Displays:
 *  - "Update available" with version and a Download button
 *  - Download progress bar while downloading
 *  - "Install & Restart" button once the download completes
 *  - "Remind Me Later" dismissal option
 *  - Error state if something goes wrong
 *
 * Subscribes to the `update:status` IPC event from the main process and
 * also polls the current status on mount.
 */

import React, { useEffect, useState, useCallback } from "react";
import type { UpdateStatusResponse } from "../../shared/ipc-types";

export function UpdateNotification(): React.ReactElement | null {
  const [status, setStatus] = useState<UpdateStatusResponse | null>(null);
  const [dismissed, setDismissed] = useState(false);

  // Subscribe to status updates from the main process.
  useEffect(() => {
    // Get initial status.
    void window.opencred.updateGetStatus().then(setStatus);

    // Listen for live updates.
    const unsubscribe = window.opencred.onUpdateStatus((newStatus) => {
      setStatus(newStatus);
      // If an update becomes available after dismissal, show the banner again.
      if (newStatus.available && !newStatus.downloading && !newStatus.downloaded) {
        setDismissed(false);
      }
    });

    return unsubscribe;
  }, []);

  const handleDownload = useCallback(() => {
    void window.opencred.updateDownload();
  }, []);

  const handleInstall = useCallback(() => {
    void window.opencred.updateInstall();
  }, []);

  const handleDismiss = useCallback(() => {
    setDismissed(true);
  }, []);

  const handleCheckNow = useCallback(() => {
    void window.opencred.updateCheck();
  }, []);

  // Nothing to show.
  if (!status) return null;
  if (dismissed && !status.downloading && !status.downloaded) return null;
  if (!status.available && !status.downloading && !status.downloaded && !status.error) {
    return null;
  }

  return (
    <div className="fixed bottom-4 right-4 z-50 w-96 rounded-lg bg-white shadow-lg border border-gray-200 p-4">
      {/* Error state */}
      {status.error && (
        <div className="space-y-2">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-full bg-red-500" />
              <span className="font-medium text-sm text-red-700">Update Error</span>
            </div>
            <button
              onClick={handleDismiss}
              className="text-gray-400 hover:text-gray-600 text-sm"
              aria-label="Dismiss"
            >
              X
            </button>
          </div>
          <p className="text-sm text-red-600">{status.error}</p>
          <button
            onClick={handleCheckNow}
            className="text-sm text-blue-600 hover:text-blue-800 underline"
          >
            Retry
          </button>
        </div>
      )}

      {/* Update downloaded — ready to install */}
      {!status.error && status.downloaded && (
        <div className="space-y-3">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-full bg-green-500" />
              <span className="font-medium text-sm text-gray-900">Update Ready</span>
            </div>
            <button
              onClick={handleDismiss}
              className="text-gray-400 hover:text-gray-600 text-sm"
              aria-label="Dismiss"
            >
              X
            </button>
          </div>
          <p className="text-sm text-gray-600">
            Version {status.version} has been downloaded and is ready to install.
          </p>
          <div className="flex gap-2">
            <button
              onClick={handleInstall}
              className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700"
            >
              Install & Restart
            </button>
            <button
              onClick={handleDismiss}
              className="rounded border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Remind Me Later
            </button>
          </div>
        </div>
      )}

      {/* Downloading */}
      {!status.error && !status.downloaded && status.downloading && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <span className="inline-block h-2 w-2 rounded-full bg-blue-500 animate-pulse" />
            <span className="font-medium text-sm text-gray-900">Downloading Update...</span>
          </div>
          {status.progress && (
            <div className="space-y-1">
              <div className="h-2 w-full rounded-full bg-gray-200">
                <div
                  className="h-2 rounded-full bg-blue-600 transition-all duration-300"
                  style={{ width: `${Math.min(status.progress.percent, 100)}%` }}
                />
              </div>
              <div className="flex justify-between text-xs text-gray-500">
                <span>{Math.round(status.progress.percent)}%</span>
                <span>
                  {formatBytes(status.progress.transferred)} / {formatBytes(status.progress.total)}
                </span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Update available — not yet downloading */}
      {!status.error && !status.downloaded && !status.downloading && status.available && (
        <div className="space-y-3">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-full bg-yellow-500" />
              <span className="font-medium text-sm text-gray-900">Update Available</span>
            </div>
            <button
              onClick={handleDismiss}
              className="text-gray-400 hover:text-gray-600 text-sm"
              aria-label="Dismiss"
            >
              X
            </button>
          </div>
          <p className="text-sm text-gray-600">A new version ({status.version}) is available.</p>
          {status.releaseNotes && (
            <p className="text-xs text-gray-500 max-h-20 overflow-y-auto whitespace-pre-wrap">
              {status.releaseNotes}
            </p>
          )}
          <div className="flex gap-2">
            <button
              onClick={handleDownload}
              className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700"
            >
              Download
            </button>
            <button
              onClick={handleDismiss}
              className="rounded border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Remind Me Later
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Format bytes into a human-readable string (e.g. "12.5 MB").
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const value = bytes / Math.pow(1024, i);
  return `${value.toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}
