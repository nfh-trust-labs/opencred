/**
 * SettingsPage — key management and application settings.
 *
 * Provides:
 *  - Full key management UI via KeyManagement component (4 tabs:
 *    Import File, Hardware Token, OS Cert Store, Generate Key)
 *  - Software update card with check/download/install flow
 *  - Network status indicator
 *  - Help & Support card with bug reporting
 *  - About card
 *
 * All key operations happen via IPC. Only metadata (ID, fingerprint,
 * algorithm, source) is displayed. Private keys NEVER reach the renderer.
 */

import { useState, useEffect, useCallback } from "react";
import { Card } from "./ui/Card";
import { Button } from "./ui/Button";
import { KeyManagement } from "./KeyManagement";
import { BugReportDialog } from "./BugReportDialog";
import type { UpdateStatusResponse } from "../../shared/ipc-types";

// ---------------------------------------------------------------------------
// UpdateCard — in-app update UI
// ---------------------------------------------------------------------------

function UpdateCard() {
  const [status, setStatus] = useState<UpdateStatusResponse>({
    checking: false,
    available: false,
    downloading: false,
    downloaded: false,
  });
  const [isDev, setIsDev] = useState(false);

  useEffect(() => {
    // Get initial status
    window.opencred.updateGetStatus().then(setStatus).catch(() => {
      setIsDev(true);
    });

    // Subscribe to live updates
    const unsub = window.opencred.onUpdateStatus(setStatus);
    return unsub;
  }, []);

  function handleCheck() {
    void window.opencred.updateCheck();
  }

  function handleDownload() {
    void window.opencred.updateDownload();
  }

  function handleInstall() {
    void window.opencred.updateInstall();
  }

  // Dev mode or offline — graceful fallback
  if (isDev) {
    return (
      <Card className="space-y-2">
        <h2 className="text-sm font-medium text-gray-700">Software Updates</h2>
        <p className="text-xs text-gray-500">
          Auto-update is not available in development mode.
        </p>
      </Card>
    );
  }

  // Format download speed
  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  return (
    <Card className="space-y-3">
      <h2 className="text-sm font-medium text-gray-700">Software Updates</h2>

      {/* Error state */}
      {status.error && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-red-600">{status.error}</p>
          <button
            onClick={handleCheck}
            className="text-xs font-medium text-brand-blue hover:underline"
          >
            Retry
          </button>
        </div>
      )}

      {/* Downloaded — ready to install */}
      {status.downloaded && (
        <div className="space-y-2">
          <p className="text-xs text-green-700">
            Version {status.version} downloaded. Restart to apply.
          </p>
          {status.releaseNotes && (
            <p className="text-xs text-gray-500 line-clamp-3">{status.releaseNotes}</p>
          )}
          <button
            onClick={handleInstall}
            className="px-3 py-1.5 text-xs font-medium text-white bg-green-600 rounded hover:bg-green-700 transition-colors"
          >
            Restart Now
          </button>
        </div>
      )}

      {/* Downloading — progress bar */}
      {status.downloading && !status.downloaded && (
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-gray-600">
            <span>Downloading {status.version}...</span>
            {status.progress && (
              <span>
                {formatBytes(status.progress.transferred)} / {formatBytes(status.progress.total)}
                {" "}({formatBytes(status.progress.bytesPerSecond)}/s)
              </span>
            )}
          </div>
          <div className="w-full h-1.5 bg-gray-200 rounded-full overflow-hidden">
            <div
              className="h-full bg-brand-blue rounded-full transition-all duration-300"
              style={{ width: `${status.progress?.percent ?? 0}%` }}
            />
          </div>
        </div>
      )}

      {/* Available — offer download */}
      {status.available && !status.downloading && !status.downloaded && !status.error && (
        <div className="space-y-2">
          <p className="text-xs text-gray-700">
            Version {status.version} is available.
          </p>
          {status.releaseNotes && (
            <p className="text-xs text-gray-500 line-clamp-3">{status.releaseNotes}</p>
          )}
          <button
            onClick={handleDownload}
            className="px-3 py-1.5 text-xs font-medium text-white bg-brand-blue rounded hover:bg-brand-blue/90 transition-colors"
          >
            Download Update
          </button>
        </div>
      )}

      {/* Checking */}
      {status.checking && (
        <div className="flex items-center gap-2">
          <div className="h-3 w-3 border-2 border-brand-blue border-t-transparent rounded-full animate-spin" />
          <span className="text-xs text-gray-500">Checking for updates...</span>
        </div>
      )}

      {/* Up to date */}
      {!status.checking && !status.available && !status.downloading && !status.downloaded && !status.error && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-gray-500">Running latest version.</p>
          <button
            onClick={handleCheck}
            className="text-xs font-medium text-brand-blue hover:underline"
          >
            Check for Updates
          </button>
        </div>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/** Number of days before a key is considered overdue for rotation. */
const ROTATION_THRESHOLD_DAYS = 90;
/** Number of days the rotation reminder is snoozed after dismissal. */
const ROTATION_SNOOZE_DAYS = 30;

export function SettingsPage() {
  const [isOffline, setIsOffline] = useState(false);
  const [bugReportOpen, setBugReportOpen] = useState(false);
  const [rotationInfo, setRotationInfo] = useState<{ overdue: boolean; ageDays: number }>({ overdue: false, ageDays: 0 });

  const checkOffline = useCallback(async () => {
    try {
      const offline = await window.opencred.getOfflineStatus();
      setIsOffline(offline);
    } catch {
      setIsOffline(true);
    }
  }, []);

  const checkRotation = useCallback(async () => {
    try {
      const response = await window.opencred.listKeys();
      if (response.keys.length === 0) return;

      const dismissedUntil = await window.opencred.getConfig("keyRotationDismissedUntil") as string | undefined;
      if (dismissedUntil && new Date(dismissedUntil) > new Date()) return;

      const now = Date.now();
      const thresholdMs = ROTATION_THRESHOLD_DAYS * 24 * 60 * 60 * 1000;
      let oldestAge = 0;
      for (const key of response.keys) {
        const age = now - new Date(key.importedAt).getTime();
        if (age > oldestAge) oldestAge = age;
      }
      if (oldestAge > thresholdMs) {
        setRotationInfo({ overdue: true, ageDays: Math.floor(oldestAge / (24 * 60 * 60 * 1000)) });
      }
    } catch {
      // Non-fatal
    }
  }, []);

  async function handleDismissRotation() {
    const snoozeUntil = new Date();
    snoozeUntil.setDate(snoozeUntil.getDate() + ROTATION_SNOOZE_DAYS);
    await window.opencred.setConfig("keyRotationDismissedUntil", snoozeUntil.toISOString());
    setRotationInfo({ overdue: false, ageDays: 0 });
  }

  useEffect(() => {
    void checkOffline();
    void checkRotation();
  }, [checkOffline, checkRotation]);

  return (
    <div className="space-y-6">
      {/* Key rotation warning */}
      {rotationInfo.overdue && (
        <div
          className="flex items-center justify-between rounded-lg border border-amber-300 bg-amber-50 px-4 py-3"
        >
          <div className="flex items-center gap-3">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-amber-200">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#92400e" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
              </svg>
            </span>
            <p className="text-sm text-amber-800">
              Your signing key is <strong>{rotationInfo.ageDays} days</strong> old. Consider rotating for security best practices.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void handleDismissRotation()}
              className="text-xs font-medium text-amber-700 hover:text-amber-900 px-2 py-1"
            >
              Dismiss
            </button>
            <Button
              onClick={() => {
                const el = document.getElementById("key-management-section");
                if (el) el.scrollIntoView({ behavior: "smooth" });
              }}
            >
              Rotate Key
            </Button>
          </div>
        </div>
      )}

      {/* Key management — all 4 sources */}
      <div id="key-management-section">
        <KeyManagement />
      </div>

      {/* Software updates */}
      <UpdateCard />

      {/* Offline status */}
      <Card className="space-y-2">
        <h2 className="text-sm font-medium text-gray-700">Network Status</h2>
        <div className="flex items-center gap-2">
          <span
            className={`h-2.5 w-2.5 rounded-full ${
              isOffline ? "bg-amber-500" : "bg-green-500"
            }`}
          />
          <span
            className={`text-sm ${isOffline ? "text-amber-700" : "text-green-700"}`}
          >
            {isOffline ? "Offline" : "Online"}
          </span>
        </div>
        <p className="text-xs text-gray-500">
          {isOffline
            ? "You are offline. Credential issuance and signature verification still work. Revocation checks require a network connection."
            : "Connected. All features are available."}
        </p>
      </Card>

      {/* Help & Support */}
      <Card className="space-y-2">
        <h2 className="text-sm font-medium text-gray-700">Help & Support</h2>
        <p className="text-xs text-gray-500">
          Encountered an issue? Generate a bug report with system info and recent logs.
        </p>
        <button
          onClick={() => setBugReportOpen(true)}
          className="px-3 py-1.5 text-xs font-medium text-txt-primary bg-surface-card border border-border-default rounded hover:bg-gray-100 transition-colors"
        >
          Report Bug
        </button>
      </Card>

      {/* App info */}
      <Card className="space-y-1">
        <h2 className="text-sm font-medium text-gray-700">About</h2>
        <p className="text-xs text-gray-500">OpenCred Desktop v0.1.0</p>
        <p className="text-xs text-gray-400">
          All signing happens locally. Private keys never leave this machine.
        </p>
      </Card>

      {/* Bug report dialog */}
      <BugReportDialog open={bugReportOpen} onClose={() => setBugReportOpen(false)} />
    </div>
  );
}
