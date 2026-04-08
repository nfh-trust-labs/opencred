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
import type { UpdateStatusResponse, DeDiStatusResponse } from "../../shared/ipc-types";

const DEDI_BASE_URL = "https://api.dedi.global";

// ---------------------------------------------------------------------------
// DeDiCard — configure / manage DeDi integration from Settings
// ---------------------------------------------------------------------------

type DeDiCardState = "idle" | "form" | "saving" | "publishing";

function StatusRow({
  label,
  active,
  description,
  action,
  onAction,
  disabled,
}: {
  label: string;
  active: boolean;
  description: string;
  action?: string;
  onAction?: () => void;
  disabled?: boolean;
}) {
  return (
    <div className="flex items-center justify-between px-3 py-2">
      <div className="flex items-center gap-2">
        <span
          className={`h-2 w-2 rounded-full flex-shrink-0 ${active ? "bg-green-500" : "bg-gray-300"}`}
        />
        <span className="text-xs font-medium text-gray-700">{label}</span>
        <span className="text-xs text-gray-400">{description}</span>
      </div>
      {action && onAction && (
        <button
          onClick={onAction}
          disabled={disabled}
          className="text-xs font-medium text-brand-blue hover:underline disabled:opacity-50"
        >
          {disabled ? "..." : action}
        </button>
      )}
      {!action && (
        <span className={`text-xs font-medium ${active ? "text-green-600" : "text-gray-400"}`}>
          {active ? "Live" : "Inactive"}
        </span>
      )}
    </div>
  );
}

function DeDiCard() {
  const [status, setStatus] = useState<DeDiStatusResponse | null>(null);
  const [state, setState] = useState<DeDiCardState>("idle");
  const [namespace, setNamespace] = useState("");
  // Transient form state only — sent to main process via IPC for encrypted
  // storage (safeStorage) and cleared immediately after submission.
  // Same pattern as DeDiSetup.tsx.
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [actionResult, setActionResult] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const s = await window.opencred.dediGetStatus();
      setStatus(s);
      if (s.configured && s.namespace) setNamespace(s.namespace);
    } catch {
      setStatus({ configured: false, registriesReady: false, publishedSchemas: [] });
    }
  }, []);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  async function handleSave() {
    if (!namespace.trim()) {
      setError("Please enter a namespace.");
      return;
    }
    if (!apiKey) {
      setError("Please enter your API key.");
      return;
    }

    setError(null);
    setActionResult(null);
    setState("saving");

    try {
      const result = await window.opencred.dediSetConfig({
        baseUrl: DEDI_BASE_URL,
        namespace: namespace.trim(),
        credentials: { type: "api-key", apiKey },
      });

      if (!result.success) {
        setError(result.error ?? "Failed to configure DeDi.");
        setState("form");
        return;
      }

      setApiKey("");
      setState("idle");
      await loadStatus();
      setActionResult({ type: "success", message: "DeDi configured successfully." });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to configure DeDi.");
      setState("form");
    }
  }

  async function handleDisconnect() {
    setError(null);
    setActionResult(null);
    try {
      await window.opencred.dediDisconnect();
      setNamespace("");
      setApiKey("");
      setState("idle");
      await loadStatus();
      setActionResult({ type: "success", message: "Disconnected from DeDi." });
    } catch (err) {
      setActionResult({
        type: "error",
        message: err instanceof Error ? err.message : "Failed to disconnect.",
      });
    }
  }

  async function handlePublishDID() {
    setError(null);
    setActionResult(null);
    setState("publishing");

    try {
      const { keys } = await window.opencred.listKeys();
      if (keys.length === 0) {
        setActionResult({
          type: "error",
          message: "No signing keys available. Import or generate a key first.",
        });
        setState("idle");
        return;
      }

      if (!status?.namespace) {
        setActionResult({ type: "error", message: "No namespace configured." });
        setState("idle");
        return;
      }

      const activeKey = keys[0];
      const exportResult = await window.opencred.exportDidDocument({
        keyId: activeKey.id,
        domain: status.namespace,
      });

      if (!exportResult.success || !exportResult.didDocument || !exportResult.did) {
        setActionResult({
          type: "error",
          message: exportResult.error ?? "Failed to export DID document.",
        });
        setState("idle");
        return;
      }

      const pubResult = await window.opencred.dediPublishDID({
        did: exportResult.did,
        document: JSON.parse(exportResult.didDocument),
      });

      setActionResult(
        pubResult.success
          ? { type: "success", message: "DID published successfully." }
          : { type: "error", message: pubResult.error ?? "Failed to publish DID." },
      );
    } catch (err) {
      setActionResult({
        type: "error",
        message: err instanceof Error ? err.message : "Failed to publish DID.",
      });
    }

    setState("idle");
  }

  async function handleCreateRegistries() {
    setActionResult(null);
    try {
      const result = await window.opencred.dediEnsureRegistries();
      if (result.success) {
        setActionResult({ type: "success", message: "Registries created." });
        await loadStatus();
      } else {
        setActionResult({ type: "error", message: result.error ?? "Failed to create registries." });
      }
    } catch (err) {
      setActionResult({
        type: "error",
        message: err instanceof Error ? err.message : "Failed to create registries.",
      });
    }
  }

  if (!status) return null;

  const isConfigured = status.configured;

  return (
    <Card className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-gray-700">DeDi Integration</h2>
        {isConfigured ? (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700">
            <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
            Connected
          </span>
        ) : (
          <span className="text-xs text-gray-400">Not configured</span>
        )}
      </div>

      {/* Action result feedback */}
      {actionResult && (
        <div
          className={`rounded-md px-3 py-2 text-xs ${
            actionResult.type === "success"
              ? "bg-green-50 text-green-700 border border-green-200"
              : "bg-red-50 text-red-700 border border-red-200"
          }`}
        >
          {actionResult.message}
        </div>
      )}

      {/* Not configured — idle */}
      {!isConfigured && state === "idle" && (
        <>
          <p className="text-xs text-gray-500">
            Connect to DeDi to publish your DID, schemas, and revocation lists.
          </p>
          <Button
            onClick={() => {
              setState("form");
              setActionResult(null);
            }}
          >
            Configure
          </Button>
        </>
      )}

      {/* Configured — idle */}
      {isConfigured && state === "idle" && (
        <>
          <div className="text-xs text-gray-500 mb-1">
            Namespace: <span className="font-medium text-gray-700">{status.namespace}</span>
          </div>

          {/* Status indicators */}
          <div className="rounded-md border border-gray-200 divide-y divide-gray-100">
            <StatusRow
              label="Registries"
              active={status.registriesReady}
              description="Schema, Public Key, Revocation"
              action={status.registriesReady ? undefined : "Create"}
              onAction={
                status.registriesReady
                  ? undefined
                  : () => {
                      void handleCreateRegistries();
                    }
              }
            />
            <StatusRow
              label="Public Key"
              active={false}
              description="Publish your DID document"
              action="Publish"
              onAction={() => void handlePublishDID()}
            />
            <StatusRow
              label="Schemas"
              active={status.publishedSchemas.length > 0}
              description={
                status.publishedSchemas.length > 0
                  ? `${status.publishedSchemas.length} published`
                  : "Published on first issuance"
              }
            />
          </div>

          <div className="flex gap-2 pt-1">
            <Button
              onClick={() => {
                setState("form");
                setApiKey("");
                setActionResult(null);
              }}
              size="sm"
            >
              Reconfigure
            </Button>
            <button
              onClick={() => void handleDisconnect()}
              className="px-3 py-1.5 text-xs font-medium text-red-600 border border-red-200 rounded hover:bg-red-50 transition-colors"
            >
              Disconnect
            </button>
          </div>
        </>
      )}

      {/* Inline configure / reconfigure form */}
      {(state === "form" || state === "saving") && (
        <div className="space-y-3 pt-1">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Namespace</label>
            <input
              type="text"
              value={namespace}
              onChange={(e) => {
                setNamespace(e.target.value);
                setError(null);
              }}
              placeholder="your-domain.example"
              disabled={state === "saving"}
              className="w-full rounded border border-gray-300 px-3 py-2 text-sm text-gray-900 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue disabled:opacity-50"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">API Key</label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => {
                setApiKey(e.target.value);
                setError(null);
              }}
              placeholder="Enter your DeDi API key"
              disabled={state === "saving"}
              className="w-full rounded border border-gray-300 px-3 py-2 text-sm text-gray-900 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue disabled:opacity-50"
            />
          </div>

          {error && <p className="text-xs text-red-600">{error}</p>}

          <div className="flex gap-2">
            <Button onClick={() => void handleSave()} disabled={state === "saving"}>
              {state === "saving" ? "Saving..." : "Save"}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setState("idle");
                setError(null);
                setActionResult(null);
              }}
              disabled={state === "saving"}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}

      {/* Busy states */}
      {state === "publishing" && (
        <div className="flex items-center gap-2">
          <div className="h-3 w-3 border-2 border-brand-blue border-t-transparent rounded-full animate-spin" />
          <span className="text-xs text-gray-500">Publishing DID...</span>
        </div>
      )}
    </Card>
  );
}

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
    window.opencred
      .updateGetStatus()
      .then(setStatus)
      .catch(() => {
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
        <p className="text-xs text-gray-500">Auto-update is not available in development mode.</p>
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
                {formatBytes(status.progress.transferred)} / {formatBytes(status.progress.total)} (
                {formatBytes(status.progress.bytesPerSecond)}/s)
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
          <p className="text-xs text-gray-700">Version {status.version} is available.</p>
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
      {!status.checking &&
        !status.available &&
        !status.downloading &&
        !status.downloaded &&
        !status.error && (
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

interface SettingsPageProps {
  onRotationDismissed?: () => void;
}

export function SettingsPage({ onRotationDismissed }: SettingsPageProps) {
  const [isOffline, setIsOffline] = useState(false);
  const [bugReportOpen, setBugReportOpen] = useState(false);
  const [rotationInfo, setRotationInfo] = useState<{ overdue: boolean; ageDays: number }>({
    overdue: false,
    ageDays: 0,
  });
  const [orgName, setOrgName] = useState("");
  const [orgNameSaved, setOrgNameSaved] = useState(false);
  const [orgNameSaving, setOrgNameSaving] = useState(false);

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

      const dismissedUntil = (await window.opencred.getConfig("keyRotationDismissedUntil")) as
        | string
        | undefined;
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
    try {
      await window.opencred.setConfig("keyRotationDismissedUntil", snoozeUntil.toISOString());
      setRotationInfo({ overdue: false, ageDays: 0 });
      onRotationDismissed?.();
    } catch {
      // Non-fatal: banner stays visible if preference fails to persist
    }
  }

  useEffect(() => {
    void checkOffline();
    void checkRotation();
    void (async () => {
      try {
        const saved = (await window.opencred.getConfig("organizationName")) as string | undefined;
        if (saved) setOrgName(saved);
      } catch {
        /* non-fatal */
      }
    })();
  }, [checkOffline, checkRotation]);

  async function handleSaveOrgName() {
    const trimmed = orgName.trim();
    setOrgNameSaving(true);
    try {
      await window.opencred.setConfig("organizationName", trimmed || undefined);
      setOrgNameSaved(true);
      setTimeout(() => setOrgNameSaved(false), 2000);
    } catch {
      /* non-fatal */
    } finally {
      setOrgNameSaving(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Organization name */}
      <Card className="space-y-3">
        <h2 className="text-sm font-medium text-gray-700">Your Organization</h2>
        <p className="text-xs text-gray-500 -mt-1">This name appears on credentials you issue.</p>
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={orgName}
            onChange={(e) => {
              setOrgName(e.target.value);
              setOrgNameSaved(false);
            }}
            placeholder="e.g. Ministry of Agriculture, Govt of India"
            className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm text-gray-900 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue"
          />
          <Button onClick={() => void handleSaveOrgName()} disabled={orgNameSaving} size="sm">
            {orgNameSaving ? "Saving..." : "Save"}
          </Button>
          {orgNameSaved && (
            <span className="flex items-center gap-1 text-xs text-green-600">
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={2.5}
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              Saved
            </span>
          )}
        </div>
      </Card>

      {/* Key rotation warning */}
      {rotationInfo.overdue && (
        <div className="flex items-center justify-between rounded-lg border border-amber-300 bg-amber-50 px-4 py-3">
          <div className="flex items-center gap-3">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-amber-200">
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="#92400e"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"
                />
              </svg>
            </span>
            <p className="text-sm text-amber-800">
              Your signing key is <strong>{rotationInfo.ageDays} days</strong> old. Consider
              rotating for security best practices.
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

      {/* 1. Key management — all 4 sources (most important) */}
      <div id="key-management-section">
        <KeyManagement />
      </div>

      {/* 2. Software updates */}
      <UpdateCard />

      {/* 3. DeDi integration */}
      <DeDiCard />

      {/* 4. Network status */}
      <Card className="space-y-2">
        <h2 className="text-sm font-medium text-gray-700">Network Status</h2>
        <p className="text-xs text-gray-400 -mt-1">
          Check your connectivity for online features like revocation and DeDi sync.
        </p>
        <div className="flex items-center gap-2">
          <span
            className={`h-2.5 w-2.5 rounded-full ${isOffline ? "bg-amber-500" : "bg-green-500"}`}
          />
          <span className={`text-sm ${isOffline ? "text-amber-700" : "text-green-700"}`}>
            {isOffline ? "Offline" : "Online"}
          </span>
        </div>
        <p className="text-xs text-gray-500">
          {isOffline
            ? "You are offline. Credential issuance and signature verification still work. Revocation checks require a network connection."
            : "Connected. All features are available."}
        </p>
      </Card>

      {/* 5. Help & Support */}
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

      {/* 6. About */}
      <Card className="space-y-1">
        <h2 className="text-sm font-medium text-gray-700">About</h2>
        <p className="text-xs text-gray-400">Version and security info for this installation.</p>
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
