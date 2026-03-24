/**
 * SettingsPage — key management and application settings.
 *
 * Provides:
 *  - Full key management UI via KeyManagement component (4 tabs:
 *    Import File, Hardware Token, OS Cert Store, Generate Key)
 *  - Network status indicator
 *  - About card
 *
 * All key operations happen via IPC. Only metadata (ID, fingerprint,
 * algorithm, source) is displayed. Private keys NEVER reach the renderer.
 */

import { useState, useEffect, useCallback } from "react";
import { Card } from "./ui/Card";
import { Button } from "./ui/Button";
import { KeyManagement } from "./KeyManagement";

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SettingsPage() {
  const [isOffline, setIsOffline] = useState(false);
  const [apiUrl, setApiUrl] = useState("https://api.opencred.dev");
  const [apiUrlSaved, setApiUrlSaved] = useState(false);
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<"idle" | "success" | "error">("idle");
  const [connectionError, setConnectionError] = useState<string | null>(null);

  const checkOffline = useCallback(async () => {
    try {
      const offline = await window.opencred.getOfflineStatus();
      setIsOffline(offline);
    } catch {
      setIsOffline(true);
    }
  }, []);

  const loadApiUrl = useCallback(async () => {
    try {
      const url = await window.opencred.getConfig("opencredApiUrl");
      if (typeof url === "string" && url.length > 0) {
        setApiUrl(url);
      }
    } catch {
      // Use default
    }
  }, []);

  useEffect(() => {
    void checkOffline();
    void loadApiUrl();
  }, [checkOffline, loadApiUrl]);

  async function handleSaveApiUrl() {
    try {
      await window.opencred.setConfig("opencredApiUrl", apiUrl.trim());
      setApiUrlSaved(true);
      setTimeout(() => setApiUrlSaved(false), 2000);
    } catch {
      // Ignore save errors
    }
  }

  async function handleTestConnection() {
    setTestingConnection(true);
    setConnectionStatus("idle");
    setConnectionError(null);

    try {
      const response = await fetch(`${apiUrl.trim()}/health`);
      if (response.ok) {
        setConnectionStatus("success");
      } else {
        setConnectionStatus("error");
        setConnectionError(`Server returned ${response.status}`);
      }
    } catch (err) {
      setConnectionStatus("error");
      setConnectionError(err instanceof Error ? err.message : "Connection failed");
    } finally {
      setTestingConnection(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Key management — all 4 sources */}
      <KeyManagement />

      {/* OpenCred Attestation API */}
      <Card className="space-y-3">
        <h2 className="text-sm font-medium text-gray-700">OpenCred Attestation API</h2>
        <p className="text-xs text-gray-500">
          Configure the OpenCred API server URL for key attestation and domain verification.
        </p>
        <div className="space-y-2">
          <label htmlFor="api-url" className="block text-xs font-medium text-gray-600">
            API URL
          </label>
          <div className="flex gap-2">
            <input
              id="api-url"
              type="text"
              value={apiUrl}
              onChange={(e) => {
                setApiUrl(e.target.value);
                setConnectionStatus("idle");
                setApiUrlSaved(false);
              }}
              placeholder="https://api.opencred.dev"
              className="flex-1 rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
            <Button
              variant="secondary"
              onClick={() => void handleSaveApiUrl()}
            >
              {apiUrlSaved ? "Saved" : "Save"}
            </Button>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="secondary"
            onClick={() => void handleTestConnection()}
            disabled={testingConnection}
          >
            {testingConnection ? "Testing..." : "Test Connection"}
          </Button>
          {connectionStatus === "success" && (
            <span className="text-sm text-green-700">Connected</span>
          )}
          {connectionStatus === "error" && (
            <span className="text-sm text-red-700">{connectionError}</span>
          )}
        </div>
      </Card>

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

      {/* App info */}
      <Card className="space-y-1">
        <h2 className="text-sm font-medium text-gray-700">About</h2>
        <p className="text-xs text-gray-500">OpenCred Desktop v0.1.0</p>
        <p className="text-xs text-gray-400">
          All signing happens locally. Private keys never leave this machine.
        </p>
      </Card>
    </div>
  );
}
