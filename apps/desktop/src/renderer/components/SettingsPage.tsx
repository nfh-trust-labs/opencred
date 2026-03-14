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
import { KeyManagement } from "./KeyManagement";

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SettingsPage() {
  const [isOffline, setIsOffline] = useState(false);

  const checkOffline = useCallback(async () => {
    try {
      const offline = await window.opencred.getOfflineStatus();
      setIsOffline(offline);
    } catch {
      setIsOffline(true);
    }
  }, []);

  useEffect(() => {
    void checkOffline();
  }, [checkOffline]);

  return (
    <div className="space-y-6">
      {/* Key management — all 4 sources */}
      <KeyManagement />

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
