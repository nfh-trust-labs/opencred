/**
 * SettingsPage — key management and application settings.
 *
 * Provides:
 *  - Table of all imported/generated keys
 *  - Import Key button (file picker)
 *  - Generate Key button (ECDSA P-256)
 *  - Offline status indicator
 *
 * All key operations happen via IPC. Only metadata (ID, fingerprint,
 * algorithm, source) is displayed. Private keys NEVER reach the renderer.
 */

import { useState, useEffect, useCallback } from "react";
import type { KeyMetadata } from "../../shared/ipc-types";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Badge } from "./ui/Badge";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SOURCE_LABELS: Record<NonNullable<KeyMetadata["source"]>, string> = {
  file: "File",
  pkcs11: "PKCS#11",
  "os-cert": "OS Cert",
  generated: "Generated",
};

function getSourceLabel(key: KeyMetadata): string {
  return key.source ? (SOURCE_LABELS[key.source] ?? key.source) : "File";
}

function sourceBadgeVariant(
  source: KeyMetadata["source"],
): "info" | "neutral" | "warning" | "success" {
  switch (source) {
    case "generated":
      return "info";
    case "pkcs11":
      return "warning";
    case "os-cert":
      return "success";
    default:
      return "neutral";
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SettingsPage() {
  const [keys, setKeys] = useState<KeyMetadata[]>([]);
  const [keysError, setKeysError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [generateLabel, setGenerateLabel] = useState("");
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);
  const [isOffline, setIsOffline] = useState(false);

  // ------------------------------------------------------------------
  // Data loading
  // ------------------------------------------------------------------

  const loadKeys = useCallback(async () => {
    try {
      const response = await window.opencred.listKeys();
      setKeys(response.keys);
      setKeysError(null);
    } catch (err) {
      setKeysError(err instanceof Error ? err.message : "Failed to load keys.");
    }
  }, []);

  const checkOffline = useCallback(async () => {
    try {
      const offline = await window.opencred.getOfflineStatus();
      setIsOffline(offline);
    } catch {
      setIsOffline(true);
    }
  }, []);

  useEffect(() => {
    void loadKeys();
    void checkOffline();
  }, [loadKeys, checkOffline]);

  // ------------------------------------------------------------------
  // Handlers
  // ------------------------------------------------------------------

  async function handleImportKey() {
    setImporting(true);
    setActionFeedback(null);
    setKeysError(null);

    try {
      const fileResult = await window.opencred.openFile({
        title: "Select Key File",
        filters: [
          { name: "Key Files", extensions: ["pem", "json", "jwk", "der", "pfx", "p12"] },
          { name: "All Files", extensions: ["*"] },
        ],
      });

      if (!fileResult.filePath) {
        setImporting(false);
        return; // User cancelled
      }

      const importResult = await window.opencred.importKey({
        filePath: fileResult.filePath,
      });

      if (importResult.success && importResult.key) {
        setActionFeedback(
          `Key imported: ${importResult.key.algorithm} (${importResult.key.fingerprint.slice(0, 16)}...)`,
        );
        void loadKeys();
      } else {
        setKeysError(importResult.error ?? "Import failed.");
      }
    } catch (err) {
      setKeysError(err instanceof Error ? err.message : "Import failed.");
    } finally {
      setImporting(false);
    }
  }

  async function handleGenerateKey() {
    setGenerating(true);
    setActionFeedback(null);
    setKeysError(null);

    try {
      const result = await window.opencred.generateKey({
        label: generateLabel.trim() || undefined,
      });

      if (result.success && result.key) {
        setActionFeedback(
          `Key generated: ${result.key.algorithm} (${result.key.fingerprint.slice(0, 16)}...)`,
        );
        setGenerateLabel("");
        void loadKeys();
      } else {
        setKeysError(result.error ?? "Key generation failed.");
      }
    } catch (err) {
      setKeysError(err instanceof Error ? err.message : "Key generation failed.");
    } finally {
      setGenerating(false);
    }
  }

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------

  return (
    <div className="space-y-6">
      {/* Key management */}
      <Card className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-medium text-gray-700">Key Management</h2>
          <span className="text-xs text-gray-400">
            {keys.length} key{keys.length !== 1 ? "s" : ""} registered
          </span>
        </div>

        {/* Action buttons */}
        <div className="flex items-end gap-3 flex-wrap">
          <Button
            onClick={() => void handleImportKey()}
            disabled={importing}
            variant="secondary"
          >
            {importing ? "Importing..." : "Import Key"}
          </Button>

          <div className="flex items-end gap-2">
            <div>
              <label className="block text-xs text-gray-500 mb-1">
                Label (optional)
              </label>
              <input
                type="text"
                value={generateLabel}
                onChange={(e) => setGenerateLabel(e.target.value)}
                placeholder="e.g. Test Issuer Key"
                className="rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none"
                onKeyDown={(e) => {
                  if (e.key === "Enter") void handleGenerateKey();
                }}
              />
            </div>
            <Button
              onClick={() => void handleGenerateKey()}
              disabled={generating}
              variant="secondary"
            >
              {generating ? "Generating..." : "Generate Key"}
            </Button>
          </div>
        </div>

        {/* Feedback */}
        {actionFeedback && (
          <p className="text-sm text-green-700">{actionFeedback}</p>
        )}
        {keysError && <p className="text-sm text-red-600">{keysError}</p>}

        {/* Key table */}
        {keys.length === 0 ? (
          <p className="text-sm text-gray-400 italic">
            No keys registered yet. Import a file or generate a key to get started.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left text-xs text-gray-500">
                  <th className="pb-2 pr-3">DID</th>
                  <th className="pb-2 pr-3">Algorithm</th>
                  <th className="pb-2 pr-3">Source</th>
                  <th className="pb-2 pr-3">Label</th>
                  <th className="pb-2">Imported</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((key) => (
                  <tr key={key.id} className="border-b border-gray-100">
                    <td className="py-2 pr-3">
                      <span
                        className="font-mono text-xs text-gray-600 block max-w-[200px] truncate"
                        title={key.id}
                      >
                        {key.id}
                      </span>
                    </td>
                    <td className="py-2 pr-3 text-gray-700">{key.algorithm}</td>
                    <td className="py-2 pr-3">
                      <Badge variant={sourceBadgeVariant(key.source)}>
                        {getSourceLabel(key)}
                      </Badge>
                    </td>
                    <td className="py-2 pr-3 text-xs text-gray-500">
                      {key.label ?? "-"}
                    </td>
                    <td className="py-2 text-xs text-gray-500">
                      {new Date(key.importedAt).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
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
