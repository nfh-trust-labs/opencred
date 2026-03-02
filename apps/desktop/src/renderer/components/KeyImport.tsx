/**
 * KeyImport — file-based key import for the desktop app.
 *
 * This uses the native file dialog via IPC to import key files.
 * Supports PEM, JWK, and PKCS#8 DER formats. Format is auto-detected.
 * Keys are imported into the main process — the private key material
 * NEVER reaches the renderer. Only key metadata is displayed.
 */

import { useState } from "react";
import type { KeyMetadata } from "../../shared/ipc-types";

/** Map format codes to user-friendly labels. */
const FORMAT_LABELS: Record<string, string> = {
  pem: "PEM",
  jwk: "JWK",
  "pkcs8-der": "PKCS#8 DER",
};

interface KeyImportProps {
  onKeyImported?: () => void;
}

export function KeyImport({ onKeyImported }: KeyImportProps) {
  const [error, setError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [lastImported, setLastImported] = useState<KeyMetadata | null>(null);

  async function handleImport() {
    setError(null);
    setLastImported(null);
    setImporting(true);
    try {
      // Use the native file dialog to select a key file.
      const fileResult = await window.opencred.openFile({
        title: "Select Key File",
        filters: [
          { name: "Key Files", extensions: ["pem", "json", "jwk", "der"] },
          { name: "All Files", extensions: ["*"] },
        ],
      });

      if (!fileResult.filePath) {
        setImporting(false);
        return; // User cancelled.
      }

      const importResult = await window.opencred.importKey({ filePath: fileResult.filePath });

      if (importResult.success && importResult.key) {
        setLastImported(importResult.key);
        onKeyImported?.();
      } else {
        setError(importResult.error ?? "Import failed.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Import failed.");
    } finally {
      setImporting(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-500">
          Supports PEM, JWK, and PKCS#8 DER formats. Only ECDSA P-256 keys are accepted. Private
          keys are stored locally and never leave this machine.
        </p>
        <button
          onClick={() => void handleImport()}
          disabled={importing}
          className="flex-shrink-0 ml-4 rounded-md bg-gray-700 px-3 py-1.5 text-sm text-white hover:bg-gray-800 disabled:opacity-40"
        >
          {importing ? "Importing..." : "Import Key"}
        </button>
      </div>

      {error && <p className="text-sm text-red-600">{error}</p>}

      {lastImported && (
        <div className="rounded-md border border-green-200 bg-green-50 p-3 text-xs">
          <p className="font-medium text-green-800">Key imported successfully</p>
          <div className="mt-1 text-green-700 space-y-0.5">
            <p>Algorithm: {lastImported.algorithm}</p>
            {lastImported.format && (
              <p>Format: {FORMAT_LABELS[lastImported.format] ?? lastImported.format}</p>
            )}
            <p>Fingerprint: {lastImported.fingerprint.slice(0, 32)}...</p>
            <p className="font-mono text-[10px] text-green-600 break-all">ID: {lastImported.id}</p>
          </div>
        </div>
      )}
    </div>
  );
}
