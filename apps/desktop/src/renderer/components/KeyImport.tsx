/**
 * KeyImport — key management for the desktop app.
 *
 * This mirrors the web app's KeyImport component but uses the native file
 * dialog via IPC instead of the browser File API. Keys are imported into
 * the main process — the private key material NEVER reaches the renderer.
 * Only key metadata (id, fingerprint, algorithm) is displayed.
 */

import { useState, useEffect } from "react";
import type { KeyMetadata } from "../../shared/ipc-types";

export function KeyImport() {
  const [keys, setKeys] = useState<KeyMetadata[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);

  async function loadKeys() {
    try {
      const response = await window.opencred.listKeys();
      setKeys(response.keys);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load keys.");
    }
  }

  useEffect(() => {
    void loadKeys();
  }, []);

  async function handleImport() {
    setError(null);
    setImporting(true);
    try {
      // Use the native file dialog to select a key file.
      const fileResult = await window.opencred.openFile({
        title: "Select Key File",
        filters: [
          { name: "JWK Files", extensions: ["json", "jwk"] },
          { name: "All Files", extensions: ["*"] },
        ],
      });

      if (!fileResult.filePath) {
        setImporting(false);
        return; // User cancelled.
      }

      const importResult = await window.opencred.importKey({ filePath: fileResult.filePath });

      if (importResult.success) {
        await loadKeys();
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
    <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-gray-700">Key Management</h2>
        <button
          onClick={() => void handleImport()}
          disabled={importing}
          className="rounded-md bg-gray-700 px-3 py-1.5 text-sm text-white hover:bg-gray-800 disabled:opacity-40"
        >
          {importing ? "Importing..." : "Import Key"}
        </button>
      </div>

      <p className="text-xs text-gray-500">
        Private keys are stored locally and never leave this machine. Only key metadata is shown
        below.
      </p>

      {error && <p className="text-sm text-red-600">{error}</p>}

      {keys.length === 0 ? (
        <p className="text-sm text-gray-400 italic">No keys imported yet.</p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 text-left text-xs text-gray-500">
              <th className="pb-2">Algorithm</th>
              <th className="pb-2">Fingerprint</th>
              <th className="pb-2">Imported</th>
            </tr>
          </thead>
          <tbody>
            {keys.map((key) => (
              <tr key={key.id} className="border-b border-gray-100">
                <td className="py-2 text-gray-700">{key.algorithm}</td>
                <td className="py-2 font-mono text-xs text-gray-500">
                  {key.fingerprint.slice(0, 16)}...
                </td>
                <td className="py-2 text-gray-500">{new Date(key.importedAt).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
