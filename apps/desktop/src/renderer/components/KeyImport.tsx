/**
 * KeyImport — file-based key import for the desktop app.
 *
 * This uses the native file dialog via IPC to import key files.
 * Supports PEM, JWK, PKCS#8 DER, and PFX/P12 formats. Format is auto-detected.
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
  pfx: "PFX/P12",
};

interface KeyImportProps {
  onKeyImported?: () => void;
}

export function KeyImport({ onKeyImported }: KeyImportProps) {
  const [error, setError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [lastImported, setLastImported] = useState<KeyMetadata | null>(null);
  const [pendingFilePath, setPendingFilePath] = useState<string | null>(null);
  const [pfxPassword, setPfxPassword] = useState("");
  const [showPfxPrompt, setShowPfxPrompt] = useState(false);

  function isPfxFile(filePath: string): boolean {
    const lower = filePath.toLowerCase();
    return lower.endsWith(".pfx") || lower.endsWith(".p12");
  }

  async function doImport(filePath: string, passphrase?: string) {
    setImporting(true);
    try {
      const importResult = await window.opencred.importKey({
        filePath,
        password: passphrase,
      });

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
      setPendingFilePath(null);
      setPfxPassword("");
      setShowPfxPrompt(false);
    }
  }

  async function handleImport() {
    setError(null);
    setLastImported(null);
    try {
      const fileResult = await window.opencred.openFile({
        title: "Select Key File",
        filters: [
          { name: "Key Files", extensions: ["pem", "json", "jwk", "der", "pfx", "p12"] },
          { name: "All Files", extensions: ["*"] },
        ],
      });

      if (!fileResult.filePath) {
        return;
      }

      if (isPfxFile(fileResult.filePath)) {
        setPendingFilePath(fileResult.filePath);
        setShowPfxPrompt(true);
        return;
      }

      await doImport(fileResult.filePath);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Import failed.");
    }
  }

  function handlePfxSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (pendingFilePath) {
      void doImport(pendingFilePath, pfxPassword);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-500">
          Import a signing key from a file. Supports PEM, JWK, PKCS#8 DER, and PFX/P12 formats —
          we'll auto-detect the type. If your IT department gave you a key file, use this option.
        </p>
        <button
          onClick={() => void handleImport()}
          disabled={importing || showPfxPrompt}
          className="flex-shrink-0 ml-4 rounded-md bg-gray-700 px-3 py-1.5 text-sm text-white hover:bg-gray-800 disabled:opacity-40"
        >
          {importing ? "Importing..." : "Import Key"}
        </button>
      </div>

      {showPfxPrompt && (
        <form
          onSubmit={handlePfxSubmit}
          className="rounded-md border border-blue-200 bg-blue-50 p-3 space-y-2"
        >
          <p className="text-xs font-medium text-blue-800">
            PFX/P12 file selected — enter password:
          </p>
          <div className="flex items-center gap-2">
            <input
              type="password"
              value={pfxPassword}
              onChange={(e) => setPfxPassword(e.target.value)}
              placeholder="Certificate password"
              autoFocus
              className="flex-1 rounded-md border border-blue-300 px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
            <button
              type="submit"
              disabled={importing}
              className="rounded-md bg-blue-600 px-3 py-1 text-sm text-white hover:bg-blue-700 disabled:opacity-40"
            >
              {importing ? "Importing..." : "Import"}
            </button>
            <button
              type="button"
              onClick={() => {
                setShowPfxPrompt(false);
                setPendingFilePath(null);
                setPfxPassword("");
              }}
              className="rounded-md bg-gray-200 px-3 py-1 text-sm text-gray-700 hover:bg-gray-300"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

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
