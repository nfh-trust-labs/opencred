/**
 * KeyManagement — tabbed container for all signing key sources.
 *
 * Provides four sub-tabs:
 *  - Import File: import PEM/JWK/PKCS#8 DER key files
 *  - Hardware Token: connect PKCS#11 devices (YubiKey, smart cards)
 *  - OS Certificate Store: use macOS Keychain / Windows CertStore
 *  - Generate Key: create a fresh ECDSA P-256 keypair in-app
 *
 * A unified key table at the bottom shows all registered keys from
 * all sources, pulling from window.opencred.listKeys().
 */

import { useState, useEffect, useCallback } from "react";
import type { KeyMetadata } from "../../shared/ipc-types";
import { KeyImport } from "./KeyImport";
import { HardwareToken } from "./HardwareToken";
import { OsCertStore } from "./OsCertStore";

type SubTab = "import" | "hardware" | "oscert" | "generate";

const SUB_TABS: { id: SubTab; label: string }[] = [
  { id: "import", label: "Import File" },
  { id: "hardware", label: "Hardware Token" },
  { id: "oscert", label: "OS Cert Store" },
  { id: "generate", label: "Generate Key" },
];

const SOURCE_LABELS: Record<string, string> = {
  file: "File",
  pkcs11: "PKCS#11",
  "os-cert": "OS Cert",
  generated: "Generated",
};

export function KeyManagement() {
  const [activeSubTab, setActiveSubTab] = useState<SubTab>("import");
  const [keys, setKeys] = useState<KeyMetadata[]>([]);
  const [keysError, setKeysError] = useState<string | null>(null);

  // Generate key state
  const [genLabel, setGenLabel] = useState("");
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);
  const [genSuccess, setGenSuccess] = useState<KeyMetadata | null>(null);

  const loadKeys = useCallback(async () => {
    try {
      const response = await window.opencred.listKeys();
      setKeys(response.keys);
      setKeysError(null);
    } catch (err) {
      setKeysError(err instanceof Error ? err.message : "Failed to load keys.");
    }
  }, []);

  useEffect(() => {
    void loadKeys();
  }, [loadKeys]);

  const handleRefreshKeys = useCallback(() => {
    void loadKeys();
  }, [loadKeys]);

  async function handleGenerateKey() {
    setGenError(null);
    setGenSuccess(null);
    setGenerating(true);
    try {
      const result = await window.opencred.generateKey({
        label: genLabel.trim() || undefined,
      });

      if (result.success && result.key) {
        setGenSuccess(result.key);
        setGenLabel("");
        void loadKeys();
      } else {
        setGenError(result.error ?? "Key generation failed.");
      }
    } catch (err) {
      setGenError(err instanceof Error ? err.message : "Key generation failed.");
    } finally {
      setGenerating(false);
    }
  }

  function getSourceLabel(key: KeyMetadata): string {
    if (key.source) {
      return SOURCE_LABELS[key.source] ?? key.source;
    }
    // Backward compatibility: infer source from format
    if (key.format === "pkcs11") return "PKCS#11";
    if (key.format?.startsWith("oscert:")) return "OS Cert";
    if (key.format === "generated") return "Generated";
    return "File";
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-4">
        <h2 className="text-sm font-medium text-gray-700">Key Management</h2>

        {/* Sub-tab navigation */}
        <div className="flex gap-1 border-b border-gray-200">
          {SUB_TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id)}
              className={`px-3 py-2 text-sm font-medium border-b-2 transition-colors ${
                activeSubTab === tab.id
                  ? "border-gray-700 text-gray-900"
                  : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Sub-tab content */}
        <div className="pt-2">
          {activeSubTab === "import" && <KeyImport onKeyImported={handleRefreshKeys} />}

          {activeSubTab === "hardware" && <HardwareToken onKeyConnected={handleRefreshKeys} />}

          {activeSubTab === "oscert" && <OsCertStore onKeyConnected={handleRefreshKeys} />}

          {activeSubTab === "generate" && (
            <div className="space-y-4">
              <p className="text-xs text-gray-500">
                Generate a fresh ECDSA P-256 keypair. The private key stays in memory and never
                leaves this application. Suitable for testing or ephemeral signing.
              </p>
              <div className="flex gap-2 items-end">
                <div className="flex-1">
                  <label className="block text-xs text-gray-600 mb-1">Label (optional)</label>
                  <input
                    type="text"
                    value={genLabel}
                    onChange={(e) => setGenLabel(e.target.value)}
                    placeholder="e.g. Test Issuer Key"
                    className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none"
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void handleGenerateKey();
                    }}
                  />
                </div>
                <button
                  onClick={() => void handleGenerateKey()}
                  disabled={generating}
                  className="rounded-md bg-gray-700 px-4 py-1.5 text-sm text-white hover:bg-gray-800 disabled:opacity-40"
                >
                  {generating ? "Generating..." : "Generate P-256 Key"}
                </button>
              </div>

              {genError && <p className="text-sm text-red-600">{genError}</p>}

              {genSuccess && (
                <div className="rounded-md border border-green-200 bg-green-50 p-3 text-xs">
                  <p className="font-medium text-green-800">Key generated successfully</p>
                  <div className="mt-1 text-green-700 space-y-0.5">
                    <p>Algorithm: {genSuccess.algorithm}</p>
                    {genSuccess.label && <p>Label: {genSuccess.label}</p>}
                    <p>Fingerprint: {genSuccess.fingerprint.slice(0, 32)}...</p>
                    <p className="font-mono text-[10px] text-green-600 break-all">
                      ID: {genSuccess.id}
                    </p>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Unified key table */}
      <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-medium text-gray-700">Active Keys</h3>
          <span className="text-xs text-gray-400">
            {keys.length} key{keys.length !== 1 ? "s" : ""} registered
          </span>
        </div>

        {keysError && <p className="text-sm text-red-600">{keysError}</p>}

        {keys.length === 0 ? (
          <p className="text-sm text-gray-400 italic">
            No keys registered yet. Import a file, connect a hardware token, or generate a key.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 text-left text-xs text-gray-500">
                <th className="pb-2">Algorithm</th>
                <th className="pb-2">Source</th>
                <th className="pb-2">Label</th>
                <th className="pb-2">Fingerprint</th>
                <th className="pb-2">Added</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.id} className="border-b border-gray-100">
                  <td className="py-2 text-gray-700">{key.algorithm}</td>
                  <td className="py-2">
                    <span className="inline-block rounded-full bg-gray-100 px-2 py-0.5 text-xs text-gray-600">
                      {getSourceLabel(key)}
                    </span>
                  </td>
                  <td className="py-2 text-gray-500 text-xs">{key.label ?? "-"}</td>
                  <td className="py-2 font-mono text-xs text-gray-500">
                    {key.fingerprint.slice(0, 16)}...
                  </td>
                  <td className="py-2 text-xs text-gray-500">
                    {new Date(key.importedAt).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
