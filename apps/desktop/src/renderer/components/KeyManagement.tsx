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

import { useState, useEffect, useCallback, useRef } from "react";
import type { KeyMetadata } from "../../shared/ipc-types";
import { KeyImport } from "./KeyImport";
import { HardwareToken } from "./HardwareToken";
import { OsCertStore } from "./OsCertStore";
import { KeyGenerate } from "./KeyGenerate";

type SubTab = "import" | "hardware" | "oscert" | "generate";

const SUB_TABS: { id: SubTab; label: string }[] = [
  { id: "import", label: "Import File" },
  { id: "hardware", label: "Hardware Token" },
  { id: "oscert", label: "OS Cert Store" },
  { id: "generate", label: "Generate Key" },
];

const SOURCE_LABELS: Record<NonNullable<KeyMetadata["source"]>, string> = {
  file: "File",
  pkcs11: "PKCS#11",
  "os-cert": "OS Cert",
  generated: "Generated",
};

export function KeyManagement() {
  const [activeSubTab, setActiveSubTab] = useState<SubTab>("import");
  const [keys, setKeys] = useState<KeyMetadata[]>([]);
  const [keysError, setKeysError] = useState<string | null>(null);
  const [guidanceOpen, setGuidanceOpen] = useState(false);
  const guidanceRef = useRef<HTMLDivElement>(null);

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

  function getSourceLabel(key: KeyMetadata): string {
    return key.source ? (SOURCE_LABELS[key.source] ?? key.source) : "File";
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-4">
        <h2 className="text-sm font-medium text-gray-700">Key Management</h2>
        <p className="text-xs text-gray-500">
          Your signing key proves that credentials came from you. You set this up during onboarding.
        </p>

        {/* Collapsible tab guidance */}
        <div className="bg-gray-50 border border-gray-200 rounded-lg overflow-hidden">
          <button
            onClick={() => setGuidanceOpen((prev) => !prev)}
            className="w-full flex items-center justify-between px-3 py-2 text-xs font-medium text-gray-600 hover:bg-gray-100 transition-colors"
          >
            <span>Which option should I choose?</span>
            <svg
              width="12"
              height="12"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              className={`transition-transform duration-200 ${guidanceOpen ? "rotate-180" : ""}`}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          <div
            ref={guidanceRef}
            className="transition-all duration-200 ease-in-out overflow-hidden"
            style={{
              maxHeight: guidanceOpen ? (guidanceRef.current?.scrollHeight ?? 200) + "px" : "0px",
              opacity: guidanceOpen ? 1 : 0,
            }}
          >
            <ul className="px-3 pb-3 space-y-1.5 text-xs text-gray-500">
              <li><span className="font-medium text-gray-700">Import File</span> — You have a key file from your IT department</li>
              <li><span className="font-medium text-gray-700">Hardware Token</span> — You use a USB security key (YubiKey, SafeNet) or smart card</li>
              <li><span className="font-medium text-gray-700">OS Cert Store</span> — You have signing certificates installed on this computer</li>
              <li><span className="font-medium text-gray-700">Generate Key</span> — You are getting started and need a new key (recommended for testing)</li>
            </ul>
          </div>
        </div>

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
          {activeSubTab === "import" && <KeyImport onKeyImported={loadKeys} />}

          {activeSubTab === "hardware" && <HardwareToken onKeyConnected={loadKeys} />}

          {activeSubTab === "oscert" && <OsCertStore onKeyConnected={loadKeys} />}

          {activeSubTab === "generate" && <KeyGenerate onKeyGenerated={loadKeys} />}
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
