/**
 * KeyGenerate — generate a fresh ECDSA P-256 keypair in-app.
 *
 * The private key stays in memory and never leaves the application.
 * Suitable for testing or ephemeral signing.
 */

import { useState } from "react";
import type { KeyMetadata } from "../../shared/ipc-types";

interface KeyGenerateProps {
  onKeyGenerated?: () => void;
}

export function KeyGenerate({ onKeyGenerated }: KeyGenerateProps) {
  const [label, setLabel] = useState("");
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<KeyMetadata | null>(null);

  async function handleGenerate() {
    setError(null);
    setSuccess(null);
    setGenerating(true);
    try {
      const result = await window.opencred.generateKey({
        label: label.trim() || undefined,
      });

      if (result.success && result.key) {
        setSuccess(result.key);
        setLabel("");
        onKeyGenerated?.();
      } else {
        setError(result.error ?? "Key generation failed.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Key generation failed.");
    } finally {
      setGenerating(false);
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-gray-500">
        Generate a new signing key (ECDSA P-256). The private key is stored securely on your
        computer and never leaves this application.
      </p>
      <div className="flex gap-2 items-end">
        <div className="flex-1">
          <label className="block text-xs text-gray-600 mb-1">Label (optional)</label>
          <input
            type="text"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="e.g. Test Issuer Key"
            className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none"
            onKeyDown={(e) => {
              if (e.key === "Enter") void handleGenerate();
            }}
          />
        </div>
        <button
          onClick={() => void handleGenerate()}
          disabled={generating}
          className="rounded-md bg-gray-700 px-4 py-1.5 text-sm text-white hover:bg-gray-800 disabled:opacity-40"
        >
          {generating ? "Generating..." : "Generate Signing Key"}
        </button>
      </div>
      <p className="text-xs text-gray-400">Creates an ECDSA P-256 keypair for credential signing</p>

      {error && <p className="text-sm text-red-600">{error}</p>}

      {success && (
        <div className="rounded-md border border-green-200 bg-green-50 p-3 text-xs">
          <p className="font-medium text-green-800">Key generated successfully</p>
          <div className="mt-1 text-green-700 space-y-0.5">
            <p>Algorithm: {success.algorithm}</p>
            {success.label && <p>Label: {success.label}</p>}
            <p>Fingerprint: {success.fingerprint.slice(0, 32)}...</p>
            <p className="font-mono text-[10px] text-green-600 break-all">ID: {success.id}</p>
          </div>
        </div>
      )}
    </div>
  );
}
