/**
 * KeyGenerationStep — Quick Start step for generating a signing keypair.
 *
 * Generates an ECDSA P-256 key via the main process IPC and displays
 * the resulting key metadata (DID, algorithm, fingerprint).
 *
 * SECURITY NOTE: The private key stays in the main process. Only metadata
 * (id, fingerprint, algorithm) is returned to the renderer.
 */

import { useState } from "react";
import type { KeyMetadata } from "../../shared/ipc-types";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Badge } from "./ui/Badge";

interface KeyGenerationStepProps {
  onKeyGenerated: (keyMeta: { id: string; fingerprint: string; algorithm: string }) => void;
  onBack: () => void;
}

export function KeyGenerationStep({ onKeyGenerated, onBack }: KeyGenerationStepProps) {
  const [label, setLabel] = useState("");
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [generatedKey, setGeneratedKey] = useState<KeyMetadata | null>(null);

  async function handleGenerate() {
    setError(null);
    setGenerating(true);

    try {
      const result = await window.opencred.generateKey({
        label: label.trim() || undefined,
      });

      if (result.success && result.key) {
        setGeneratedKey(result.key);
      } else {
        setError(result.error ?? "Key generation failed. Please try again.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Key generation failed.");
    } finally {
      setGenerating(false);
    }
  }

  function handleNext() {
    if (generatedKey) {
      onKeyGenerated({
        id: generatedKey.id,
        fingerprint: generatedKey.fingerprint,
        algorithm: generatedKey.algorithm,
      });
    }
  }

  return (
    <Card className="space-y-6">
      <div className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-900">Generate Signing Key</h2>
        <p className="text-sm text-gray-600">
          Generate an ECDSA P-256 keypair for signing credentials. The private key stays on this
          machine and is never transmitted.
        </p>
      </div>

      {/* Label input */}
      <div>
        <label htmlFor="key-label" className="block text-xs font-medium text-gray-600">
          Key Label (optional)
        </label>
        <input
          id="key-label"
          type="text"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="e.g. My Organization Signing Key"
          disabled={generating || generatedKey !== null}
          className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50 disabled:text-gray-400"
        />
      </div>

      {/* Generate button (shown when no key generated yet) */}
      {!generatedKey && (
        <div>
          <Button onClick={() => void handleGenerate()} disabled={generating}>
            {generating ? "Generating..." : "Generate Key"}
          </Button>
        </div>
      )}

      {/* Error display */}
      {error && (
        <div className="rounded-md border border-red-200 bg-red-50 p-3">
          <p className="text-sm text-red-700">{error}</p>
        </div>
      )}

      {/* Key info display (shown after generation) */}
      {generatedKey && (
        <div className="rounded-lg border border-green-200 bg-green-50 p-4 space-y-3">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-medium text-green-800">Key Generated</h3>
            <Badge variant="success">Ready</Badge>
          </div>
          <dl className="text-xs text-green-700 space-y-2">
            <div className="flex gap-2">
              <dt className="font-medium w-24 flex-shrink-0">DID:</dt>
              <dd className="font-mono break-all">{generatedKey.id}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="font-medium w-24 flex-shrink-0">Algorithm:</dt>
              <dd>{generatedKey.algorithm}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="font-medium w-24 flex-shrink-0">Fingerprint:</dt>
              <dd className="font-mono">{generatedKey.fingerprint}</dd>
            </div>
            {generatedKey.label && (
              <div className="flex gap-2">
                <dt className="font-medium w-24 flex-shrink-0">Label:</dt>
                <dd>{generatedKey.label}</dd>
              </div>
            )}
          </dl>
        </div>
      )}

      {/* Navigation */}
      <div className="flex items-center justify-between pt-2">
        <Button variant="secondary" onClick={onBack}>
          Back
        </Button>
        {generatedKey && <Button onClick={handleNext}>Next</Button>}
      </div>
    </Card>
  );
}
