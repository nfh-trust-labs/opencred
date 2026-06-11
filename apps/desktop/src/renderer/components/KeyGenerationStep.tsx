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
        <h2 className="text-lg font-semibold text-txt-primary">Generate Signing Key</h2>
        <p className="text-sm text-txt-secondary">
          Generate an ECDSA P-256 keypair for signing credentials. The private key stays on this
          machine and is never transmitted.
        </p>
      </div>

      {/* Label input */}
      <div>
        <label htmlFor="key-label" className="block text-xs font-medium text-txt-secondary">
          Key Label (optional)
        </label>
        <input
          id="key-label"
          type="text"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="e.g. My Organization Signing Key"
          disabled={generating || generatedKey !== null}
          className="mt-1 block w-full rounded-md border border-border px-3 py-2 text-sm shadow-sm focus:border-brand focus:ring-1 focus:ring-blue-500 disabled:bg-surface-warm disabled:text-txt-muted"
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
        <div className="rounded-md border border-state-danger-border bg-state-danger-bg p-3">
          <p className="text-sm text-state-danger">{error}</p>
        </div>
      )}

      {/* Key info display (shown after generation) */}
      {generatedKey && (
        <div className="rounded-lg border border-state-success-border bg-state-success-bg p-4 space-y-3">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-medium text-state-success">Key Generated</h3>
            <Badge variant="success">Ready</Badge>
          </div>
          <dl className="text-xs text-state-success space-y-2">
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
