/**
 * AttestationResultStep — Quick Start final step showing attestation result.
 *
 * Displays the received Key Attestation VC details and allows the user
 * to store it and proceed to credential issuance.
 */

import { useState } from "react";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Badge } from "./ui/Badge";

interface AttestationResultStepProps {
  attestationCredential: Record<string, unknown>;
  keyId: string;
  organizationName: string;
  domain: string;
  onComplete: () => void;
}

export function AttestationResultStep({
  attestationCredential,
  keyId,
  organizationName,
  domain,
  onComplete,
}: AttestationResultStepProps) {
  const [storing, setStoring] = useState(false);
  const [stored, setStored] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validFrom = attestationCredential.validFrom as string | undefined;
  const validUntil = attestationCredential.validUntil as string | undefined;
  const issuer = attestationCredential.issuer as string | undefined;

  async function handleStore() {
    setStoring(true);
    setError(null);

    try {
      const result = await window.opencred.attestation.import({
        keyId,
        credential: attestationCredential,
      });

      if (result.success) {
        setStored(true);
      } else {
        setError(result.error ?? "Failed to store attestation");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to store attestation");
    } finally {
      setStoring(false);
    }
  }

  return (
    <Card className="space-y-6">
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <h2 className="text-lg font-semibold text-gray-900">Key Attestation Received</h2>
          <Badge variant="success">Verified</Badge>
        </div>
        <p className="text-sm text-gray-600">
          Your signing key has been attested by OpenCred. This attestation
          will be embedded in credentials you issue, establishing trust.
        </p>
      </div>

      {/* Attestation details */}
      <div className="rounded-lg border border-gray-200 bg-gray-50 p-4 space-y-3">
        <dl className="text-sm space-y-2">
          <div className="flex gap-2">
            <dt className="font-medium text-gray-600 w-32 flex-shrink-0">Organization:</dt>
            <dd className="text-gray-900">{organizationName}</dd>
          </div>
          <div className="flex gap-2">
            <dt className="font-medium text-gray-600 w-32 flex-shrink-0">Domain:</dt>
            <dd className="font-mono text-gray-900">{domain}</dd>
          </div>
          <div className="flex gap-2">
            <dt className="font-medium text-gray-600 w-32 flex-shrink-0">Attested by:</dt>
            <dd className="font-mono text-xs text-gray-900 break-all">{issuer ?? "OpenCred"}</dd>
          </div>
          {validFrom && (
            <div className="flex gap-2">
              <dt className="font-medium text-gray-600 w-32 flex-shrink-0">Valid from:</dt>
              <dd className="text-gray-900">{new Date(validFrom).toLocaleDateString()}</dd>
            </div>
          )}
          {validUntil && (
            <div className="flex gap-2">
              <dt className="font-medium text-gray-600 w-32 flex-shrink-0">Valid until:</dt>
              <dd className="text-gray-900">{new Date(validUntil).toLocaleDateString()}</dd>
            </div>
          )}
          <div className="flex gap-2">
            <dt className="font-medium text-gray-600 w-32 flex-shrink-0">Key ID:</dt>
            <dd className="font-mono text-xs text-gray-900 break-all">{keyId}</dd>
          </div>
        </dl>
      </div>

      {/* Error */}
      {error && (
        <div className="rounded-md border border-red-200 bg-red-50 p-3">
          <p className="text-sm text-red-700">{error}</p>
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center justify-between pt-2">
        {!stored ? (
          <Button onClick={() => void handleStore()} disabled={storing}>
            {storing ? "Storing..." : "Store Attestation"}
          </Button>
        ) : (
          <Button onClick={onComplete}>
            Start Issuing Credentials
          </Button>
        )}
      </div>

      {stored && (
        <div className="rounded-md border border-green-200 bg-green-50 p-3">
          <p className="text-sm text-green-700">
            Attestation stored. Your credentials will now include this attestation
            in their proof, establishing a verifiable trust chain.
          </p>
        </div>
      )}
    </Card>
  );
}
