/**
 * DomainVerificationStep — Quick Start step for verifying domain ownership.
 *
 * Shows a DNS TXT or HTTP challenge and checks verification status
 * via the attestation API.
 */

import { useState } from "react";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Badge } from "./ui/Badge";

type VerificationMethod = "dns-txt" | "http-challenge";
type Status = "idle" | "challenge-created" | "checking" | "verified" | "failed";

interface ChallengeInfo {
  challengeId: string;
  challenge: string;
  instructions: string;
}

interface DomainVerificationStepProps {
  domain: string;
  keyId: string;
  organizationName: string;
  onVerified: (attestationCredential: Record<string, unknown>) => void;
  onBack: () => void;
}

export function DomainVerificationStep({
  domain,
  keyId,
  organizationName,
  onVerified: _onVerified,
  onBack,
}: DomainVerificationStepProps) {
  const [method, setMethod] = useState<VerificationMethod>("dns-txt");
  const [status, setStatus] = useState<Status>("idle");
  const [challenge, setChallenge] = useState<ChallengeInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleStartChallenge() {
    setError(null);
    setStatus("checking");

    try {
      // In a real implementation, this would call the API via IPC.
      // For now, we simulate the challenge creation.
      // The main process would proxy: POST /attestation/challenge
      const mockChallenge: ChallengeInfo = {
        challengeId: `ch_${Date.now()}`,
        challenge: method === "dns-txt"
          ? `opencred-verify=mock-token-${Date.now()}`
          : `mock-token-${Date.now()}`,
        instructions: method === "dns-txt"
          ? `Add a DNS TXT record to _opencred-verify.${domain} with the value shown below.`
          : `Place a file at https://${domain}/.well-known/opencred-challenge/mock-token containing the token below.`,
      };

      setChallenge(mockChallenge);
      setStatus("challenge-created");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create challenge");
      setStatus("failed");
    }
  }

  async function handleCheckVerification() {
    if (!challenge) return;
    setError(null);
    setStatus("checking");

    try {
      // In a real implementation, this would call:
      // POST /attestation/challenge/:id/verify via IPC
      // For now, we show the UI flow. The actual API integration
      // will be wired up when the API is running.
      setError("Domain verification requires the OpenCred API server. Configure the API URL in Settings.");
      setStatus("failed");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification check failed");
      setStatus("failed");
    }
  }

  return (
    <Card className="space-y-6">
      <div className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-900">Verify Domain Ownership</h2>
        <p className="text-sm text-gray-600">
          Prove you control <span className="font-mono font-medium">{domain}</span> by
          completing a verification challenge.
        </p>
      </div>

      {/* Method selector */}
      {status === "idle" && (
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-2">
              Verification Method
            </label>
            <div className="flex gap-3">
              <button
                onClick={() => setMethod("dns-txt")}
                className={`flex-1 rounded-md border px-4 py-3 text-sm text-left ${
                  method === "dns-txt"
                    ? "border-blue-500 bg-blue-50 text-blue-900"
                    : "border-gray-200 bg-white text-gray-700 hover:border-gray-300"
                }`}
              >
                <div className="font-medium">DNS TXT Record</div>
                <div className="text-xs mt-1 opacity-75">Add a TXT record to your DNS</div>
              </button>
              <button
                onClick={() => setMethod("http-challenge")}
                className={`flex-1 rounded-md border px-4 py-3 text-sm text-left ${
                  method === "http-challenge"
                    ? "border-blue-500 bg-blue-50 text-blue-900"
                    : "border-gray-200 bg-white text-gray-700 hover:border-gray-300"
                }`}
              >
                <div className="font-medium">HTTP Challenge</div>
                <div className="text-xs mt-1 opacity-75">Host a file on your web server</div>
              </button>
            </div>
          </div>

          <Button onClick={() => void handleStartChallenge()}>
            Start Verification
          </Button>
        </div>
      )}

      {/* Challenge instructions */}
      {challenge && status !== "idle" && (
        <div className="space-y-4">
          <div className="rounded-md border border-blue-200 bg-blue-50 p-4">
            <p className="text-sm text-blue-800 mb-2">{challenge.instructions}</p>
            <div className="rounded bg-white border border-blue-100 p-2">
              <code className="text-xs text-blue-900 break-all">{challenge.challenge}</code>
            </div>
          </div>

          {status === "challenge-created" && (
            <Button onClick={() => void handleCheckVerification()}>
              Check Verification
            </Button>
          )}
        </div>
      )}

      {/* Status display */}
      {status === "checking" && (
        <div className="flex items-center gap-2 text-sm text-blue-700">
          <div className="h-4 w-4 animate-spin rounded-full border-2 border-blue-500 border-t-transparent" />
          Checking...
        </div>
      )}

      {status === "verified" && (
        <div className="rounded-md border border-green-200 bg-green-50 p-3 flex items-center gap-2">
          <Badge variant="success">Verified</Badge>
          <span className="text-sm text-green-800">Domain ownership confirmed</span>
        </div>
      )}

      {/* Error display */}
      {error && (
        <div className="rounded-md border border-red-200 bg-red-50 p-3 space-y-2">
          <p className="text-sm text-red-700">{error}</p>
          {status === "failed" && (
            <Button
              variant="secondary"
              onClick={() => {
                setStatus(challenge ? "challenge-created" : "idle");
                setError(null);
              }}
            >
              Try Again
            </Button>
          )}
        </div>
      )}

      {/* Navigation */}
      <div className="flex items-center justify-between pt-2">
        <Button variant="secondary" onClick={onBack}>
          Back
        </Button>
      </div>

      {/* Hidden context info for debugging */}
      <input type="hidden" data-key-id={keyId} data-org={organizationName} />
    </Card>
  );
}
