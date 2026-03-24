/**
 * DomainVerificationStep — Quick Start step for verifying domain ownership.
 *
 * Shows a DNS TXT or HTTP challenge and checks verification status
 * via the attestation API. Also supports business VC as an alternative
 * identity verification method.
 */

import { useState } from "react";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Badge } from "./ui/Badge";

type VerificationMethod = "dns-txt" | "http" | "business-vc";
type Status = "idle" | "challenge-created" | "checking" | "verified" | "failed";

interface ChallengeInfo {
  challengeId: string;
  token: string;
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
  onVerified,
  onBack,
}: DomainVerificationStepProps) {
  const [method, setMethod] = useState<VerificationMethod>("dns-txt");
  const [status, setStatus] = useState<Status>("idle");
  const [challenge, setChallenge] = useState<ChallengeInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [businessVcContent, setBusinessVcContent] = useState<string | null>(null);

  async function handleStartChallenge() {
    setError(null);
    setStatus("checking");

    try {
      const result = await window.opencred.attestation.requestChallenge({
        domain,
        method: method as "dns-txt" | "http",
      });

      if (!result.success || !result.challengeId || !result.token) {
        setError(result.error ?? "Failed to create challenge");
        setStatus("failed");
        return;
      }

      setChallenge({
        challengeId: result.challengeId,
        token: result.token,
        instructions: result.instructions ?? (method === "dns-txt"
          ? `Add a DNS TXT record to ${domain} with the value shown below.`
          : `Place a file at https://${domain}/.well-known/opencred-challenge/${result.challengeId} with the token below.`),
      });
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
      const result = await window.opencred.attestation.submitVerification({
        challengeId: challenge.challengeId,
        keyId,
        domain,
        organizationName,
      });

      if (result.success && result.credential) {
        setStatus("verified");
        onVerified(result.credential);
      } else {
        setError(result.error ?? "Domain verification failed");
        setStatus("failed");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification check failed");
      setStatus("failed");
    }
  }

  async function handleLoadBusinessVc() {
    try {
      const file = await window.opencred.openFile({
        title: "Select Business VC",
        filters: [
          { name: "Verifiable Credential", extensions: ["json", "jwt"] },
          { name: "All Files", extensions: ["*"] },
        ],
      });

      if (file.content) {
        setBusinessVcContent(file.content);
        setError(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to open file");
    }
  }

  async function handleSubmitBusinessVc() {
    if (!businessVcContent) return;
    setError(null);
    setStatus("checking");

    try {
      let businessVc: string | Record<string, unknown>;
      try {
        businessVc = JSON.parse(businessVcContent) as Record<string, unknown>;
      } catch {
        // Not JSON — treat as compact JWT/SD-JWT string
        businessVc = businessVcContent;
      }

      const result = await window.opencred.attestation.submitBusinessVc({
        businessVc,
        keyId,
      });

      if (result.success && result.credential) {
        setStatus("verified");
        onVerified(result.credential);
      } else {
        setError(result.error ?? "Business VC verification failed");
        setStatus("failed");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Business VC attestation failed");
      setStatus("failed");
    }
  }

  return (
    <Card className="space-y-6">
      <div className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-900">Verify Your Identity</h2>
        <p className="text-sm text-gray-600">
          Prove your identity to receive a key attestation from OpenCred.
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
                onClick={() => setMethod("http")}
                className={`flex-1 rounded-md border px-4 py-3 text-sm text-left ${
                  method === "http"
                    ? "border-blue-500 bg-blue-50 text-blue-900"
                    : "border-gray-200 bg-white text-gray-700 hover:border-gray-300"
                }`}
              >
                <div className="font-medium">HTTP Challenge</div>
                <div className="text-xs mt-1 opacity-75">Host a file on your web server</div>
              </button>
              <button
                onClick={() => setMethod("business-vc")}
                className={`flex-1 rounded-md border px-4 py-3 text-sm text-left ${
                  method === "business-vc"
                    ? "border-blue-500 bg-blue-50 text-blue-900"
                    : "border-gray-200 bg-white text-gray-700 hover:border-gray-300"
                }`}
              >
                <div className="font-medium">Business VC</div>
                <div className="text-xs mt-1 opacity-75">Submit an existing business credential</div>
              </button>
            </div>
          </div>

          {method !== "business-vc" ? (
            <Button onClick={() => void handleStartChallenge()}>
              Start Verification
            </Button>
          ) : (
            <div className="space-y-3">
              <p className="text-sm text-gray-600">
                Provide a verified business credential (JSON or JWT) to prove your organization&apos;s identity.
              </p>
              <div className="flex gap-2">
                <Button variant="secondary" onClick={() => void handleLoadBusinessVc()}>
                  Select File...
                </Button>
                {businessVcContent && (
                  <span className="self-center text-sm text-green-700">File loaded</span>
                )}
              </div>
              {businessVcContent && (
                <Button onClick={() => void handleSubmitBusinessVc()}>
                  Submit Business VC
                </Button>
              )}
            </div>
          )}
        </div>
      )}

      {/* Challenge instructions (domain verification methods only) */}
      {challenge && status !== "idle" && method !== "business-vc" && (
        <div className="space-y-4">
          <div className="rounded-md border border-blue-200 bg-blue-50 p-4">
            <p className="text-sm text-blue-800 mb-2">{challenge.instructions}</p>
            <div className="rounded bg-white border border-blue-100 p-2">
              <code className="text-xs text-blue-900 break-all">{challenge.token}</code>
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
          <span className="text-sm text-green-800">Identity verified — attestation received</span>
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
    </Card>
  );
}
