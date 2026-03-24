/**
 * DomainVerificationStep — Quick Start step for verifying domain ownership.
 *
 * Supports three verification methods:
 *   1. DNS TXT record challenge
 *   2. HTTP challenge (file on web server)
 *   3. Business Credential (file upload)
 *
 * Calls the OpenCred API via IPC preload bridge.
 */

import { useState, useRef } from "react";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Badge } from "./ui/Badge";

type VerificationMethod = "dns-txt" | "http" | "business-vc";
type Status = "idle" | "challenge-created" | "checking" | "verified" | "failed";

interface ChallengeInfo {
  challengeId: string;
  token: string;
  instructions: string;
  expiresAt?: string;
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
  const [businessVcFileName, setBusinessVcFileName] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  async function handleStartChallenge() {
    setError(null);
    setStatus("checking");

    try {
      const apiMethod = method === "dns-txt" ? "dns-txt" : "http";
      const result = await window.opencred.attestation.requestChallenge({
        domain,
        method: apiMethod,
      });

      if (result.success && result.challengeId) {
        setChallenge({
          challengeId: result.challengeId,
          token: result.token ?? "",
          instructions: result.instructions ?? (
            method === "dns-txt"
              ? `Add a DNS TXT record to _opencred-verify.${domain} with the token value shown below.`
              : `Place a file at https://${domain}/.well-known/opencred-challenge containing the token below.`
          ),
          expiresAt: result.expiresAt,
        });
        setStatus("challenge-created");
      } else {
        setError(result.error ?? "Failed to create challenge");
        setStatus("failed");
      }
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
        setError(result.error ?? "Verification failed. Make sure you have completed the challenge.");
        setStatus("failed");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification check failed");
      setStatus("failed");
    }
  }

  async function handleBusinessVcUpload() {
    try {
      const result = await window.opencred.openFile({
        title: "Select Business Credential",
        filters: [{ name: "JSON", extensions: ["json", "jsonld"] }],
      });
      if (result.content) {
        setBusinessVcContent(result.content);
        setBusinessVcFileName(result.filePath?.split("/").pop() ?? "credential.json");
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
      const result = await window.opencred.attestation.submitBusinessVc({
        businessVc: businessVcContent,
        keyId,
      });

      if (result.success && result.credential) {
        setStatus("verified");
        onVerified(result.credential);
      } else {
        setError(result.error ?? "Business credential verification failed.");
        setStatus("failed");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Business credential submission failed");
      setStatus("failed");
    }
  }

  return (
    <Card className="space-y-6">
      <div className="space-y-2">
        <h2 className="text-lg font-semibold text-gray-900">Verify Your Identity</h2>
        <p className="text-sm text-gray-600">
          Prove your organization controls{" "}
          <span className="font-mono font-medium">{domain}</span> or submit a
          business credential to receive a Key Attestation.
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
                <div className="font-medium">Business Credential</div>
                <div className="text-xs mt-1 opacity-75">Upload a verified business VC</div>
              </button>
            </div>
          </div>

          {method !== "business-vc" && (
            <Button onClick={() => void handleStartChallenge()}>
              Start Verification
            </Button>
          )}

          {method === "business-vc" && (
            <div className="space-y-3">
              <div className="rounded-md border border-gray-200 bg-gray-50 p-4 space-y-3">
                <p className="text-sm text-gray-700">
                  Upload a business Verifiable Credential (e.g. a GLEIF vLEI credential
                  or similar business identity VC) to verify your organization.
                </p>
                <div className="flex items-center gap-3">
                  <Button
                    variant="secondary"
                    onClick={() => void handleBusinessVcUpload()}
                  >
                    Choose File
                  </Button>
                  {businessVcFileName && (
                    <span className="text-sm text-gray-600">{businessVcFileName}</span>
                  )}
                </div>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,.jsonld"
                  className="hidden"
                />
              </div>
              {businessVcContent && (
                <Button onClick={() => void handleSubmitBusinessVc()}>
                  Submit Business Credential
                </Button>
              )}
            </div>
          )}
        </div>
      )}

      {/* Challenge instructions (DNS/HTTP) */}
      {challenge && status !== "idle" && method !== "business-vc" && (
        <div className="space-y-4">
          <div className="rounded-md border border-blue-200 bg-blue-50 p-4">
            <p className="text-sm text-blue-800 mb-2">{challenge.instructions}</p>
            <div className="rounded bg-white border border-blue-100 p-2">
              <code className="text-xs text-blue-900 break-all">{challenge.token}</code>
            </div>
            {challenge.expiresAt && (
              <p className="text-xs text-blue-600 mt-2">
                Expires: {new Date(challenge.expiresAt).toLocaleString()}
              </p>
            )}
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
          <span className="text-sm text-green-800">Identity verified successfully</span>
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
