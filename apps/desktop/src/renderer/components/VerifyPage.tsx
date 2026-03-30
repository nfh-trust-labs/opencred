/**
 * VerifyPage — credential verification with detailed check results.
 *
 * Supports:
 *  - Pasting credential JSON directly into a textarea
 *  - Loading a credential from a file via native dialog
 *  - Verifying the credential and displaying per-check results
 *
 * Verification happens in the main process via IPC. When offline,
 * only signature and date checks are possible. Revocation checks
 * require connectivity and show appropriate messaging.
 */

import { useState } from "react";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Badge } from "./ui/Badge";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface VerificationCheck {
  name: string;
  passed: boolean;
  detail?: string;
}

type VerificationStatus = "VALID" | "INVALID" | "EXPIRED" | "ERROR";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function statusToBadgeVariant(
  status: VerificationStatus,
): "success" | "error" | "warning" {
  switch (status) {
    case "VALID":
      return "success";
    case "EXPIRED":
      return "warning";
    case "INVALID":
    case "ERROR":
      return "error";
  }
}

function deriveStatus(valid: boolean, checks: VerificationCheck[]): VerificationStatus {
  if (valid) return "VALID";
  const hasExpired = checks.some(
    (c) => !c.passed && c.name.toLowerCase().includes("expir"),
  );
  if (hasExpired) return "EXPIRED";
  return "INVALID";
}

const CHECK_HINTS: Record<string, string> = {
  'signature': 'Confirms the credential was digitally sealed by the issuer',
  'not-before': 'The credential\'s start date has passed',
  'expiry': 'The credential has not expired',
  'revocation': 'The credential has not been revoked',
  'context': 'The credential\'s context is valid and resolvable',
};

function getCheckHint(checkName: string): string | undefined {
  const lower = checkName.toLowerCase();
  for (const [key, hint] of Object.entries(CHECK_HINTS)) {
    if (lower.includes(key)) return hint;
  }
  return undefined;
}

function getErrorHint(message: string): string | null {
  if (!message) return null;
  const lower = message.toLowerCase();
  if (lower.includes("no proof found") || lower.includes("missing a proof") || lower.includes("proof is missing")) {
    return "This document is missing a digital seal. Make sure you received the complete credential file.";
  }
  if (lower.includes("context") && (lower.includes("missing") || lower.includes("not found") || lower.includes("could not"))) {
    return "The credential references a context that could not be found. This may mean the issuer's context is not published.";
  }
  if (lower.includes("failed") || lower.includes("invalid") || lower.includes("error")) {
    return "If you copied the text, make sure you copied the entire content including all brackets.";
  }
  return null;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function VerifyPage() {
  const [credential, setCredential] = useState("");
  const [valid, setValid] = useState<boolean | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [checks, setChecks] = useState<VerificationCheck[]>([]);
  const [loading, setLoading] = useState(false);
  const [isOffline, setIsOffline] = useState(false);

  // ------------------------------------------------------------------
  // Handlers
  // ------------------------------------------------------------------

  async function handleVerify() {
    if (!credential.trim()) return;

    setLoading(true);
    setValid(null);
    setMessage(null);
    setChecks([]);

    try {
      // Check connectivity for user messaging
      try {
        const offline = await window.opencred.getOfflineStatus();
        setIsOffline(offline);
      } catch {
        setIsOffline(true);
      }

      const response = await window.opencred.verifyCredential({ credential });

      if (response.success) {
        setValid(response.valid ?? false);
        setMessage(response.message ?? (response.valid ? "Valid." : "Invalid."));
        setChecks(response.checks ?? []);
      } else {
        setValid(false);
        setMessage(response.error ?? "Verification failed.");
      }
    } catch (err) {
      setValid(false);
      setMessage(err instanceof Error ? err.message : "Verification failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handleLoadFile() {
    try {
      const result = await window.opencred.openFile({
        title: "Load Verifiable Credential",
        filters: [
          { name: "JSON", extensions: ["json", "jsonld"] },
          { name: "All Files", extensions: ["*"] },
        ],
      });

      if (result.content) {
        setCredential(result.content);
        setValid(null);
        setMessage(null);
        setChecks([]);
      }
    } catch {
      // User cancelled
    }
  }

  function handleClear() {
    setCredential("");
    setValid(null);
    setMessage(null);
    setChecks([]);
  }

  // ------------------------------------------------------------------
  // Derived state
  // ------------------------------------------------------------------

  const status: VerificationStatus | null =
    valid !== null ? deriveStatus(valid, checks) : null;

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------

  return (
    <div className="space-y-4">
      {/* Input */}
      <Card className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="oc-card-label">Input</h2>
          <div className="flex gap-2">
            <button
              onClick={() => void handleLoadFile()}
              className="rounded-md bg-gray-100 px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-200"
            >
              Upload File
            </button>
            {credential && (
              <button
                onClick={handleClear}
                className="rounded-md bg-gray-100 px-3 py-1.5 text-xs text-gray-500 hover:bg-gray-200"
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {!credential && (
          <p className="text-xs text-gray-500">
            You can get this from the person or organization that issued the credential.
          </p>
        )}

        <textarea
          rows={8}
          value={credential}
          onChange={(e) => {
            setCredential(e.target.value);
            setValid(null);
            setMessage(null);
            setChecks([]);
          }}
          placeholder="Paste credential text here, or use 'Upload File' to load a .json file"
          className="block w-full rounded-md border border-gray-300 px-3 py-2 font-mono text-xs shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
        />

        <Button
          onClick={() => void handleVerify()}
          disabled={!credential.trim() || loading}
        >
          {loading ? "Verifying..." : "Verify"}
        </Button>
      </Card>

      {/* Overall result */}
      {status !== null && message && (
        <Card
          className={`space-y-3 ${
            status === "VALID"
              ? "border-green-200 bg-green-50"
              : status === "EXPIRED"
                ? "border-amber-200 bg-amber-50"
                : "border-red-200 bg-red-50"
          }`}
        >
          <div className="flex items-center gap-3">
            <Badge variant={statusToBadgeVariant(status)}>{status}</Badge>
            <p
              className={`text-sm font-medium ${
                status === "VALID"
                  ? "text-green-800"
                  : status === "EXPIRED"
                    ? "text-amber-800"
                    : "text-red-800"
              }`}
            >
              {status === "VALID"
                ? "Valid Credential"
                : status === "EXPIRED"
                  ? "Expired Credential"
                  : "Invalid Credential"}
            </p>
          </div>
          <p
            className={`text-sm ${
              status === "VALID"
                ? "text-green-700"
                : status === "EXPIRED"
                  ? "text-amber-700"
                  : "text-red-700"
            }`}
          >
            {message}
          </p>
          {status !== "VALID" && message && getErrorHint(message) && (
            <p className="mt-1 text-xs text-gray-500">
              {getErrorHint(message)}
            </p>
          )}
        </Card>
      )}

      {/* Per-check results */}
      {checks.length > 0 && (
        <Card className="space-y-3">
          <h3 className="oc-card-label">Verification Checks</h3>
          <div className="space-y-2">
            {checks.map((check, i) => {
              const hint = getCheckHint(check.name);
              return (
                <div
                  key={i}
                  className={`flex items-start gap-3 rounded-md border px-3 py-2.5 ${
                    check.passed
                      ? "border-green-200 bg-green-50"
                      : "border-red-200 bg-red-50"
                  }`}
                >
                  <span
                    className={`flex-shrink-0 mt-0.5 text-xs font-semibold ${
                      check.passed ? "text-green-600" : "text-red-600"
                    }`}
                  >
                    {check.passed ? "PASS" : "FAIL"}
                  </span>
                  <div className="min-w-0">
                    <span className="text-xs font-medium text-gray-700">
                      {check.name}
                    </span>
                    {hint && (
                      <p className="mt-0.5 text-xs text-gray-400">{hint}</p>
                    )}
                    {check.detail && (
                      <p className="mt-0.5 text-xs text-gray-500">{check.detail}</p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* Offline warning */}
      {isOffline && valid !== null && (
        <Card className="border-amber-200 bg-amber-50">
          <p className="text-xs text-amber-700">
            You are offline. Only signature and date checks were performed. Revocation
            status could not be verified.
          </p>
        </Card>
      )}
    </div>
  );
}
