/**
 * CredentialVerifier — paste or load a VC JSON, verify signature offline,
 * and display detailed verification results.
 *
 * Verification happens in the main process via IPC. The renderer receives
 * the verification checks (signature, dates, etc.) and displays them.
 * When offline, only signature and date checks are possible. Revocation
 * checks require connectivity and show appropriate messaging.
 */

import { useState } from "react";
import { VerificationResult } from "./VerificationResult";

interface VerificationCheck {
  name: string;
  passed: boolean;
  detail?: string;
}

export function CredentialVerifier() {
  const [credential, setCredential] = useState("");
  const [valid, setValid] = useState<boolean | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [checks, setChecks] = useState<VerificationCheck[]>([]);
  const [loading, setLoading] = useState(false);
  const [isOffline, setIsOffline] = useState(false);

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

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-gray-700">Verify Credential</h2>
        <button
          onClick={() => void handleLoadFile()}
          className="rounded-md bg-gray-100 px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-200"
        >
          Load from File
        </button>
      </div>

      <textarea
        rows={8}
        value={credential}
        onChange={(e) => {
          setCredential(e.target.value);
          setValid(null);
          setMessage(null);
          setChecks([]);
        }}
        placeholder="Paste a signed Verifiable Credential (JSON)..."
        className="block w-full rounded-md border border-gray-300 px-3 py-2 font-mono text-xs shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
      />

      <button
        onClick={() => void handleVerify()}
        disabled={!credential.trim() || loading}
        className="rounded-md bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700 disabled:opacity-40"
      >
        {loading ? "Verifying..." : "Verify"}
      </button>

      {valid !== null && message && (
        <VerificationResult valid={valid} message={message} />
      )}

      {checks.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-medium text-gray-600">Verification Checks</h3>
          {checks.map((check, i) => (
            <div
              key={i}
              className={`flex items-start gap-2 rounded-md border px-3 py-2 text-xs ${
                check.passed
                  ? "border-green-200 bg-green-50"
                  : "border-red-200 bg-red-50"
              }`}
            >
              <span className={check.passed ? "text-green-600" : "text-red-600"}>
                {check.passed ? "PASS" : "FAIL"}
              </span>
              <div>
                <span className="font-medium text-gray-700">{check.name}</span>
                {check.detail && (
                  <p className="mt-0.5 text-gray-500">{check.detail}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {isOffline && valid !== null && (
        <p className="text-xs text-amber-600">
          You are offline. Only signature and date checks were performed. Revocation
          status could not be verified.
        </p>
      )}
    </div>
  );
}
