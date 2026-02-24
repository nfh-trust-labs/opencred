/**
 * CredentialVerifier — placeholder for the desktop app.
 *
 * This mirrors the web app's CredentialVerifier component. In the desktop app,
 * verification can work offline using bundled JSON-LD contexts. The full
 * implementation will be added in a follow-up issue.
 */

import { useState } from "react";

export function CredentialVerifier() {
  const [credential, setCredential] = useState("");
  const [result, setResult] = useState<string | null>(null);

  async function handleVerify() {
    if (!credential.trim()) return;
    try {
      const response = await window.opencred.verifyCredential({ credential });
      if (response.success) {
        setResult(response.valid ? "Credential is valid." : (response.message ?? "Invalid."));
      } else {
        setResult(`Error: ${response.error}`);
      }
    } catch (err) {
      setResult(`Verification failed: ${err instanceof Error ? err.message : "Unknown error"}`);
    }
  }

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-4">
      <h2 className="text-sm font-medium text-gray-700">Verify Credential</h2>
      <textarea
        rows={8}
        value={credential}
        onChange={(e) => {
          setCredential(e.target.value);
          setResult(null);
        }}
        placeholder="Paste a signed Verifiable Credential (JSON)..."
        className="block w-full rounded-md border border-gray-300 px-3 py-2 font-mono text-xs shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
      />
      <button
        onClick={() => void handleVerify()}
        disabled={!credential.trim()}
        className="rounded-md bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700 disabled:opacity-40"
      >
        Verify
      </button>
      {result && (
        <p className={`text-sm ${result.startsWith("Error") ? "text-red-600" : "text-gray-700"}`}>
          {result}
        </p>
      )}
    </div>
  );
}
