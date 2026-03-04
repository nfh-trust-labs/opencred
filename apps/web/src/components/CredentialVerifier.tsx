import { useState } from "react";
import { OpenCredClient } from "../api/client";
import type { VerifyResponse } from "../api/client";
import { VerificationResult } from "./VerificationResult";

interface Props {
  apiUrl: string;
  token: string;
}

export function CredentialVerifier({ apiUrl, token }: Props) {
  const [vcJson, setVcJson] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<VerifyResponse | null>(null);

  function handleFile(file: File) {
    const reader = new FileReader();
    reader.onload = () => {
      setVcJson(reader.result as string);
      setResult(null);
      setError(null);
    };
    reader.readAsText(file);
  }

  function detectInputFormat(input: string): "json" | "jws" | "unknown" {
    const trimmed = input.trim();
    if (trimmed.startsWith("{")) return "json";
    // JWS compact serialization: three dot-separated base64url parts
    const parts = trimmed.split(".");
    if (parts.length === 3 && parts.every((p) => p.length > 0)) return "jws";
    return "unknown";
  }

  async function handleVerify() {
    setError(null);
    setResult(null);

    const format = detectInputFormat(vcJson);
    let credential: unknown;

    if (format === "json") {
      try {
        credential = JSON.parse(vcJson);
      } catch {
        setError("Invalid JSON — please paste a valid Verifiable Credential");
        return;
      }
    } else if (format === "jws") {
      // Pass the JWS compact string directly
      credential = vcJson.trim();
    } else {
      setError("Unrecognized format — paste a VC JSON-LD document or a JWS compact string");
      return;
    }

    setLoading(true);
    try {
      const client = new OpenCredClient(apiUrl, token || undefined);
      const res = await client.verifyCredential(credential);
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification request failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <label htmlFor="vc-json" className="block text-sm font-medium text-gray-700">
          Verifiable Credential (JSON-LD or JWS)
        </label>
        <textarea
          id="vc-json"
          rows={12}
          value={vcJson}
          onChange={(e) => {
            setVcJson(e.target.value);
            setResult(null);
          }}
          placeholder="Paste a VC JSON-LD document or JWS compact string here..."
          className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 font-mono text-xs shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
        />
      </div>
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={handleVerify}
          disabled={!vcJson.trim() || loading}
          className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40"
        >
          {loading ? "Verifying..." : "Verify"}
        </button>
        <label className="cursor-pointer rounded-md border border-gray-300 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50">
          Upload file
          <input
            type="file"
            accept=".json,.jws,.txt"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handleFile(file);
            }}
          />
        </label>
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-3">
          <p className="text-sm text-red-700">{error}</p>
        </div>
      )}

      {result && <VerificationResult result={result} />}
    </div>
  );
}
